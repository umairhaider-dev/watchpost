"""The YAML rule format and its validation.

Rules follow Sigma where Sigma has an answer (``title``, ``description``,
``level``/``severity``, ``falsepositives``, ``references``, ``tags``,
``detection`` with named selections and a ``condition``) and add a few
keys for what Sigma's single-event format does not cover:

* ``type``: ``match`` (default), ``threshold``, ``sequence`` or ``new_value``
* ``mitre``: explicit ATT&CK tactic and technique IDs (``attack.*`` tags
  are read too, so imported Sigma rules keep their mapping)
* ``logsource.source``: which parsers' events the rule looks at
* ``group_by``: the entity fields an alert is about, e.g. ``[source.ip]``
* ``threshold``, ``sequence``, ``new_value``: settings for the stateful types
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Annotated, Any

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from watchpost.db.models import LogSource, RuleType, Severity
from watchpost.detection.errors import RuleError
from watchpost.detection.mitre import TACTIC_IDS_BY_TAG

MAX_RULE_YAML_BYTES = 64 * 1024
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SELECTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_duration(value: object) -> timedelta:
    """Parse ``30s``, ``5m``, ``2h`` or ``7d``."""
    if isinstance(value, timedelta):
        return value
    match = _DURATION.match(str(value))
    if match is None:
        msg = f"invalid duration {value!r}; use a number followed by s, m, h or d (e.g. 5m)"
        raise ValueError(msg)
    duration = timedelta(**{_UNITS[match[2]]: int(match[1])})
    if duration <= timedelta(0):
        msg = "duration must be positive"
        raise ValueError(msg)
    return duration


Duration = Annotated[timedelta, BeforeValidator(parse_duration)]
TacticId = Annotated[str, Field(pattern=r"^TA\d{4}$")]
TechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]


def _as_list(value: object) -> object:
    return [value] if isinstance(value, str) else value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MitreMapping(_Strict):
    tactics: list[TacticId] = Field(default_factory=list)
    techniques: list[TechniqueId] = Field(default_factory=list)


class LogSourceFilter(_Strict):
    """Which events a rule looks at; empty means every source."""

    source: Annotated[list[LogSource], BeforeValidator(_as_list)] = Field(default_factory=list)
    # Sigma descriptors, accepted for compatibility but not used for filtering.
    product: str | None = None
    service: str | None = None
    category: str | None = None


class ThresholdSpec(_Strict):
    """Fire when ``count`` matching events (or distinct values) occur within ``timeframe``."""

    count: int = Field(ge=2, le=100_000)
    timeframe: Duration
    distinct: str | None = Field(
        default=None, description="Count distinct values of this field instead of events."
    )


class SequenceStep(_Strict):
    name: str = Field(pattern=_SELECTION_NAME.pattern)
    detection: dict[str, Any]
    count: int = Field(default=1, ge=1, le=10_000)


class SequenceSpec(_Strict):
    """Steps that must happen in order, for the same ``group_by`` entity, within ``maxspan``."""

    maxspan: Duration
    steps: list[SequenceStep] = Field(min_length=2, max_length=10)

    @field_validator("steps")
    @classmethod
    def _unique_names(cls, steps: list[SequenceStep]) -> list[SequenceStep]:
        names = [step.name for step in steps]
        if len(names) != len(set(names)):
            msg = "sequence step names must be unique"
            raise ValueError(msg)
        return steps


class NewValueSpec(_Strict):
    """Fire when ``field`` has a value not seen for the ``group_by`` entity in ``lookback``."""

    field: str
    lookback: Duration
    require_history: bool = Field(
        default=True,
        description="Only alert for entities that already have history in the lookback window.",
    )


class RuleDefinition(_Strict):
    """A validated detection rule."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=1)
    severity: Severity
    type: RuleType = RuleType.MATCH
    enabled: bool = True
    author: str | None = None
    references: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    logsource: LogSourceFilter = Field(default_factory=LogSourceFilter)
    detection: dict[str, Any] | None = None
    group_by: Annotated[list[str], BeforeValidator(_as_list)] = Field(default_factory=list)
    threshold: ThresholdSpec | None = None
    sequence: SequenceSpec | None = None
    new_value: NewValueSpec | None = None

    # Sigma metadata that has no effect here but should not break imports.
    status: str | None = None
    date: Any = None
    modified: Any = None
    license: str | None = None
    related: Any = None
    fields: Any = None
    name: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_sigma_level(cls, data: Any) -> Any:
        """Sigma calls severity ``level``; accept either name."""
        if isinstance(data, dict) and "level" in data and "severity" not in data:
            data = {**data, "severity": data["level"]}
            del data["level"]
        return data

    @model_validator(mode="after")
    def _check_type_settings(self) -> RuleDefinition:
        required: dict[RuleType, tuple[str, ...]] = {
            RuleType.MATCH: ("detection",),
            RuleType.THRESHOLD: ("detection", "threshold"),
            RuleType.SEQUENCE: ("sequence",),
            RuleType.NEW_VALUE: ("detection", "new_value"),
        }
        for key in required[self.type]:
            if getattr(self, key) is None:
                msg = f"a {self.type} rule needs a '{key}' section"
                raise ValueError(msg)
        for key in ("threshold", "sequence", "new_value"):
            if getattr(self, key) is not None and key != self.type.value:
                msg = f"'{key}' is only valid for {key} rules, not {self.type} rules"
                raise ValueError(msg)
        if self.type is RuleType.SEQUENCE and self.detection is not None:
            msg = "sequence rules define detection per step, not at the top level"
            raise ValueError(msg)
        if self.type in {RuleType.SEQUENCE, RuleType.NEW_VALUE} and not self.group_by:
            msg = f"{self.type} rules need group_by: the entity the events must share"
            raise ValueError(msg)
        return self

    @property
    def tactics(self) -> list[str]:
        """Tactic IDs from ``mitre`` plus any ``attack.<tactic>`` tags."""
        found = list(self.mitre.tactics)
        for tag in self.tags:
            tactic = TACTIC_IDS_BY_TAG.get(tag.lower().removeprefix("attack."))
            if tag.lower().startswith("attack.") and tactic and tactic not in found:
                found.append(tactic)
        return found

    @property
    def techniques(self) -> list[str]:
        """Technique IDs from ``mitre`` plus any ``attack.tNNNN`` tags."""
        found = list(self.mitre.techniques)
        for tag in self.tags:
            match = _TECHNIQUE_TAG.match(tag)
            if match and match[1].upper() not in found:
                found.append(match[1].upper())
        return found


def load_rule(text: str) -> RuleDefinition:
    """Parse and validate rule YAML.

    Raises:
        RuleError: with a readable explanation of what is wrong.
    """
    if len(text.encode("utf-8")) > MAX_RULE_YAML_BYTES:
        msg = f"rule is larger than {MAX_RULE_YAML_BYTES // 1024} KiB"
        raise RuleError(msg)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"invalid YAML: {exc}"
        raise RuleError(msg) from exc
    if not isinstance(data, dict):
        msg = "a rule must be a YAML mapping (key: value pairs)"
        raise RuleError(msg)
    try:
        return RuleDefinition.model_validate(data)
    except ValidationError as exc:
        raise RuleError(describe_validation_error(exc)) from exc


def describe_validation_error(exc: ValidationError) -> str:
    problems = []
    for error in exc.errors()[:5]:
        location = ".".join(str(part) for part in error["loc"])
        message = str(error["msg"]).removeprefix("Value error, ")
        problems.append(f"{location}: {message}" if location else message)
    return "; ".join(problems)
