"""Turning a validated rule into fast, reusable predicates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from watchpost.db.models import RuleType, Severity
from watchpost.detection.condition import compile_condition
from watchpost.detection.errors import RuleError
from watchpost.detection.fields import EventRow, Resolver, resolver_for
from watchpost.detection.matchers import Predicate, compile_selection
from watchpost.detection.schema import RuleDefinition, load_rule

# Alerts from match rules are grouped per host unless the rule says otherwise.
DEFAULT_GROUP_BY = ("host.name",)


@dataclass(frozen=True, slots=True)
class CompiledStep:
    """One step of a sequence rule."""

    name: str
    predicate: Predicate
    count: int


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A rule ready to evaluate. Build it once, use it for many events."""

    definition: RuleDefinition
    log_sources: frozenset[str] | None
    predicate: Predicate | None
    steps: tuple[CompiledStep, ...]
    group_fields: tuple[str, ...]
    group_resolvers: tuple[Resolver, ...]
    distinct_resolver: Resolver | None
    value_resolver: Resolver | None

    @property
    def id(self) -> str:
        return self.definition.id

    @property
    def title(self) -> str:
        return self.definition.title

    @property
    def severity(self) -> Severity:
        return self.definition.severity

    @property
    def rule_type(self) -> RuleType:
        return self.definition.type

    def accepts_source(self, row: EventRow) -> bool:
        """Cheap pre-check on the event's log source."""
        return self.log_sources is None or row.get("log_source") in self.log_sources

    def matches(self, row: EventRow) -> bool:
        """True if the event satisfies the rule's detection block (not for sequences)."""
        if self.predicate is None:
            msg = f"rule {self.id} has no single detection block"
            raise RuleError(msg)
        return self.accepts_source(row) and self.predicate(row)

    def group_values(self, row: EventRow) -> tuple[str | None, ...]:
        """The entity an event belongs to, e.g. ``("203.0.113.45",)``."""
        return tuple(_as_key(resolve(row)) for resolve in self.group_resolvers)


def compile_detection(detection: dict[str, Any], context: str = "detection") -> Predicate:
    """Compile a Sigma ``detection`` block (named selections plus a condition)."""
    condition = detection.get("condition")
    if not isinstance(condition, str | list) or not condition:
        msg = f"{context} needs a 'condition'"
        raise RuleError(msg)
    selections = {
        str(name): compile_selection(str(name), body)
        for name, body in detection.items()
        if name != "condition"
    }
    if not selections:
        msg = f"{context} needs at least one selection"
        raise RuleError(msg)
    return compile_condition(condition, selections)


def compile_rule(definition: RuleDefinition) -> CompiledRule:
    """Compile a validated rule.

    Raises:
        RuleError: for problems schema validation cannot see, such as a
            condition naming a missing selection or an invalid regex.
    """
    predicate = None
    if definition.detection is not None:
        predicate = compile_detection(definition.detection)
    steps: tuple[CompiledStep, ...] = ()
    if definition.sequence is not None:
        steps = tuple(
            CompiledStep(
                name=step.name,
                predicate=compile_detection(step.detection, f"step {step.name!r}"),
                count=step.count,
            )
            for step in definition.sequence.steps
        )

    group_fields = tuple(definition.group_by)
    if not group_fields and definition.type is RuleType.MATCH:
        group_fields = DEFAULT_GROUP_BY
    distinct = definition.threshold.distinct if definition.threshold else None
    value_field = definition.new_value.field if definition.new_value else None
    sources = definition.logsource.source
    return CompiledRule(
        definition=definition,
        log_sources=frozenset(source.value for source in sources) if sources else None,
        predicate=predicate,
        steps=steps,
        group_fields=group_fields,
        group_resolvers=tuple(resolver_for(field) for field in group_fields),
        distinct_resolver=resolver_for(distinct) if distinct else None,
        value_resolver=resolver_for(value_field) if value_field else None,
    )


def compile_rule_text(text: str) -> CompiledRule:
    """Load, validate and compile rule YAML in one step."""
    return compile_rule(load_rule(text))


def _as_key(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)
