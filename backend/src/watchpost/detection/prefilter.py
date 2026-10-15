"""Narrowing detection queries in SQL before the rules run in Python.

Window and new-value rules read events around the scope again (a brute
force can straddle two uploads; a new address is judged against 30 days of
history). Without help, those queries return every event of the log source
or the user and Python throws most of them away.

A rule's condition often *requires* a selection whose fields are plain
column values (``event.action: ssh_login``, ``event.code: '4625'``).
:func:`rule_filter` turns those into SQL conditions. It is conservative:
anything it cannot translate exactly (``or``, quantifiers, modifiers, fields
of the raw record, wildcards, non-ASCII text) simply adds no condition, and
Python still evaluates the full rule on every row that comes back. A filter
can therefore only remove rows that could never match.

:func:`rule_columns` goes one step further for rules that only use
normalised fields: their queries can skip the raw record, which is by far
the largest and slowest column to read.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import ColumnElement, and_, func, or_

from watchpost.db.models import Event, RuleType
from watchpost.detection.compiler import CompiledRule
from watchpost.detection.condition import tokenize
from watchpost.detection.matchers import plain_needles
from watchpost.events import FIELDS_BY_NAME, FieldKind

_EVENTS = Event.__table__
_TEXT_KINDS = frozenset({FieldKind.KEYWORD, FieldKind.TEXT})
_STRUCTURE = frozenset({"or", "(", ")", "of", "1", "any", "all", "them"})
# Read by the engine for every row: ordering, scope checks and the alert's entities.
_ENGINE_COLUMNS = frozenset(
    {"id", "timestamp", "log_source", "ingest_job_id", "host_name", "source_ip", "user_name"}
)


def required_selections(condition: Any) -> list[str]:
    """Selections that must match for ``condition`` to be true; empty if unsure.

    Only a plain chain such as ``a and b and not c`` is understood: ``a`` and
    ``b`` are required, ``c`` is not.
    """
    if not isinstance(condition, str):
        return []
    tokens = tokenize(condition)
    if any(token.lower() in _STRUCTURE or "*" in token for token in tokens):
        return []
    required: list[str] = []
    negated = False
    expect_operand = True
    for token in tokens:
        word = token.lower()
        if expect_operand and word == "not":
            negated = not negated
            continue
        if expect_operand:
            if not negated:
                required.append(token)
            negated, expect_operand = False, False
        elif word == "and":
            expect_operand = True
        else:
            return []
    return required if not expect_operand else []


def _field_condition(key: str, expected: Any) -> ColumnElement[bool] | None:
    field, *modifiers = str(key).split("|")
    spec = FIELDS_BY_NAME.get(field)
    values = expected if isinstance(expected, list) else [expected]
    if modifiers or spec is None or not values:
        return None
    column = _EVENTS.c[spec.column]
    if spec.kind is FieldKind.INTEGER:
        numbers = all(isinstance(value, int) and not isinstance(value, bool) for value in values)
        return column.in_(values) if numbers else None
    needles = plain_needles(values) if spec.kind in _TEXT_KINDS else None
    # Python and PostgreSQL agree on lower-casing ASCII; leave anything else to Python.
    if needles is None or not all(needle.isascii() for needle in needles):
        return None
    return func.lower(column).in_(sorted(set(needles)))


def detection_filter(detection: Mapping[str, Any] | None) -> ColumnElement[bool] | None:
    """SQL that every event matching ``detection`` satisfies, or ``None``."""
    if not detection:
        return None
    conditions: list[ColumnElement[bool]] = []
    for name in required_selections(detection.get("condition")):
        body = detection.get(name)
        if not isinstance(body, Mapping):
            continue
        for key, expected in body.items():
            condition = _field_condition(str(key), expected)
            if condition is not None:
                conditions.append(condition)
    return and_(*conditions) if conditions else None


def rule_filter(rule: CompiledRule) -> ColumnElement[bool] | None:
    """SQL that every event relevant to ``rule`` satisfies, or ``None``."""
    definition = rule.definition
    if rule.rule_type is RuleType.SEQUENCE and definition.sequence is not None:
        steps = [detection_filter(step.detection) for step in definition.sequence.steps]
        if any(step is None for step in steps):
            return None
        return or_(*(step for step in steps if step is not None))
    return detection_filter(definition.detection)


def any_rule_filter(rules: Sequence[CompiledRule]) -> ColumnElement[bool] | None:
    """SQL for events relevant to at least one of ``rules``, or ``None``."""
    filters = [rule_filter(rule) for rule in rules]
    if not filters or any(item is None for item in filters):
        return None
    return or_(*(item for item in filters if item is not None))


def _selection_fields(detection: Mapping[str, Any]) -> set[str] | None:
    fields: set[str] = set()
    for name, body in detection.items():
        if name == "condition":
            continue
        mappings = body if isinstance(body, list) else [body]
        for mapping in mappings:
            # Keyword lists search the raw line as well as the message.
            if not isinstance(mapping, Mapping):
                return None
            fields.update(str(key).split("|")[0] for key in mapping)
    return fields


def rule_columns(rule: CompiledRule) -> list[ColumnElement[Any]] | None:
    """The columns ``rule`` reads, or ``None`` if it needs the raw record (or more)."""
    definition = rule.definition
    detections = [definition.detection] if definition.detection is not None else []
    if definition.sequence is not None:
        detections += [step.detection for step in definition.sequence.steps]
    fields = set(rule.group_fields)
    if definition.threshold is not None and definition.threshold.distinct:
        fields.add(definition.threshold.distinct)
    if definition.new_value is not None:
        fields.add(definition.new_value.field)
    for detection in detections:
        selected = _selection_fields(detection)
        if selected is None:
            return None
        fields |= selected
    names = set(_ENGINE_COLUMNS)
    for field in fields:
        spec = FIELDS_BY_NAME.get(field)
        if spec is None:
            return None
        names.add(spec.column)
    return [_EVENTS.c[name] for name in sorted(names)]
