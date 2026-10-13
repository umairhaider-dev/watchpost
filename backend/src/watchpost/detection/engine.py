"""Evaluating compiled rules over event rows.

Everything here is pure: it takes rows (``events`` columns plus
``raw_event``) and returns :class:`Hit` objects. The database runner and the
rule tester both use it; only where the rows come from differs.

Hits are already grouped: one hit per rule and ``group_by`` entity for
match rules, and one hit per burst for threshold and sequence rules, so a
brute force of five hundred attempts is one hit, not five hundred.
"""

from __future__ import annotations

import bisect
import hashlib
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from watchpost.db.models import RuleType
from watchpost.detection.compiler import CompiledRule
from watchpost.detection.fields import EventRow

# Evidence kept per hit; the event count keeps going beyond it.
MAX_EVIDENCE_PER_HIT = 10_000
_MAX_GROUP_KEY_LENGTH = 400

InScope = Callable[[EventRow], bool]


def _always(_row: EventRow) -> bool:
    return True


@dataclass(slots=True)
class Hit:
    """A rule firing for one entity, with the events that caused it."""

    rule_id: str
    group: tuple[tuple[str, str | None], ...]
    event_ids: list[int]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    host_name: str | None = None
    source_ip: str | None = None
    user_name: str | None = None

    @property
    def group_key(self) -> str:
        """Stable identity used to merge hits into one open alert."""
        described = "|".join(
            f"{name}={value if value is not None else '-'}" for name, value in self.group
        )
        key = f"{self.rule_id}|{described}"
        if len(key) > _MAX_GROUP_KEY_LENGTH:
            digest = hashlib.sha256(described.encode("utf-8")).hexdigest()
            key = f"{self.rule_id}|sha256={digest}"
        return key

    @property
    def group_label(self) -> str:
        """Human-readable entity, e.g. ``203.0.113.45`` or ``web-01, alice``."""
        values = [value for _, value in self.group if value is not None]
        return ", ".join(values)


@dataclass(slots=True)
class _HitBuilder:
    rule_id: str
    group: tuple[tuple[str, str | None], ...]
    event_ids: list[int] = field(default_factory=list)
    seen_ids: set[int] = field(default_factory=set)
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    latest: EventRow | None = None

    def add(self, row: EventRow) -> None:
        event_id = int(row["id"])
        if event_id in self.seen_ids:
            return
        self.seen_ids.add(event_id)
        self.event_count += 1
        if len(self.event_ids) < MAX_EVIDENCE_PER_HIT:
            self.event_ids.append(event_id)
        timestamp: datetime = row["timestamp"]
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp >= self.last_seen:
            self.last_seen = timestamp
            self.latest = row

    def build(self) -> Hit:
        if self.first_seen is None or self.last_seen is None or self.latest is None:
            msg = "cannot build a hit without events"
            raise ValueError(msg)
        return Hit(
            rule_id=self.rule_id,
            group=self.group,
            event_ids=self.event_ids,
            event_count=self.event_count,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            host_name=self.latest.get("host_name"),
            source_ip=self.latest.get("source_ip"),
            user_name=self.latest.get("user_name"),
        )


def _sort_key(row: EventRow) -> tuple[datetime, int]:
    return row["timestamp"], int(row["id"])


def _labelled(
    rule: CompiledRule, values: tuple[str | None, ...]
) -> tuple[tuple[str, str | None], ...]:
    return tuple(zip(rule.group_fields, values, strict=True))


# --------------------------------------------------------------------------
# match
# --------------------------------------------------------------------------


def evaluate_match(rule: CompiledRule, rows: Iterable[EventRow]) -> list[Hit]:
    """Every matching event, grouped by the rule's entity fields."""
    builders: dict[tuple[str | None, ...], _HitBuilder] = {}
    for row in rows:
        if not rule.matches(row):
            continue
        values = rule.group_values(row)
        builder = builders.get(values)
        if builder is None:
            builder = builders[values] = _HitBuilder(rule.id, _labelled(rule, values))
        builder.add(row)
    return [builder.build() for builder in builders.values()]


# --------------------------------------------------------------------------
# threshold
# --------------------------------------------------------------------------


def evaluate_threshold(
    rule: CompiledRule, rows: Iterable[EventRow], in_scope: InScope = _always
) -> list[Hit]:
    """Bursts of at least ``count`` matching events (or distinct values) within ``timeframe``.

    Every window that reaches the threshold marks its events; marked events
    closer together than ``timeframe`` form one hit. Hits made only of
    out-of-scope events are dropped, so re-scanning context around new
    events does not re-raise old activity.
    """
    spec = rule.definition.threshold
    if spec is None:
        msg = f"rule {rule.id} has no threshold settings"
        raise ValueError(msg)
    groups: dict[tuple[str | None, ...], list[EventRow]] = defaultdict(list)
    for row in rows:
        if rule.matches(row):
            groups[rule.group_values(row)].append(row)

    hits: list[Hit] = []
    for values, events in groups.items():
        events.sort(key=_sort_key)
        marked = _mark_threshold_windows(rule, events, spec.count, spec.timeframe)
        for cluster in _clusters(events, marked, spec.timeframe):
            if any(in_scope(row) for row in cluster):
                builder = _HitBuilder(rule.id, _labelled(rule, values))
                for row in cluster:
                    builder.add(row)
                hits.append(builder.build())
    return hits


def _mark_threshold_windows(
    rule: CompiledRule, events: Sequence[EventRow], count: int, timeframe: timedelta
) -> list[bool]:
    distinct = rule.distinct_resolver
    marked = [False] * len(events)
    values: Counter[str] = Counter()
    start = 0
    last_marked = -1
    for end, row in enumerate(events):
        if distinct is not None and (value := distinct(row)) is not None:
            values[str(value)] += 1
        while row["timestamp"] - events[start]["timestamp"] > timeframe:
            if distinct is not None and (old := distinct(events[start])) is not None:
                values[str(old)] -= 1
                if values[str(old)] == 0:
                    del values[str(old)]
            start += 1
        size = len(values) if distinct is not None else end - start + 1
        if size >= count:
            for index in range(max(start, last_marked + 1), end + 1):
                marked[index] = True
            last_marked = end
    return marked


def _clusters(
    events: Sequence[EventRow], marked: Sequence[bool], gap: timedelta
) -> list[list[EventRow]]:
    clusters: list[list[EventRow]] = []
    current: list[EventRow] = []
    for row, is_marked in zip(events, marked, strict=True):
        if not is_marked:
            continue
        if current and row["timestamp"] - current[-1]["timestamp"] > gap:
            clusters.append(current)
            current = []
        current.append(row)
    if current:
        clusters.append(current)
    return clusters


# --------------------------------------------------------------------------
# sequence
# --------------------------------------------------------------------------


def evaluate_sequence(
    rule: CompiledRule, rows: Iterable[EventRow], in_scope: InScope = _always
) -> list[Hit]:
    """Ordered steps from the same entity within ``maxspan``.

    For each event that can finish the sequence, the steps are matched
    greedily from the start of its window (earliest events first), which
    finds a match whenever one exists. All events used by matches for an
    entity are merged into one hit.
    """
    spec = rule.definition.sequence
    if spec is None:
        msg = f"rule {rule.id} has no sequence settings"
        raise ValueError(msg)
    steps = rule.steps
    groups: dict[tuple[str | None, ...], list[tuple[EventRow, tuple[bool, ...]]]] = defaultdict(
        list
    )
    for row in rows:
        if not rule.accepts_source(row):
            continue
        flags = tuple(step.predicate(row) for step in steps)
        if not any(flags):
            continue
        values = rule.group_values(row)
        if any(value is None for value in values):
            continue  # "the same entity" needs the entity to be known
        groups[values].append((row, flags))

    hits: list[Hit] = []
    for values, entries in groups.items():
        entries.sort(key=lambda entry: _sort_key(entry[0]))
        times = [entry[0]["timestamp"] for entry in entries]
        builder = _HitBuilder(rule.id, _labelled(rule, values))
        for end, (end_row, end_flags) in enumerate(entries):
            if not end_flags[-1]:
                continue
            start = bisect.bisect_left(times, end_row["timestamp"] - spec.maxspan)
            used = _match_steps(entries[start : end + 1], [step.count for step in steps])
            if used and any(in_scope(row) for row in used):
                for row in used:
                    builder.add(row)
        if builder.event_count:
            hits.append(builder.build())
    return hits


def _match_steps(
    window: Sequence[tuple[EventRow, tuple[bool, ...]]], counts: Sequence[int]
) -> list[EventRow]:
    used: list[EventRow] = []
    step = 0
    seen = 0
    for row, flags in window:
        if flags[step]:
            used.append(row)
            seen += 1
            if seen == counts[step]:
                step += 1
                seen = 0
                if step == len(counts):
                    return used
    return []


# --------------------------------------------------------------------------
# new_value
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Seen:
    timestamp: datetime
    event_id: int
    value: str


def evaluate_new_value(
    rule: CompiledRule, history: Iterable[EventRow], targets: Iterable[EventRow]
) -> list[Hit]:
    """Target events whose ``field`` value was not seen for their entity before.

    ``history`` must cover at least the lookback window before the earliest
    target; it may include the targets themselves. Each (entity, new value)
    pair becomes its own hit.
    """
    spec = rule.definition.new_value
    resolve_value = rule.value_resolver
    if spec is None or resolve_value is None:
        msg = f"rule {rule.id} has no new_value settings"
        raise ValueError(msg)

    seen_by_entity: dict[tuple[str | None, ...], list[_Seen]] = defaultdict(list)
    for row in history:
        if not rule.matches(row):
            continue
        value = resolve_value(row)
        if value is not None:
            seen = _Seen(row["timestamp"], int(row["id"]), str(value))
            seen_by_entity[rule.group_values(row)].append(seen)
    for entries in seen_by_entity.values():
        entries.sort(key=lambda seen: (seen.timestamp, seen.event_id))
    times_by_entity = {
        entity: [seen.timestamp for seen in entries] for entity, entries in seen_by_entity.items()
    }

    value_field = spec.field
    builders: dict[tuple[tuple[str | None, ...], str], _HitBuilder] = {}
    for row in targets:
        if not rule.matches(row):
            continue
        entity = rule.group_values(row)
        raw_value = resolve_value(row)
        if raw_value is None or any(value is None for value in entity):
            continue
        value = str(raw_value)
        prior = _prior_values(
            seen_by_entity.get(entity, []), times_by_entity.get(entity, []), row, spec.lookback
        )
        if (spec.require_history and not prior) or value in prior:
            continue
        key = (entity, value)
        builder = builders.get(key)
        if builder is None:
            group = (*_labelled(rule, entity), (value_field, value))
            builder = builders[key] = _HitBuilder(rule.id, group)
        builder.add(row)
    return [builder.build() for builder in builders.values()]


def _prior_values(
    entries: Sequence[_Seen], times: Sequence[datetime], row: EventRow, lookback: timedelta
) -> set[str]:
    """Values seen strictly before ``row`` and no earlier than ``lookback`` before it."""
    timestamp: datetime = row["timestamp"]
    event_id = int(row["id"])
    start = bisect.bisect_left(times, timestamp - lookback)
    values: set[str] = set()
    for seen in entries[start:]:
        if (seen.timestamp, seen.event_id) >= (timestamp, event_id):
            break
        values.add(seen.value)
    return values


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------


def evaluate(rule: CompiledRule, rows: Sequence[EventRow]) -> list[Hit]:
    """Evaluate any rule type over a self-contained set of rows (all in scope)."""
    if rule.rule_type is RuleType.MATCH:
        return evaluate_match(rule, rows)
    if rule.rule_type is RuleType.THRESHOLD:
        return evaluate_threshold(rule, rows)
    if rule.rule_type is RuleType.SEQUENCE:
        return evaluate_sequence(rule, rows)
    return evaluate_new_value(rule, rows, rows)


def row_with_id(row: dict[str, Any], event_id: int) -> dict[str, Any]:
    """Give an unsaved event row an ID so it can take part in evaluation."""
    return {**row, "id": event_id}
