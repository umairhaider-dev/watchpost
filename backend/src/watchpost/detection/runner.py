"""Running rules over stored events and turning hits into alerts.

A detection run has a *scope*: the events one ingestion job inserted, or a
time range. Scope events are streamed from PostgreSQL in chunks:

* match rules are evaluated chunk by chunk;
* threshold and sequence rules also need the events *around* the scope (a
  brute force can straddle two uploads), so their log sources are read
  again for the scope's time range widened by the rule's window; only hits
  that include a scope event are kept;
* new_value rules compare scope events with the entity's history over the
  lookback period.

Hits become alerts through an upsert on the partial unique index of open
alerts: a repeat hit for the same rule and entity updates the open alert
instead of creating another. Evidence links are idempotent, so running
detection twice over the same events changes nothing.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Result,
    Select,
    func,
    literal_column,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.db.models import (
    Alert,
    AlertStatus,
    DetectionRun,
    DetectionStatus,
    DetectionTrigger,
    Event,
    RuleType,
    alert_events,
)
from watchpost.db.streaming import stream_rows
from watchpost.detection.compiler import CompiledRule
from watchpost.detection.engine import (
    MAX_EVIDENCE_PER_HIT,
    Hit,
    evaluate_match,
    evaluate_new_value,
    evaluate_sequence,
    evaluate_threshold,
)
from watchpost.detection.fields import EventRow
from watchpost.detection.store import load_compiled_rules
from watchpost.events import FIELDS_BY_NAME

logger = logging.getLogger(__name__)

MAX_EVIDENCE_PER_ALERT = MAX_EVIDENCE_PER_HIT
_EVENTS = Event.__table__
_OPEN_ALERT = text("status IN ('new', 'investigating')")


# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Scope:
    """Which events a run is about: one ingestion job, or a time range."""

    ingest_job_id: int | None = None
    start: datetime | None = None
    end: datetime | None = None

    def conditions(self) -> list[ColumnElement[bool]]:
        if self.ingest_job_id is not None:
            return [_EVENTS.c.ingest_job_id == self.ingest_job_id]
        conditions: list[ColumnElement[bool]] = []
        if self.start is not None:
            conditions.append(_EVENTS.c.timestamp >= self.start)
        if self.end is not None:
            conditions.append(_EVENTS.c.timestamp <= self.end)
        return conditions

    def contains(self, row: EventRow) -> bool:
        if self.ingest_job_id is not None:
            return bool(row.get("ingest_job_id") == self.ingest_job_id)
        timestamp: datetime = row["timestamp"]
        return (self.start is None or timestamp >= self.start) and (
            self.end is None or timestamp <= self.end
        )


@dataclass(slots=True)
class _Bounds:
    first: datetime | None = None
    last: datetime | None = None

    def update(self, rows: Sequence[EventRow]) -> None:
        for row in rows:
            timestamp: datetime = row["timestamp"]
            if self.first is None or timestamp < self.first:
                self.first = timestamp
            if self.last is None or timestamp > self.last:
                self.last = timestamp


def _source_filter(query: Select[Any], sources: frozenset[str] | None) -> Select[Any]:
    if sources is None:
        return query
    return query.where(_EVENTS.c.log_source.in_(sorted(sources)))


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


@dataclass(slots=True)
class DetectionResult:
    events_scanned: int = 0
    hits: list[tuple[CompiledRule, Hit]] = field(default_factory=list)


def _window(rule: CompiledRule) -> timedelta:
    definition = rule.definition
    if definition.threshold is not None:
        return definition.threshold.timeframe
    if definition.sequence is not None:
        return definition.sequence.maxspan
    return timedelta(0)


def _merge(existing: Hit, new: Hit) -> Hit:
    """Combine two hits for the same rule and entity from different chunks."""
    room = MAX_EVIDENCE_PER_HIT - len(existing.event_ids)
    latest = new if new.last_seen >= existing.last_seen else existing
    return Hit(
        rule_id=existing.rule_id,
        group=existing.group,
        event_ids=existing.event_ids + new.event_ids[: max(room, 0)],
        event_count=existing.event_count + new.event_count,
        first_seen=min(existing.first_seen, new.first_seen),
        last_seen=max(existing.last_seen, new.last_seen),
        host_name=latest.host_name,
        source_ip=latest.source_ip,
        user_name=latest.user_name,
    )


def _scan_chunk(
    match_rules: Sequence[CompiledRule],
    value_rules: Sequence[CompiledRule],
    rows: Sequence[EventRow],
    targets: dict[str, list[EventRow]],
) -> list[tuple[CompiledRule, Hit]]:
    hits = [(rule, hit) for rule in match_rules for hit in evaluate_match(rule, rows)]
    for rule in value_rules:
        targets[rule.id].extend(row for row in rows if rule.matches(row))
    return hits


def _keep_relevant(
    rules: Sequence[CompiledRule], rows: Sequence[EventRow], kept: dict[str, list[EventRow]]
) -> None:
    for rule in rules:
        if rule.rule_type is RuleType.SEQUENCE:
            relevant = [
                row
                for row in rows
                if rule.accepts_source(row) and any(step.predicate(row) for step in rule.steps)
            ]
        else:
            relevant = [row for row in rows if rule.matches(row)]
        kept[rule.id].extend(relevant)


def _evaluate_window_rule(rule: CompiledRule, rows: Sequence[EventRow], scope: Scope) -> list[Hit]:
    if rule.rule_type is RuleType.THRESHOLD:
        return evaluate_threshold(rule, rows, scope.contains)
    return evaluate_sequence(rule, rows, scope.contains)


async def detect(
    session_factory: async_sessionmaker[AsyncSession],
    rules: Sequence[CompiledRule],
    scope: Scope,
) -> DetectionResult:
    """Evaluate ``rules`` over the events in ``scope``. Does not write anything."""
    match_rules = [rule for rule in rules if rule.rule_type is RuleType.MATCH]
    window_rules = [
        rule for rule in rules if rule.rule_type in {RuleType.THRESHOLD, RuleType.SEQUENCE}
    ]
    value_rules = [rule for rule in rules if rule.rule_type is RuleType.NEW_VALUE]

    result = DetectionResult()
    merged: dict[tuple[str, str], tuple[CompiledRule, Hit]] = {}
    targets: dict[str, list[EventRow]] = defaultdict(list)
    bounds = _Bounds()

    scope_query = select(_EVENTS).where(*scope.conditions())
    async for rows in stream_rows(session_factory, scope_query):
        result.events_scanned += len(rows)
        bounds.update(rows)
        for rule, hit in await asyncio.to_thread(
            _scan_chunk, match_rules, value_rules, rows, targets
        ):
            key = (rule.id, hit.group_key)
            previous = merged.get(key)
            merged[key] = (rule, _merge(previous[1], hit) if previous else hit)
    result.hits.extend(merged.values())
    if bounds.first is None or bounds.last is None:
        return result

    await _detect_windows(session_factory, window_rules, scope, (bounds.first, bounds.last), result)
    await _detect_new_values(session_factory, value_rules, targets, result)
    return result


async def _detect_windows(
    session_factory: async_sessionmaker[AsyncSession],
    rules: Sequence[CompiledRule],
    scope: Scope,
    span: tuple[datetime, datetime],
    result: DetectionResult,
) -> None:
    # One pass over the context per set of log sources, shared by its rules.
    by_sources: dict[frozenset[str] | None, list[CompiledRule]] = defaultdict(list)
    for rule in rules:
        by_sources[rule.log_sources].append(rule)
    first, last = span
    for sources, group in by_sources.items():
        widest = max(_window(rule) for rule in group)
        query = _source_filter(select(_EVENTS), sources).where(
            _EVENTS.c.timestamp >= first - widest,
            _EVENTS.c.timestamp <= last + widest,
        )
        kept: dict[str, list[EventRow]] = defaultdict(list)
        async for rows in stream_rows(session_factory, query):
            await asyncio.to_thread(_keep_relevant, group, rows, kept)
        for rule in group:
            hits = await asyncio.to_thread(_evaluate_window_rule, rule, kept[rule.id], scope)
            result.hits.extend((rule, hit) for hit in hits)


async def _detect_new_values(
    session_factory: async_sessionmaker[AsyncSession],
    rules: Sequence[CompiledRule],
    targets: dict[str, list[EventRow]],
    result: DetectionResult,
) -> None:
    for rule in rules:
        rule_targets = targets.get(rule.id, [])
        spec = rule.definition.new_value
        if not rule_targets or spec is None:
            continue
        first = min(row["timestamp"] for row in rule_targets)
        last = max(row["timestamp"] for row in rule_targets)
        query = _source_filter(select(_EVENTS), rule.log_sources).where(
            _EVENTS.c.timestamp >= first - spec.lookback, _EVENTS.c.timestamp <= last
        )
        # Narrow the history to the entities involved when that maps to a column.
        if len(rule.group_fields) == 1 and rule.group_fields[0] in FIELDS_BY_NAME:
            column = _EVENTS.c[FIELDS_BY_NAME[rule.group_fields[0]].column]
            entities = {values[0] for values in map(rule.group_values, rule_targets)}
            query = query.where(column.in_(sorted(entity for entity in entities if entity)))
        history: list[EventRow] = []
        async for rows in stream_rows(session_factory, query):
            history.extend(row for row in rows if rule.matches(row))
        hits = await asyncio.to_thread(evaluate_new_value, rule, history, rule_targets)
        result.hits.extend((rule, hit) for hit in hits)


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------


@dataclass(slots=True)
class SaveResult:
    created: int = 0
    updated: int = 0


def alert_title(rule: CompiledRule, hit: Hit) -> str:
    label = hit.group_label
    title = f"{rule.title}: {label}" if label else rule.title
    return title[:255]


async def save_hits(session: AsyncSession, hits: Sequence[tuple[CompiledRule, Hit]]) -> SaveResult:
    """Create or update one alert per hit and link its evidence. Flushes, does not commit."""
    saved = SaveResult()
    for rule, hit in hits:
        insert = pg_insert(Alert).values(
            rule_id=rule.id,
            title=alert_title(rule, hit),
            severity=rule.severity,
            status=AlertStatus.NEW,
            group_key=hit.group_key,
            first_seen=hit.first_seen,
            last_seen=hit.last_seen,
            event_count=0,
            host_name=hit.host_name,
            source_ip=hit.source_ip,
            user_name=hit.user_name,
            mitre_tactics=rule.definition.tactics,
            mitre_techniques=rule.definition.techniques,
        )
        upsert = insert.on_conflict_do_update(
            index_elements=[Alert.group_key],
            index_where=_OPEN_ALERT,
            set_={
                "first_seen": func.least(Alert.first_seen, insert.excluded.first_seen),
                "last_seen": func.greatest(Alert.last_seen, insert.excluded.last_seen),
                "host_name": func.coalesce(insert.excluded.host_name, Alert.host_name),
                "source_ip": func.coalesce(insert.excluded.source_ip, Alert.source_ip),
                "user_name": func.coalesce(insert.excluded.user_name, Alert.user_name),
                "updated_at": func.now(),
            },
        )
        # xmax is 0 for a freshly inserted row and non-zero for an updated one.
        returned: Result[int, int, bool] = await session.execute(
            upsert.returning(
                Alert.id, Alert.event_count, literal_column("xmax = 0").label("created")
            )
        )
        alert_id, current_count, created = returned.one()

        room = max(MAX_EVIDENCE_PER_ALERT - current_count, 0)
        evidence = hit.event_ids[:room]
        linked = 0
        if evidence:
            links = await session.execute(
                pg_insert(alert_events)
                .values([{"alert_id": alert_id, "event_id": event_id} for event_id in evidence])
                .on_conflict_do_nothing()
                .returning(alert_events.c.event_id)
            )
            linked = len(links.all())
        # Events beyond the evidence cap still count, once.
        overflow = hit.event_count - len(hit.event_ids) if created else 0
        if linked or overflow:
            await session.execute(
                update(Alert)
                .where(Alert.id == alert_id)
                .values(event_count=Alert.event_count + linked + overflow)
            )
        if created:
            saved.created += 1
        else:
            saved.updated += 1
    await session.flush()
    return saved


# --------------------------------------------------------------------------
# Runs
# --------------------------------------------------------------------------


async def create_run(
    session: AsyncSession,
    *,
    trigger: DetectionTrigger,
    ingest_job_id: int | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    rule_ids: Sequence[str] | None = None,
    created_by_id: int | None = None,
) -> DetectionRun:
    """Record a queued detection run. Flushes, does not commit."""
    run = DetectionRun(
        trigger=trigger,
        ingest_job_id=ingest_job_id,
        range_start=start,
        range_end=end,
        rule_ids=list(rule_ids) if rule_ids is not None else None,
        created_by_id=created_by_id,
    )
    session.add(run)
    await session.flush()
    return run


async def execute_run(
    session_factory: async_sessionmaker[AsyncSession], run_id: int
) -> DetectionStatus | None:
    """Carry out a queued detection run. Returns its final status, or ``None`` if skipped."""
    async with session_factory() as session:
        run = await session.get(DetectionRun, run_id, with_for_update=True)
        if run is None or run.status in {DetectionStatus.COMPLETED, DetectionStatus.FAILED}:
            logger.info("Detection run %d is missing or already finished; skipping", run_id)
            return None
        run.status = DetectionStatus.RUNNING
        run.started_at = datetime.now(UTC)
        scope = Scope(ingest_job_id=run.ingest_job_id, start=run.range_start, end=run.range_end)
        rule_ids = run.rule_ids
        await session.commit()

    try:
        async with session_factory() as session:
            loaded = await load_compiled_rules(session, rule_ids, enabled_only=rule_ids is None)
        result = await detect(session_factory, loaded.rules, scope)
        async with session_factory() as session:
            saved = await save_hits(session, result.hits)
            await session.execute(
                update(DetectionRun)
                .where(DetectionRun.id == run_id)
                .values(
                    status=DetectionStatus.COMPLETED,
                    finished_at=datetime.now(UTC),
                    events_scanned=result.events_scanned,
                    hits=len(result.hits),
                    alerts_created=saved.created,
                    alerts_updated=saved.updated,
                    error=(
                        f"skipped rules that failed to compile: {', '.join(loaded.broken)}"
                        if loaded.broken
                        else None
                    ),
                )
            )
            await session.commit()
    except Exception:
        # Run boundary: record the failure so the UI shows it; details go to the log.
        logger.exception("Detection run %d failed", run_id)
        async with session_factory() as session:
            await session.execute(
                update(DetectionRun)
                .where(DetectionRun.id == run_id)
                .values(
                    status=DetectionStatus.FAILED,
                    finished_at=datetime.now(UTC),
                    error="detection failed; see worker logs",
                )
            )
            await session.commit()
        return DetectionStatus.FAILED
    logger.info(
        "Detection run %d: %d events, %d hits, %d new alerts, %d updated",
        run_id,
        result.events_scanned,
        len(result.hits),
        saved.created,
        saved.updated,
    )
    return DetectionStatus.COMPLETED
