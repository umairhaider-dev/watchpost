"""Numbers for the overview dashboard.

Everything is computed with a handful of aggregate queries, so the
dashboard stays fast however many events are stored:

* alert metrics cover alerts whose activity started in the period
  (``first_seen``), so imported historical logs land where they happened;
* the ingestion rate comes from completed ingestion jobs, attributed to the
  time each job finished;
* resolution times cover cases and alerts resolved in the period.

Time series are bucketed on fixed UTC boundaries and padded with empty
buckets, so a chart always has one bar per interval.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import ColumnElement, desc, extract, func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import (
    OPEN_ALERT_STATUSES,
    Alert,
    AlertStatus,
    Case,
    CaseStatus,
    Event,
    IngestionJob,
    IngestStatus,
    Ioc,
    IocType,
    Rule,
    Severity,
)

TOP_N = 10
MAX_BUCKETS = 120
# "All time" picks the finest bucket that keeps the chart near this many bars.
TARGET_BUCKETS = 60
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_HOUR = timedelta(hours=1)
_DAY = timedelta(days=1)
# Bucket sizes for "all time", from finest to coarsest.
_BUCKET_STEPS = (_HOUR, 6 * _HOUR, _DAY, 7 * _DAY, 30 * _DAY)


class DashboardRange(StrEnum):
    DAY = "24h"
    WEEK = "7d"
    MONTH = "30d"
    ALL = "all"


_FIXED: dict[DashboardRange, tuple[timedelta, timedelta]] = {
    DashboardRange.DAY: (_DAY, _HOUR),
    DashboardRange.WEEK: (7 * _DAY, 6 * _HOUR),
    DashboardRange.MONTH: (30 * _DAY, _DAY),
}


@dataclass(frozen=True, slots=True)
class Period:
    """What to count (``start`` onwards, or everything) and how to chart it."""

    start: datetime | None
    end: datetime
    bucket: timedelta
    # Where the chart begins: the period start, or the earliest data for "all time".
    origin: datetime

    def buckets(self) -> list[datetime]:
        """The start of every bucket up to ``end``, at most the latest ``MAX_BUCKETS``."""
        first = floor_time(self.origin, self.bucket)
        last = floor_time(self.end, self.bucket)
        count = int((last - first) / self.bucket) + 1
        skip = max(0, count - MAX_BUCKETS)
        return [first + self.bucket * index for index in range(skip, count)]


def floor_time(moment: datetime, bucket: timedelta) -> datetime:
    """The start of the bucket containing ``moment`` (buckets are aligned to the epoch)."""
    steps = (moment - EPOCH) // bucket
    return EPOCH + bucket * steps


def bucket_for_span(span: timedelta) -> timedelta:
    """The finest bucket that keeps a span to about ``TARGET_BUCKETS`` bars."""
    for step in _BUCKET_STEPS:
        if span / step <= TARGET_BUCKETS:
            return step
    return _BUCKET_STEPS[-1]


@dataclass(slots=True)
class Ranked:
    value: str
    alerts: int
    events: int
    known_bad: bool = False


@dataclass(slots=True)
class RuleCount:
    rule_id: str
    title: str
    severity: Severity
    alerts: int


@dataclass(slots=True)
class Resolution:
    resolved: int = 0
    mean_seconds: float | None = None
    median_seconds: float | None = None


@dataclass(slots=True)
class Dashboard:
    range: DashboardRange
    start: datetime | None
    end: datetime
    bucket_seconds: int
    totals: dict[str, int] = field(default_factory=dict)
    alerts_over_time: list[dict[str, Any]] = field(default_factory=list)
    alerts_by_severity: list[dict[str, Any]] = field(default_factory=list)
    top_source_ips: list[Ranked] = field(default_factory=list)
    top_users: list[Ranked] = field(default_factory=list)
    top_rules: list[RuleCount] = field(default_factory=list)
    ingestion: dict[str, Any] = field(default_factory=dict)
    case_resolution: Resolution = field(default_factory=Resolution)
    alert_resolution: Resolution = field(default_factory=Resolution)


async def _period(session: AsyncSession, chosen: DashboardRange, now: datetime) -> Period:
    if chosen in _FIXED:
        length, bucket = _FIXED[chosen]
        return Period(start=now - length, end=now, bucket=bucket, origin=now - length)
    earliest = await _earliest(session) or now - 30 * _DAY
    return Period(start=None, end=now, bucket=bucket_for_span(now - earliest), origin=earliest)


async def _earliest(session: AsyncSession) -> datetime | None:
    first_alert = await session.scalar(select(func.min(Alert.first_seen)))
    first_job = await session.scalar(select(func.min(IngestionJob.finished_at)))
    candidates = [moment for moment in (first_alert, first_job) if moment is not None]
    return min(candidates) if candidates else None


def _since(column: Any, period: Period) -> ColumnElement[bool]:
    return column >= period.start if period.start is not None else true()


async def _totals(session: AsyncSession, period: Period) -> dict[str, int]:
    open_alerts = Alert.status.in_(OPEN_ALERT_STATUSES)
    alert_row = (
        await session.execute(
            select(
                func.count().filter(_since(Alert.first_seen, period)),
                func.count().filter(open_alerts),
                func.count().filter(Alert.status == AlertStatus.NEW),
                func.count().filter(open_alerts, Alert.assignee_id.is_(None)),
            )
        )
    ).one()
    open_cases = await session.scalar(
        select(func.count())
        .select_from(Case)
        .where(Case.status.in_([CaseStatus.OPEN, CaseStatus.IN_PROGRESS]))
    )
    events = await session.scalar(select(func.count()).select_from(Event))
    return {
        "alerts": alert_row[0],
        "open_alerts": alert_row[1],
        "new_alerts": alert_row[2],
        "unassigned_open_alerts": alert_row[3],
        "open_cases": open_cases or 0,
        "events": events or 0,
    }


async def _alerts_over_time(
    session: AsyncSession, period: Period, buckets: list[datetime]
) -> list[dict[str, Any]]:
    bucket = func.date_bin(period.bucket, Alert.first_seen, EPOCH).label("bucket")
    rows = await session.execute(
        select(bucket, Alert.severity, func.count())
        .where(_since(Alert.first_seen, period))
        .group_by(bucket, Alert.severity)
    )
    series = {start: {severity.value: 0 for severity in Severity} for start in buckets}
    for start, severity, count in rows:
        if start in series:
            series[start][severity.value] += count
    return [{"bucket": start, **counts} for start, counts in series.items()]


async def _by_severity(session: AsyncSession, period: Period) -> list[dict[str, Any]]:
    rows = {
        severity: (total, open_)
        for severity, total, open_ in await session.execute(
            select(
                Alert.severity,
                func.count(),
                func.count().filter(Alert.status.in_(OPEN_ALERT_STATUSES)),
            )
            .where(_since(Alert.first_seen, period))
            .group_by(Alert.severity)
        )
    }
    ordered = sorted(Severity, key=lambda severity: severity.rank, reverse=True)
    return [
        {
            "severity": severity,
            "count": rows.get(severity, (0, 0))[0],
            "open": rows.get(severity, (0, 0))[1],
        }
        for severity in ordered
    ]


async def _top_entities(session: AsyncSession, period: Period, column: Any) -> list[Ranked]:
    alerts = func.count().label("alerts")
    rows = await session.execute(
        select(column, alerts, func.coalesce(func.sum(Alert.event_count), 0))
        .where(_since(Alert.first_seen, period), column.is_not(None))
        .group_by(column)
        .order_by(desc(alerts), desc(func.sum(Alert.event_count)), column)
        .limit(TOP_N)
    )
    return [Ranked(str(value), count, int(events)) for value, count, events in rows]


async def _mark_known_bad(session: AsyncSession, ranked: list[Ranked]) -> None:
    if not ranked:
        return
    known = set(
        await session.scalars(
            select(Ioc.value).where(
                Ioc.ioc_type == IocType.IP,
                Ioc.is_active.is_(True),
                Ioc.value.in_([item.value for item in ranked]),
            )
        )
    )
    for item in ranked:
        item.known_bad = item.value in known


async def _top_rules(session: AsyncSession, period: Period) -> list[RuleCount]:
    alerts = func.count().label("alerts")
    rows = await session.execute(
        select(Rule.id, Rule.title, Rule.severity, alerts)
        .join(Alert, Alert.rule_id == Rule.id)
        .where(_since(Alert.first_seen, period))
        .group_by(Rule.id, Rule.title, Rule.severity)
        .order_by(desc(alerts), Rule.id)
        .limit(TOP_N)
    )
    return [RuleCount(rule_id, title, severity, count) for rule_id, title, severity, count in rows]


async def _ingestion(
    session: AsyncSession, period: Period, buckets: list[datetime]
) -> dict[str, Any]:
    finished = IngestionJob.status == IngestStatus.COMPLETED
    in_period = _since(IngestionJob.finished_at, period)
    bucket = func.date_bin(period.bucket, IngestionJob.finished_at, EPOCH).label("bucket")
    rows = await session.execute(
        select(bucket, func.sum(IngestionJob.events_inserted), func.count())
        .where(finished, in_period)
        .group_by(bucket)
    )
    series = {start: {"events": 0, "jobs": 0} for start in buckets}
    for start, events, jobs in rows:
        if start in series:
            series[start] = {"events": int(events or 0), "jobs": jobs}
    duration = extract("epoch", IngestionJob.finished_at - IngestionJob.started_at)
    events, jobs, seconds = (
        await session.execute(
            select(
                func.coalesce(func.sum(IngestionJob.events_inserted), 0),
                func.count(),
                func.sum(duration),
            ).where(finished, in_period, IngestionJob.started_at.is_not(None))
        )
    ).one()
    rate = float(events) / float(seconds) if seconds and float(seconds) > 0 else None
    return {
        "series": [{"bucket": start, **counts} for start, counts in series.items()],
        "events_ingested": int(events),
        "jobs": jobs,
        "events_per_second": rate,
    }


async def _resolution(
    session: AsyncSession, opened: Any, resolved: Any, period: Period
) -> Resolution:
    seconds = extract("epoch", resolved - opened)
    count, mean, median = (
        await session.execute(
            select(
                func.count(),
                func.avg(seconds),
                func.percentile_cont(0.5).within_group(seconds),
            ).where(resolved.is_not(None), _since(resolved, period))
        )
    ).one()
    return Resolution(
        resolved=count,
        mean_seconds=float(mean) if mean is not None else None,
        median_seconds=float(median) if median is not None else None,
    )


async def build_dashboard(
    session: AsyncSession, chosen: DashboardRange, now: datetime | None = None
) -> Dashboard:
    """All dashboard figures for the chosen period, ending ``now``."""
    now = now or datetime.now(UTC)
    period = await _period(session, chosen, now)
    buckets = period.buckets()
    dashboard = Dashboard(
        range=chosen,
        start=period.start,
        end=now,
        bucket_seconds=int(period.bucket.total_seconds()),
    )
    dashboard.totals = await _totals(session, period)
    dashboard.alerts_over_time = await _alerts_over_time(session, period, buckets)
    dashboard.alerts_by_severity = await _by_severity(session, period)
    dashboard.top_source_ips = await _top_entities(session, period, Alert.source_ip)
    await _mark_known_bad(session, dashboard.top_source_ips)
    dashboard.top_users = await _top_entities(session, period, Alert.user_name)
    dashboard.top_rules = await _top_rules(session, period)
    dashboard.ingestion = await _ingestion(session, period, buckets)
    dashboard.case_resolution = await _resolution(
        session, Case.created_at, Case.resolved_at, period
    )
    dashboard.alert_resolution = await _resolution(
        session, Alert.created_at, Alert.resolved_at, period
    )
    return dashboard
