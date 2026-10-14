"""The events around an alert, in time order.

The timeline covers the alert's activity widened by a window on both sides
and includes every event that shares one of the alert's entities (host,
source IP or user), so an analyst can see what led up to the detection and
what followed. Evidence events are marked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Alert, Event, alert_events

DEFAULT_WINDOW = timedelta(minutes=30)
MAX_WINDOW = timedelta(hours=24)
MAX_TIMELINE_EVENTS = 500


@dataclass(slots=True)
class Timeline:
    start: datetime
    end: datetime
    entities: dict[str, str]
    events: list[Event] = field(default_factory=list)
    evidence_ids: set[int] = field(default_factory=set)
    truncated: bool = False


def _entity_conditions(alert: Alert) -> tuple[dict[str, str], list[ColumnElement[bool]]]:
    entities: dict[str, str] = {}
    conditions: list[ColumnElement[bool]] = []
    if alert.host_name:
        entities["host.name"] = alert.host_name
        conditions.append(Event.host_name == alert.host_name)
    if alert.source_ip:
        entities["source.ip"] = str(alert.source_ip)
        conditions.append(
            or_(Event.source_ip == alert.source_ip, Event.destination_ip == alert.source_ip)
        )
    if alert.user_name:
        entities["user.name"] = alert.user_name
        conditions.append(Event.user_name == alert.user_name)
    return entities, conditions


async def alert_timeline(
    session: AsyncSession, alert: Alert, window: timedelta = DEFAULT_WINDOW
) -> Timeline:
    """Events involving the alert's entities from ``window`` before to ``window`` after it."""
    window = min(max(window, timedelta(0)), MAX_WINDOW)
    entities, conditions = _entity_conditions(alert)
    timeline = Timeline(
        start=alert.first_seen - window, end=alert.last_seen + window, entities=entities
    )
    evidence = select(alert_events.c.event_id).where(alert_events.c.alert_id == alert.id)
    timeline.evidence_ids = set(await session.scalars(evidence))
    involved = or_(Event.id.in_(evidence), *conditions)
    events = list(
        await session.scalars(
            select(Event)
            .where(involved, Event.timestamp >= timeline.start, Event.timestamp <= timeline.end)
            .order_by(Event.timestamp, Event.id)
            .limit(MAX_TIMELINE_EVENTS + 1)
        )
    )
    timeline.truncated = len(events) > MAX_TIMELINE_EVENTS
    timeline.events = events[:MAX_TIMELINE_EVENTS]
    return timeline
