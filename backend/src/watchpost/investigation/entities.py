"""Entity profiles: what is known about one IP address, user or host.

A profile summarises the events that involve the entity (when it was first
and last seen, from which log sources, daily activity, the entities it
interacted with most) and lists its alerts and the cases they belong to.
An IP address matches as either end of a connection.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from sqlalchemy import ColumnElement, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import OPEN_ALERT_STATUSES, Alert, Case, Event, Ioc, IocType
from watchpost.intel.alerts import local_intel

MAX_ALERTS = 50
TOP_RELATED = 10
ACTIVITY_DAYS = 60

_EVENTS = Event.__table__


class EntityKind(StrEnum):
    IP = "ip"
    USER = "user"
    HOST = "host"


class EntityError(ValueError):
    """The entity value is not valid for its kind."""


@dataclass(frozen=True, slots=True)
class Counted:
    value: str
    count: int


@dataclass(slots=True)
class EntityProfile:
    kind: EntityKind
    value: str
    query: str
    event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    log_sources: list[Counted] = field(default_factory=list)
    activity: list[tuple[datetime, int]] = field(default_factory=list)
    related: dict[str, list[Counted]] = field(default_factory=dict)
    alerts: list[Alert] = field(default_factory=list)
    alert_count: int = 0
    open_alert_count: int = 0
    cases: list[Case] = field(default_factory=list)
    intel: list[Ioc] = field(default_factory=list)


def normalise(kind: EntityKind, value: str) -> str:
    """The canonical value, as stored on events.

    Raises:
        EntityError: for an invalid address or an empty or oversized name.
    """
    text = value.strip()
    if kind is EntityKind.IP:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            msg = f"{value!r} is not an IP address"
            raise EntityError(msg) from exc
    if not text or len(text) > 255:
        msg = f"a {kind.value} name is 1-255 characters"
        raise EntityError(msg)
    return text


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def search_query(kind: EntityKind, value: str) -> str:
    """The event search query that finds this entity's events."""
    if kind is EntityKind.IP:
        return f"ip:{value}"
    field_name = "user.name" if kind is EntityKind.USER else "host.name"
    return f"{field_name}:{_quoted(value)}"


def _event_condition(kind: EntityKind, value: str) -> ColumnElement[bool]:
    if kind is EntityKind.IP:
        return or_(_EVENTS.c.source_ip == value, _EVENTS.c.destination_ip == value)
    if kind is EntityKind.USER:
        return _EVENTS.c.user_name == value
    return _EVENTS.c.host_name == value


def _alert_condition(kind: EntityKind, value: str) -> ColumnElement[bool]:
    if kind is EntityKind.IP:
        return Alert.source_ip == value
    if kind is EntityKind.USER:
        return Alert.user_name == value
    return func.lower(Alert.host_name) == value.lower()


# What else to show next to each kind of entity: (label, events column).
_RELATED: dict[EntityKind, tuple[tuple[str, str], ...]] = {
    EntityKind.IP: (("users", "user_name"), ("hosts", "host_name")),
    EntityKind.USER: (("ips", "source_ip"), ("hosts", "host_name")),
    EntityKind.HOST: (("users", "user_name"), ("ips", "source_ip")),
}


async def _top(
    session: AsyncSession, condition: ColumnElement[bool], column_name: str
) -> list[Counted]:
    column = _EVENTS.c[column_name]
    count = func.count().label("count")
    rows = await session.execute(
        select(column, count)
        .where(condition, column.is_not(None))
        .group_by(column)
        .order_by(desc(count), column)
        .limit(TOP_RELATED)
    )
    return [Counted(str(value), number) for value, number in rows]


async def _events_summary(session: AsyncSession, profile: EntityProfile) -> None:
    condition = _event_condition(profile.kind, profile.value)
    count, first, last = (
        await session.execute(
            select(
                func.count(), func.min(_EVENTS.c.timestamp), func.max(_EVENTS.c.timestamp)
            ).where(condition)
        )
    ).one()
    profile.event_count, profile.first_seen, profile.last_seen = count, first, last
    if not count:
        return
    profile.log_sources = await _top(session, condition, "log_source")
    day = func.date_trunc("day", _EVENTS.c.timestamp).label("day")
    days = await session.execute(
        select(day, func.count())
        .where(condition)
        .group_by(day)
        .order_by(desc(day))
        .limit(ACTIVITY_DAYS)
    )
    profile.activity = sorted((moment, number) for moment, number in days)
    for label, column_name in _RELATED[profile.kind]:
        profile.related[label] = await _top(session, condition, column_name)


async def _alerts_summary(session: AsyncSession, profile: EntityProfile) -> None:
    condition = _alert_condition(profile.kind, profile.value)
    total, open_ = (
        await session.execute(
            select(func.count(), func.count().filter(Alert.status.in_(OPEN_ALERT_STATUSES))).where(
                condition
            )
        )
    ).one()
    profile.alert_count, profile.open_alert_count = total, open_
    profile.alerts = list(
        await session.scalars(
            select(Alert).where(condition).order_by(Alert.last_seen.desc()).limit(MAX_ALERTS)
        )
    )
    case_ids = select(Alert.case_id).where(condition, Alert.case_id.is_not(None)).distinct()
    profile.cases = list(
        await session.scalars(
            select(Case).where(Case.id.in_(case_ids)).order_by(Case.updated_at.desc())
        )
    )


async def entity_profile(session: AsyncSession, kind: EntityKind, value: str) -> EntityProfile:
    """Everything known about one entity.

    Raises:
        EntityError: if the value is not valid for the kind.
    """
    canonical = normalise(kind, value)
    profile = EntityProfile(kind=kind, value=canonical, query=search_query(kind, canonical))
    await _events_summary(session, profile)
    await _alerts_summary(session, profile)
    if kind is EntityKind.IP:
        profile.intel = (await local_intel(session, [(IocType.IP, canonical)]))[
            IocType.IP, canonical
        ]
    return profile
