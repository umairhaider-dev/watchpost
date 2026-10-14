"""The alert queue: filtering, triage (status and assignment) and enrichment."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import ColumnElement, case, func, select
from sqlalchemy.exc import IntegrityError

from watchpost import audit
from watchpost.accounts import AccountError, assignable_user
from watchpost.api.deps import ActorDep, EnricherDep, SessionDep
from watchpost.api.routes.events import EventOut
from watchpost.db.models import (
    Alert,
    AlertStatus,
    AuditLog,
    Event,
    Rule,
    Severity,
    User,
    alert_events,
)
from watchpost.intel.alerts import enrich_alert
from watchpost.investigation.timeline import DEFAULT_WINDOW, MAX_WINDOW, alert_timeline
from watchpost.investigation.triage import ReopenConflictError, assign, set_status

router = APIRouter(prefix="/alerts", tags=["alerts"])

MAX_EVIDENCE_SHOWN = 100
MAX_BULK_ALERTS = 500

_SEVERITY_RANK = case(
    {severity.value: severity.rank for severity in Severity}, value=Alert.severity, else_=0
)


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str | None
    title: str
    severity: Severity
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    event_count: int
    host_name: str | None
    source_ip: str | None
    user_name: str | None
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    case_id: int | None
    assignee_id: int | None
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int


class AlertRule(BaseModel):
    id: str
    title: str
    description: str
    false_positives: list[str]


class ActivityOut(BaseModel):
    """One audit entry about an alert or case."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    username: str | None
    action: str
    details: dict[str, Any]


class AlertDetail(AlertOut):
    enrichment: dict[str, Any]
    rule: AlertRule | None
    evidence: list[EventOut]
    activity: list[ActivityOut]


class AlertUpdate(BaseModel):
    """Fields to change; ``assignee_id: null`` unassigns."""

    status: AlertStatus | None = None
    assignee_id: int | None = None

    @model_validator(mode="after")
    def _something_to_change(self) -> AlertUpdate:
        if not self.model_fields_set & {"status", "assignee_id"}:
            msg = "give a status or an assignee_id"
            raise ValueError(msg)
        if "status" in self.model_fields_set and self.status is None:
            msg = "status cannot be null"
            raise ValueError(msg)
        return self


class BulkAlertUpdate(AlertUpdate):
    alert_ids: list[int] = Field(min_length=1, max_length=MAX_BULK_ALERTS)

    @field_validator("alert_ids")
    @classmethod
    def _unique(cls, value: list[int]) -> list[int]:
        return list(dict.fromkeys(value))


class TimelineEvent(EventOut):
    is_evidence: bool


class TimelineOut(BaseModel):
    start: datetime
    end: datetime
    window_minutes: int
    entities: dict[str, str]
    truncated: bool
    events: list[TimelineEvent]


class ConflictOut(BaseModel):
    alert_id: int
    open_alert_id: int


class BulkResult(BaseModel):
    updated: list[int]
    unchanged: list[int]
    missing: list[int]
    conflicts: list[ConflictOut]


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"not an IP address: {value!r}"
        ) from exc


@dataclass(frozen=True, slots=True)
class AlertFilters:
    """Alert queue filters; every one that is set must match."""

    statuses: list[AlertStatus] | None = None
    severities: list[Severity] | None = None
    rule_id: str | None = None
    host: str | None = None
    source_ip: str | None = None
    user: str | None = None
    technique: str | None = None
    assignee_id: int | None = None
    unassigned: bool = False
    case_id: int | None = None
    since: datetime | None = None
    until: datetime | None = None
    q: str | None = None

    def conditions(self) -> list[ColumnElement[bool]]:
        return [*self._what(), *self._who_and_when()]

    def _what(self) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []
        if self.statuses:
            conditions.append(Alert.status.in_(self.statuses))
        if self.severities:
            conditions.append(Alert.severity.in_(self.severities))
        if self.rule_id:
            conditions.append(Alert.rule_id == self.rule_id)
        if self.technique:
            conditions.append(Alert.mitre_techniques.contains([self.technique.strip().upper()]))
        if self.case_id is not None:
            conditions.append(Alert.case_id == self.case_id)
        if self.q and self.q.strip():
            conditions.append(Alert.title.icontains(self.q.strip(), autoescape=True))
        return conditions

    def _who_and_when(self) -> list[ColumnElement[bool]]:
        conditions: list[ColumnElement[bool]] = []
        if self.host:
            conditions.append(func.lower(Alert.host_name) == self.host.strip().lower())
        if self.source_ip:
            conditions.append(Alert.source_ip == _ip(self.source_ip))
        if self.user:
            conditions.append(Alert.user_name == self.user.strip())
        if self.assignee_id is not None:
            conditions.append(Alert.assignee_id == self.assignee_id)
        if self.unassigned:
            conditions.append(Alert.assignee_id.is_(None))
        # Alerts whose activity overlaps the period.
        if self.since is not None:
            conditions.append(Alert.last_seen >= self.since)
        if self.until is not None:
            conditions.append(Alert.first_seen <= self.until)
        return conditions


def alert_filters(
    alert_status: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    host: Annotated[str | None, Query(max_length=255, description="Host name")] = None,
    source_ip: Annotated[str | None, Query(max_length=64)] = None,
    user: Annotated[str | None, Query(max_length=255, description="User name")] = None,
    technique: Annotated[str | None, Query(max_length=16, description="e.g. T1110.001")] = None,
    assignee_id: Annotated[int | None, Query()] = None,
    unassigned: Annotated[bool, Query(description="Only alerts nobody owns")] = False,
    case_id: Annotated[int | None, Query()] = None,
    since: Annotated[datetime | None, Query(description="Activity at or after")] = None,
    until: Annotated[datetime | None, Query(description="Activity at or before")] = None,
    q: Annotated[str | None, Query(max_length=200, description="Part of the title")] = None,
) -> AlertFilters:
    return AlertFilters(
        statuses=alert_status,
        severities=severity,
        rule_id=rule_id,
        host=host,
        source_ip=source_ip,
        user=user,
        technique=technique,
        assignee_id=assignee_id,
        unassigned=unassigned,
        case_id=case_id,
        since=since,
        until=until,
        q=q,
    )


@router.get("", response_model=AlertPage)
async def list_alerts(
    session: SessionDep,
    filters: Annotated[AlertFilters, Depends(alert_filters)],
    sort: Annotated[Literal["last_seen", "first_seen", "severity"], Query()] = "last_seen",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Alerts matching every given filter, most recent activity (or most severe) first.

    ``since``/``until`` select alerts whose activity overlaps that period.
    """
    conditions = filters.conditions()
    order: Sequence[ColumnElement[Any]] = {
        "last_seen": [Alert.last_seen.desc()],
        "first_seen": [Alert.first_seen.desc()],
        "severity": [_SEVERITY_RANK.desc(), Alert.last_seen.desc()],
    }[sort]
    items = await session.scalars(
        select(Alert)
        .where(*conditions)
        .order_by(*order, Alert.id.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await session.scalar(select(func.count()).select_from(Alert).where(*conditions))
    return {"items": list(items), "total": total or 0}


async def _get_alert(session: SessionDep, alert_id: int) -> Alert:
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return alert


async def _assignee(session: SessionDep, assignee_id: int | None) -> User | None:
    if assignee_id is None:
        return None
    try:
        return await assignable_user(session, assignee_id)
    except AccountError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: int, session: SessionDep) -> dict[str, Any]:
    """One alert with its rule, the first evidence events (oldest first) and its history."""
    alert = await _get_alert(session, alert_id)
    rule = await session.get(Rule, alert.rule_id) if alert.rule_id else None
    evidence = await session.scalars(
        select(Event)
        .join(alert_events, alert_events.c.event_id == Event.id)
        .where(alert_events.c.alert_id == alert_id)
        .order_by(Event.timestamp, Event.id)
        .limit(MAX_EVIDENCE_SHOWN)
    )
    activity: list[AuditLog] = list(await audit.history(session, "alert", alert_id))
    return {
        **AlertOut.model_validate(alert).model_dump(),
        "enrichment": alert.enrichment,
        "rule": (
            {
                "id": rule.id,
                "title": rule.title,
                "description": rule.description,
                "false_positives": rule.false_positives,
            }
            if rule
            else None
        ),
        "evidence": list(evidence),
        "activity": activity,
    }


@router.patch(
    "/{alert_id}",
    response_model=AlertOut,
    responses={409: {"description": "Another open alert already tracks this activity"}},
)
async def update_alert(
    alert_id: int, body: AlertUpdate, session: SessionDep, actor: ActorDep
) -> Alert:
    """Change an alert's status or assignee."""
    alert = await _get_alert(session, alert_id)
    try:
        if "assignee_id" in body.model_fields_set:
            await assign(session, alert, await _assignee(session, body.assignee_id), actor=actor)
        if body.status is not None:
            await set_status(session, alert, body.status, actor=actor)
        await session.commit()
    except ReopenConflictError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except IntegrityError as exc:
        # Another request reopened an alert for the same activity first.
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "another open alert already tracks this activity"
        ) from exc
    await session.refresh(alert)
    return alert


@router.post("/bulk", response_model=BulkResult)
async def bulk_update(body: BulkAlertUpdate, session: SessionDep, actor: ActorDep) -> BulkResult:
    """Apply one status and/or assignee to many alerts.

    Alerts that cannot be reopened are reported in ``conflicts``; the rest are
    updated together.
    """
    assignee = (
        await _assignee(session, body.assignee_id)
        if "assignee_id" in body.model_fields_set
        else None
    )
    found = {
        alert.id: alert
        for alert in await session.scalars(select(Alert).where(Alert.id.in_(body.alert_ids)))
    }
    result = BulkResult(updated=[], unchanged=[], missing=[], conflicts=[])
    for alert_id in body.alert_ids:
        alert = found.get(alert_id)
        if alert is None:
            result.missing.append(alert_id)
            continue
        changed = False
        if "assignee_id" in body.model_fields_set:
            changed = await assign(session, alert, assignee, actor=actor) or changed
        if body.status is not None:
            try:
                changed = await set_status(session, alert, body.status, actor=actor) or changed
            except ReopenConflictError as exc:
                result.conflicts.append(
                    ConflictOut(alert_id=exc.alert_id, open_alert_id=exc.open_alert_id)
                )
                continue
        (result.updated if changed else result.unchanged).append(alert_id)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "these alerts include two open alerts for the same activity; reopen them one by one",
        ) from exc
    return result


@router.get("/{alert_id}/timeline", response_model=TimelineOut)
async def get_timeline(
    alert_id: int,
    session: SessionDep,
    window_minutes: Annotated[
        int,
        Query(
            ge=0,
            le=int(MAX_WINDOW.total_seconds() // 60),
            description="How far before and after the alert's activity to look",
        ),
    ] = int(DEFAULT_WINDOW.total_seconds() // 60),
) -> dict[str, Any]:
    """Events involving the alert's host, IP or user around the time it fired."""
    alert = await _get_alert(session, alert_id)
    timeline = await alert_timeline(session, alert, timedelta(minutes=window_minutes))
    return {
        "start": timeline.start,
        "end": timeline.end,
        "window_minutes": window_minutes,
        "entities": timeline.entities,
        "truncated": timeline.truncated,
        "events": [
            {
                **EventOut.model_validate(event).model_dump(),
                "is_evidence": event.id in timeline.evidence_ids,
            }
            for event in timeline.events
        ],
    }


@router.post("/{alert_id}/enrich", response_model=dict[str, Any])
async def enrich(
    alert_id: int,
    enricher: EnricherDep,
    refresh: Annotated[bool, Query(description="Ask providers even if cached")] = False,
) -> dict[str, Any]:
    """Rebuild an alert's indicator context now and return it."""
    enrichment = await enrich_alert(enricher, alert_id, refresh=refresh)
    if enrichment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return enrichment
