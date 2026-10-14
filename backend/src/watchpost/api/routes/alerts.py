"""Reading and enriching alerts.

Triage (status changes, assignment, cases) arrives with case management.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import ColumnElement, func, select

from watchpost.api.deps import EnricherDep, SessionDep
from watchpost.api.routes.events import EventOut
from watchpost.db.models import Alert, AlertStatus, Event, Rule, Severity, alert_events
from watchpost.intel.alerts import enrich_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])

MAX_EVIDENCE_SHOWN = 100


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


class AlertDetail(AlertOut):
    enrichment: dict[str, Any]
    rule: AlertRule | None
    evidence: list[EventOut]


@router.get("", response_model=AlertPage)
async def list_alerts(
    session: SessionDep,
    alert_status: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Alerts, most recent activity first."""
    conditions: list[ColumnElement[bool]] = []
    if alert_status:
        conditions.append(Alert.status.in_(alert_status))
    if severity:
        conditions.append(Alert.severity.in_(severity))
    if rule_id:
        conditions.append(Alert.rule_id == rule_id)
    items = await session.scalars(
        select(Alert)
        .where(*conditions)
        .order_by(Alert.last_seen.desc(), Alert.id.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await session.scalar(select(func.count()).select_from(Alert).where(*conditions))
    return {"items": list(items), "total": total or 0}


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: int, session: SessionDep) -> dict[str, Any]:
    """One alert with its rule and the first evidence events, oldest first."""
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    rule = await session.get(Rule, alert.rule_id) if alert.rule_id else None
    evidence = await session.scalars(
        select(Event)
        .join(alert_events, alert_events.c.event_id == Event.id)
        .where(alert_events.c.alert_id == alert_id)
        .order_by(Event.timestamp, Event.id)
        .limit(MAX_EVIDENCE_SHOWN)
    )
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
