"""Entity pages: one IP address, user or host across events, alerts and cases."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from watchpost.api.deps import SessionDep
from watchpost.api.routes.alerts import AlertOut
from watchpost.api.routes.cases import CaseSummary
from watchpost.api.routes.intel import IocOut
from watchpost.investigation.entities import EntityError, EntityKind, entity_profile

router = APIRouter(prefix="/entities", tags=["investigation"])


class CountedOut(BaseModel):
    value: str
    count: int


class DayCount(BaseModel):
    day: datetime
    count: int


class EntityOut(BaseModel):
    kind: EntityKind
    value: str
    query: str
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    log_sources: list[CountedOut]
    activity: list[DayCount]
    related: dict[str, list[CountedOut]]
    alert_count: int
    open_alert_count: int
    alerts: list[AlertOut]
    cases: list[CaseSummary]
    intel: list[IocOut]


@router.get("/{kind}", response_model=EntityOut)
async def get_entity(
    kind: EntityKind,
    session: SessionDep,
    value: Annotated[str, Query(min_length=1, max_length=255)],
) -> dict[str, Any]:
    """What is known about an entity. ``query`` finds its events in the event search."""
    try:
        profile = await entity_profile(session, kind, value)
    except EntityError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return {
        "kind": profile.kind,
        "value": profile.value,
        "query": profile.query,
        "event_count": profile.event_count,
        "first_seen": profile.first_seen,
        "last_seen": profile.last_seen,
        "log_sources": profile.log_sources,
        "activity": [{"day": day, "count": count} for day, count in profile.activity],
        "related": profile.related,
        "alert_count": profile.alert_count,
        "open_alert_count": profile.open_alert_count,
        "alerts": profile.alerts,
        "cases": profile.cases,
        "intel": [IocOut.model_validate(ioc) for ioc in profile.intel],
    }
