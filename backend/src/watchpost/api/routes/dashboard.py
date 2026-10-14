"""The overview dashboard."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from watchpost.api.deps import SessionDep
from watchpost.dashboard import DashboardRange, build_dashboard
from watchpost.db.models import Severity

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class Totals(BaseModel):
    alerts: int
    open_alerts: int
    new_alerts: int
    unassigned_open_alerts: int
    open_cases: int
    events: int


class SeverityBucket(BaseModel):
    bucket: datetime
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class SeverityCount(BaseModel):
    severity: Severity
    count: int
    open: int


class RankedOut(BaseModel):
    value: str
    alerts: int
    events: int
    known_bad: bool


class RuleCountOut(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    alerts: int


class IngestionBucket(BaseModel):
    bucket: datetime
    events: int
    jobs: int


class IngestionOut(BaseModel):
    series: list[IngestionBucket]
    events_ingested: int
    jobs: int
    events_per_second: float | None


class ResolutionOut(BaseModel):
    resolved: int
    mean_seconds: float | None
    median_seconds: float | None


class DashboardOut(BaseModel):
    range: DashboardRange
    start: datetime | None
    end: datetime
    bucket_seconds: int
    totals: Totals
    alerts_over_time: list[SeverityBucket]
    alerts_by_severity: list[SeverityCount]
    top_source_ips: list[RankedOut]
    top_users: list[RankedOut]
    top_rules: list[RuleCountOut]
    ingestion: IngestionOut
    case_resolution: ResolutionOut
    alert_resolution: ResolutionOut


@router.get("", response_model=DashboardOut)
async def dashboard(
    session: SessionDep,
    period: Annotated[DashboardRange, Query(alias="range")] = DashboardRange.WEEK,
) -> dict[str, Any]:
    """Alert, ingestion and resolution figures for the overview page."""
    return asdict(await build_dashboard(session, period))
