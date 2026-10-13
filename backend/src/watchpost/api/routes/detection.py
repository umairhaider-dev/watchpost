"""Starting and following detection runs."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator
from redis.exceptions import RedisError
from sqlalchemy import select

from watchpost.api.deps import QueueDep, SessionDep
from watchpost.db.models import DetectionRun, DetectionStatus, DetectionTrigger, Rule
from watchpost.detection.runner import create_run

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection", tags=["detection"])


class DetectionRunRequest(BaseModel):
    """Scan stored events again, e.g. after enabling or writing a rule."""

    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    rule_ids: list[str] | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def _ordered(self) -> DetectionRunRequest:
        if self.start and self.end and self.start > self.end:
            msg = "start must be before end"
            raise ValueError(msg)
        return self


class DetectionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    trigger: DetectionTrigger
    status: DetectionStatus
    ingest_job_id: int | None
    rule_ids: list[str] | None
    range_start: datetime | None
    range_end: datetime | None
    events_scanned: int
    hits: int
    alerts_created: int
    alerts_updated: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


@router.post("/runs", response_model=DetectionRunOut, status_code=status.HTTP_202_ACCEPTED)
async def start_run(
    body: DetectionRunRequest, session: SessionDep, queue: QueueDep
) -> DetectionRun:
    """Queue a detection run over a time range (all stored events if no range is given)."""
    if body.rule_ids is not None:
        known = set(await session.scalars(select(Rule.id).where(Rule.id.in_(body.rule_ids))))
        unknown = sorted(set(body.rule_ids) - known)
        if unknown:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"unknown rule(s): {', '.join(unknown)}"
            )
    run = await create_run(
        session,
        trigger=DetectionTrigger.MANUAL,
        start=body.start,
        end=body.end,
        rule_ids=body.rule_ids,
    )
    await session.commit()
    await session.refresh(run)
    try:
        await queue.enqueue_detection(run.id)
    except (RedisError, OSError) as exc:
        logger.error("Could not queue detection run %d: %s", run.id, exc)
        run.status = DetectionStatus.FAILED
        run.error = "the job queue is unavailable; please try again"
        run.finished_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "job queue unavailable; try again shortly"
        ) from exc
    return run


@router.get("/runs", response_model=list[DetectionRunOut])
async def list_runs(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[DetectionRun]:
    """Most recent detection runs first."""
    runs = await session.scalars(select(DetectionRun).order_by(DetectionRun.id.desc()).limit(limit))
    return list(runs)


@router.get("/runs/{run_id}", response_model=DetectionRunOut)
async def get_run(run_id: int, session: SessionDep) -> DetectionRun:
    run = await session.get(DetectionRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "detection run not found")
    return run
