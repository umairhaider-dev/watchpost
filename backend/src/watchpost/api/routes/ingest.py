"""Log ingestion endpoints: uploads, job status and parser information."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, ConfigDict
from redis.exceptions import RedisError
from sqlalchemy import func, select

from watchpost.api.deps import QueueDep, SessionDep, SettingsDep
from watchpost.db.models import IngestionJob, IngestOrigin, IngestStatus
from watchpost.ingestion.errors import UnsupportedFileError, UploadTooLargeError
from watchpost.ingestion.parsers import AUTO, PARSERS, is_valid_parser_choice
from watchpost.ingestion.storage import display_filename, save_upload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingestion"])

UPLOAD_PATH = "/api/ingest/uploads"
HOST_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$"


class ParserInfo(BaseModel):
    name: str
    label: str
    description: str
    input_format: str


class IngestInfo(BaseModel):
    parsers: list[ParserInfo]
    max_upload_bytes: int
    watch_enabled: bool
    watch_interval_seconds: int


class MalformedSampleOut(BaseModel):
    line: int
    reason: str
    excerpt: str


class IngestionJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    origin: IngestOrigin
    status: IngestStatus
    filename: str
    parser: str
    detected_parser: str | None
    host_name: str | None
    file_size: int
    bytes_processed: int
    records_read: int
    events_inserted: int
    events_duplicate: int
    records_malformed: int
    records_skipped: int
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class IngestionJobDetail(IngestionJobOut):
    malformed_samples: list[MalformedSampleOut]


class IngestionJobPage(BaseModel):
    items: list[IngestionJobOut]
    total: int


@router.get("/info", response_model=IngestInfo)
async def ingest_info(settings: SettingsDep) -> IngestInfo:
    """Available parsers and ingestion limits, for the upload form."""
    return IngestInfo(
        parsers=[
            ParserInfo(
                name=parser.name,
                label=parser.label,
                description=parser.description,
                input_format=parser.input_format.value,
            )
            for parser in PARSERS.values()
        ],
        max_upload_bytes=settings.max_upload_bytes,
        watch_enabled=settings.watch_enabled,
        watch_interval_seconds=settings.watch_interval_seconds,
    )


@router.post(
    "/uploads",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestionJobOut,
    responses={
        413: {"description": "File larger than the upload limit"},
        415: {"description": "Not a text log file"},
        503: {"description": "Job queue unavailable"},
    },
)
async def upload_log_file(
    session: SessionDep,
    settings: SettingsDep,
    queue: QueueDep,
    file: Annotated[UploadFile, File(description="Log file (plain text, JSON or .gz)")],
    parser: Annotated[str, Form(description="Parser name, or 'auto' to detect")] = AUTO,
    host_name: Annotated[
        str | None,
        Form(
            pattern=HOST_NAME_PATTERN,
            description="Host to record for events that do not name one (e.g. web logs)",
        ),
    ] = None,
) -> IngestionJob:
    """Store an uploaded log file and queue it for ingestion."""
    if not is_valid_parser_choice(parser):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"unknown parser {parser!r}; expected 'auto' or one of: {', '.join(PARSERS)}",
        )
    try:
        stored = await save_upload(file, settings.upload_dir, settings.max_upload_bytes)
    except UnsupportedFileError as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc
    except UploadTooLargeError as exc:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc)) from exc
    finally:
        await file.close()

    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename=display_filename(file.filename),
        stored_path=str(stored.path.resolve()),
        parser=parser,
        host_name=host_name,
        file_size=stored.size,
        file_sha256=stored.sha256,
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    try:
        await queue.enqueue_ingestion(job.id)
    except (RedisError, OSError) as exc:
        logger.error("Could not queue ingestion job %d: %s", job.id, exc)
        job.status = IngestStatus.FAILED
        job.error = "the job queue is unavailable; please upload the file again"
        job.finished_at = datetime.now(UTC)
        await session.commit()
        stored.path.unlink(missing_ok=True)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "job queue unavailable; try again shortly"
        ) from exc
    logger.info("Queued upload %r as ingestion job %d", job.filename, job.id)
    return job


@router.get("/jobs", response_model=IngestionJobPage)
async def list_ingestion_jobs(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    job_status: Annotated[IngestStatus | None, Query(alias="status")] = None,
) -> dict[str, Any]:
    """Most recent ingestion jobs first."""
    query = select(IngestionJob)
    count = select(func.count()).select_from(IngestionJob)
    if job_status is not None:
        query = query.where(IngestionJob.status == job_status)
        count = count.where(IngestionJob.status == job_status)
    jobs = await session.scalars(
        query.order_by(IngestionJob.created_at.desc(), IngestionJob.id.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await session.scalar(count)
    return {"items": list(jobs), "total": total or 0}


@router.get("/jobs/{job_id}", response_model=IngestionJobDetail)
async def get_ingestion_job(job_id: int, session: SessionDep) -> IngestionJob:
    """One job, including the first malformed records it reported."""
    job = await session.get(IngestionJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ingestion job not found")
    return job
