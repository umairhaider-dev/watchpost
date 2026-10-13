"""Running an ingestion job from start to finish.

A job moves ``queued -> running -> completed | failed``. Progress counters
are written after every batch in the same transaction as the batch's events,
so the numbers shown in the UI always match what is in the database, even
if the worker dies half-way through a file.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import IngestionJob, IngestOrigin, IngestStatus
from watchpost.ingestion.errors import IngestionError
from watchpost.ingestion.parsers import AUTO, ParseContext, Parser, detect_parser, get_parser
from watchpost.ingestion.pipeline import ParseStats, insert_events, parse_events, take_rows
from watchpost.ingestion.readers import LogFile, read_sample

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _JobSnapshot:
    """The job fields the runner needs, detached from any session."""

    id: int
    origin: IngestOrigin
    stored_path: Path
    parser: str
    host_name: str | None
    created_at: datetime


async def run_ingestion_job(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    job_id: int,
) -> IngestStatus | None:
    """Process one queued job. Returns its final status, or ``None`` if skipped."""
    snapshot = await _claim(session_factory, job_id)
    if snapshot is None:
        return None
    try:
        await _ingest(session_factory, settings, snapshot)
    except (IngestionError, OSError) as exc:
        logger.warning("Ingestion job %d failed: %s", job_id, exc)
        await _mark_failed(session_factory, job_id, str(exc))
        return IngestStatus.FAILED
    except Exception:
        # Job boundary: record the failure on the job so the user sees it,
        # with the full traceback in the worker log.
        logger.exception("Ingestion job %d crashed", job_id)
        await _mark_failed(
            session_factory, job_id, "internal error while ingesting; see worker logs"
        )
        return IngestStatus.FAILED
    finally:
        _cleanup(snapshot, settings)
    return IngestStatus.COMPLETED


async def _claim(
    session_factory: async_sessionmaker[AsyncSession], job_id: int
) -> _JobSnapshot | None:
    """Mark a job as running, unless it is missing or already finished.

    A job left in ``running`` by a crashed worker is picked up again; the
    event hash makes the restart safe.
    """
    async with session_factory() as session:
        job = await session.get(IngestionJob, job_id, with_for_update=True)
        if job is None:
            logger.warning("Ingestion job %d does not exist", job_id)
            return None
        if job.status.is_finished:
            logger.info("Ingestion job %d already %s; skipping", job_id, job.status)
            return None
        job.status = IngestStatus.RUNNING
        job.started_at = datetime.now(UTC)
        snapshot = _JobSnapshot(
            id=job.id,
            origin=job.origin,
            stored_path=Path(job.stored_path),
            parser=job.parser,
            host_name=job.host_name,
            created_at=job.created_at,
        )
        await session.commit()
    return snapshot


async def _ingest(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    job: _JobSnapshot,
) -> None:
    parser_cls = await _resolve_parser(job)
    parser = parser_cls(
        ParseContext(reference_time=_reference_time(job), default_host=job.host_name)
    )
    logger.info("Ingesting job %d (%s) with parser %s", job.id, job.stored_path.name, parser.name)

    stats = ParseStats()
    inserted = duplicates = 0
    with LogFile.open(job.stored_path) as log_file:
        events = parse_events(log_file.stream, parser, stats)
        while True:
            rows = await asyncio.to_thread(take_rows, events, settings.ingest_batch_size, job.id)
            if not rows:
                break
            async with session_factory() as session:
                batch_inserted = await insert_events(session, rows)
                inserted += batch_inserted
                duplicates += len(rows) - batch_inserted
                await _save_progress(
                    session,
                    job.id,
                    stats=stats,
                    inserted=inserted,
                    duplicates=duplicates,
                    position=log_file.position(),
                )
                await session.commit()
        position = log_file.position()

    async with session_factory() as session:
        await _save_progress(
            session,
            job.id,
            stats=stats,
            inserted=inserted,
            duplicates=duplicates,
            position=position,
        )
        await session.execute(
            update(IngestionJob)
            .where(IngestionJob.id == job.id)
            .values(
                status=IngestStatus.COMPLETED,
                finished_at=datetime.now(UTC),
                malformed_samples=stats.samples_as_json(),
                detected_parser=parser.name,
            )
        )
        await session.commit()
    logger.info(
        "Ingestion job %d done: %d read, %d inserted, %d duplicate, %d malformed, %d skipped",
        job.id,
        stats.records_read,
        inserted,
        duplicates,
        stats.malformed,
        stats.skipped,
    )


async def _resolve_parser(job: _JobSnapshot) -> type[Parser]:
    if job.parser != AUTO:
        try:
            return get_parser(job.parser)
        except KeyError as exc:
            msg = f"unknown parser {job.parser!r}"
            raise IngestionError(msg) from exc
    sample = await asyncio.to_thread(read_sample, job.stored_path)
    return detect_parser(sample)


def _reference_time(job: _JobSnapshot) -> datetime:
    """Anchor for year-less timestamps: the file's mtime for watched files, else upload time."""
    if job.origin is IngestOrigin.WATCH_FOLDER:
        try:
            return datetime.fromtimestamp(job.stored_path.stat().st_mtime, tz=UTC)
        except OSError:
            logger.debug("Could not stat %s; using job creation time", job.stored_path)
    return job.created_at


async def _save_progress(
    session: AsyncSession,
    job_id: int,
    *,
    stats: ParseStats,
    inserted: int,
    duplicates: int,
    position: int,
) -> None:
    await session.execute(
        update(IngestionJob)
        .where(IngestionJob.id == job_id)
        .values(
            bytes_processed=position,
            records_read=stats.records_read,
            events_inserted=inserted,
            events_duplicate=duplicates,
            records_malformed=stats.malformed,
            records_skipped=stats.skipped,
        )
    )


async def _mark_failed(
    session_factory: async_sessionmaker[AsyncSession], job_id: int, error: str
) -> None:
    async with session_factory() as session:
        await session.execute(
            update(IngestionJob)
            .where(IngestionJob.id == job_id)
            .values(status=IngestStatus.FAILED, error=error[:2000], finished_at=datetime.now(UTC))
        )
        await session.commit()


def _cleanup(job: _JobSnapshot, settings: Settings) -> None:
    """Delete an uploaded file once processed; watched files are never touched."""
    if job.origin is not IngestOrigin.UPLOAD or settings.keep_uploads:
        return
    try:
        job.stored_path.unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not delete processed upload %s", job.stored_path, exc_info=True)
