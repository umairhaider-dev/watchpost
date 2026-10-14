"""Shared steps for integration tests that work with the sample files."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import DetectionTrigger, IngestionJob, IngestOrigin
from watchpost.detection.runner import RunOutcome, create_run, execute_run
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.intel.feeds import parse_feed
from watchpost.intel.store import upsert_iocs

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples"
RULES_DIR = ROOT / "backend" / "rules"


async def import_sample_feed(session: AsyncSession) -> list[int]:
    """Load ``samples/iocs.csv`` into the indicator store; returns the indicator IDs."""
    feed = parse_feed((SAMPLES / "iocs.csv").read_bytes(), "iocs.csv")
    result = await upsert_iocs(session, feed.entries, source="iocs.csv")
    return result.ioc_ids


async def ingest_sample(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    name: str,
) -> int:
    """Ingest one sample file through a real ingestion job; returns the job ID."""
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    path = settings.upload_dir / name
    shutil.copy(SAMPLES / name, path)
    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename=name,
        stored_path=str(path),
        parser="auto",
        file_size=path.stat().st_size,
    )
    db_session.add(job)
    await db_session.flush()
    await run_ingestion_job(session_factory, settings, job.id)
    return job.id


async def detect_job(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession], job_id: int
) -> RunOutcome:
    """Run detection over one ingestion job's events."""
    run = await create_run(db_session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job_id)
    outcome = await execute_run(session_factory, run.id)
    assert outcome is not None
    return outcome
