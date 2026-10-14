"""Job functions executed by the worker.

Every job receives arq's ``ctx`` dict as its first argument; the resources
put there by :func:`watchpost.worker.settings.startup` are read through
:func:`worker_context` so jobs get typed access to them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from arq.connections import ArqRedis
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import DetectionTrigger, IngestionJob, IngestStatus, Rule
from watchpost.detection.runner import create_run, execute_run
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.ingestion.watcher import scan_watch_folder
from watchpost.intel.alerts import enrich_alerts as enrich_alert_ids
from watchpost.intel.alerts import pending_alert_ids
from watchpost.intel.enrichment import Enricher
from watchpost.intel.matching import INTEL_RULE_ID, SweepResult, sweep_events
from watchpost.worker.queue import ArqJobQueue, JobQueue

logger = logging.getLogger(__name__)

CONTEXT_KEY = "watchpost"


@dataclass(slots=True)
class WorkerContext:
    """Resources shared by every job in a worker process."""

    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    enricher: Enricher | None = None
    http: httpx.AsyncClient | None = None


def worker_context(ctx: dict[str, Any]) -> WorkerContext:
    """Return the typed worker context stored in arq's ``ctx``."""
    value = ctx.get(CONTEXT_KEY)
    if not isinstance(value, WorkerContext):
        msg = "worker context missing; was the worker started with WorkerSettings?"
        raise RuntimeError(msg)
    return value


def enricher(ctx: dict[str, Any]) -> Enricher:
    """The worker's enrichment service."""
    service = worker_context(ctx).enricher
    if service is None:
        msg = "enrichment is not set up in this worker"
        raise RuntimeError(msg)
    return service


def job_queue(ctx: dict[str, Any]) -> JobQueue:
    """Queue for follow-up jobs, using the worker's own Redis connection."""
    redis = ctx.get("redis")
    if not isinstance(redis, ArqRedis):
        msg = "arq did not provide a Redis connection in the job context"
        raise RuntimeError(msg)
    return ArqJobQueue(redis)


async def ping(ctx: dict[str, Any]) -> str:
    """Round-trip check: proves the worker is consuming jobs and can reach the database."""
    wctx = worker_context(ctx)
    async with wctx.session_factory() as session:
        await session.execute(text("SELECT 1"))
    logger.info("Ping job %s completed", ctx.get("job_id"))
    return "pong"


async def ingest_file(ctx: dict[str, Any], job_id: int) -> str:
    """Parse and store the file behind ingestion job ``job_id``, then queue detection."""
    wctx = worker_context(ctx)
    status = await run_ingestion_job(wctx.session_factory, wctx.settings, job_id)
    if status is IngestStatus.COMPLETED:
        await queue_detection_for_job(wctx.session_factory, job_queue(ctx), job_id)
    return status.value if status is not None else "skipped"


async def queue_detection_for_job(
    session_factory: async_sessionmaker[AsyncSession], queue: JobQueue, job_id: int
) -> int | None:
    """Queue a detection run over the events a job inserted; ``None`` if it inserted none."""
    async with session_factory() as session:
        inserted = await session.scalar(
            select(IngestionJob.events_inserted).where(IngestionJob.id == job_id)
        )
        if not inserted:
            return None
        run = await create_run(session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job_id)
        run_id = run.id
        await session.commit()
    await queue.enqueue_detection(run_id)
    return run_id


async def run_detection(ctx: dict[str, Any], run_id: int) -> str:
    """Evaluate the rules for detection run ``run_id``, record alerts and queue enrichment."""
    outcome = await execute_run(worker_context(ctx).session_factory, run_id)
    if outcome is None:
        return "skipped"
    if outcome.changed_alert_ids:
        await job_queue(ctx).enqueue_enrichment(outcome.changed_alert_ids)
    return outcome.status.value


async def enrich_alerts(ctx: dict[str, Any], alert_ids: list[int]) -> int:
    """Attach indicator context to alerts. Returns how many were enriched."""
    summary = await enrich_alert_ids(enricher(ctx), alert_ids)
    return summary.enriched


async def enrich_pending(ctx: dict[str, Any]) -> int:
    """Cron job: retry alerts whose lookups were postponed by a rate limit."""
    service = enricher(ctx)
    async with service.session_factory() as session:
        alert_ids = await pending_alert_ids(session)
    if not alert_ids:
        return 0
    return (await enrich_alert_ids(service, alert_ids)).enriched


async def sweep_iocs(ctx: dict[str, Any], ioc_ids: list[int] | None = None) -> int:
    """Flag stored events that match indicators, then alert on the new matches.

    Returns how many events matched.
    """
    wctx = worker_context(ctx)
    result = await sweep_events(wctx.session_factory, ioc_ids=ioc_ids)
    await queue_detection_for_sweep(wctx.session_factory, job_queue(ctx), result)
    return result.events_matched


async def queue_detection_for_sweep(
    session_factory: async_sessionmaker[AsyncSession], queue: JobQueue, result: SweepResult
) -> int | None:
    """Run the indicator-match rule over the period with new matches, if it is enabled."""
    if result.first is None or result.last is None:
        return None
    async with session_factory() as session:
        enabled = await session.scalar(select(Rule.enabled).where(Rule.id == INTEL_RULE_ID))
        if not enabled:
            logger.info("Rule %s is disabled; not alerting on swept matches", INTEL_RULE_ID)
            return None
        run = await create_run(
            session,
            trigger=DetectionTrigger.INTEL,
            start=result.first,
            end=result.last,
            rule_ids=[INTEL_RULE_ID],
        )
        run_id = run.id
        await session.commit()
    await queue.enqueue_detection(run_id)
    return run_id


async def scan_watch_folder_job(ctx: dict[str, Any]) -> int:
    """Cron job: queue new files from the watched folder. Returns how many were queued."""
    wctx = worker_context(ctx)
    created = await scan_watch_folder(wctx.session_factory, wctx.settings, job_queue(ctx))
    return len(created)
