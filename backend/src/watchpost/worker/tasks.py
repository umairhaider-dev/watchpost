"""Job functions executed by the worker.

Every job receives arq's ``ctx`` dict as its first argument; the resources
put there by :func:`watchpost.worker.settings.startup` are read through
:func:`worker_context` so jobs get typed access to them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from arq.connections import ArqRedis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.ingestion.watcher import scan_watch_folder
from watchpost.worker.queue import ArqJobQueue, JobQueue

logger = logging.getLogger(__name__)

CONTEXT_KEY = "watchpost"


@dataclass(slots=True)
class WorkerContext:
    """Resources shared by every job in a worker process."""

    settings: Settings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]


def worker_context(ctx: dict[str, Any]) -> WorkerContext:
    """Return the typed worker context stored in arq's ``ctx``."""
    value = ctx.get(CONTEXT_KEY)
    if not isinstance(value, WorkerContext):
        msg = "worker context missing; was the worker started with WorkerSettings?"
        raise RuntimeError(msg)
    return value


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
    """Parse and store the file behind ingestion job ``job_id``."""
    wctx = worker_context(ctx)
    status = await run_ingestion_job(wctx.session_factory, wctx.settings, job_id)
    return status.value if status is not None else "skipped"


async def scan_watch_folder_job(ctx: dict[str, Any]) -> int:
    """Cron job: queue new files from the watched folder. Returns how many were queued."""
    wctx = worker_context(ctx)
    created = await scan_watch_folder(wctx.session_factory, wctx.settings, job_queue(ctx))
    return len(created)
