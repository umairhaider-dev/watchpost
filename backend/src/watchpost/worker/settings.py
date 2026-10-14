"""arq worker configuration.

Start the worker with ``arq watchpost.worker.settings.WorkerSettings``.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from arq.connections import RedisSettings
from arq.cron import CronJob, cron
from arq.typing import StartupShutdown, WorkerCoroutine
from redis.asyncio import Redis

from watchpost import __version__
from watchpost.core.config import Settings, get_settings, log_configuration_warnings
from watchpost.core.logging import configure_logging
from watchpost.db.session import create_engine, create_session_factory
from watchpost.intel.enrichment import build_enricher, http_client
from watchpost.intel.providers import configured_providers
from watchpost.worker.queue import QUEUE_NAME
from watchpost.worker.tasks import (
    CONTEXT_KEY,
    WorkerContext,
    enrich_alerts,
    enrich_pending,
    ingest_file,
    ping,
    requeue_stale_work,
    run_detection,
    scan_watch_folder_job,
    sweep_iocs,
    worker_context,
)

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Open the database engine and HTTP client once per worker process."""
    redis = ctx.get("redis")
    if not isinstance(redis, Redis):
        msg = "arq did not provide a Redis connection to the worker"
        raise RuntimeError(msg)
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    log_configuration_warnings(settings)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings)
    session_factory = create_session_factory(engine)
    http = http_client(settings)
    ctx[CONTEXT_KEY] = WorkerContext(
        settings=settings,
        engine=engine,
        session_factory=session_factory,
        enricher=build_enricher(settings, session_factory, redis, http),
        http=http,
    )
    if settings.watch_enabled:
        logger.info("Watching %s every %d s", settings.watch_dir, settings.watch_interval_seconds)
    logger.info("Watchpost worker %s started (env=%s)", __version__, settings.env.value)


async def shutdown(ctx: dict[str, Any]) -> None:
    """Close the HTTP client and dispose of the database engine."""
    wctx = worker_context(ctx)
    if wctx.http is not None:
        await wctx.http.aclose()
    await wctx.engine.dispose()
    logger.info("Watchpost worker stopped")


def build_cron_jobs(settings: Settings) -> list[CronJob]:
    """Periodic jobs: queue recovery always; folder scan and lookup retries when enabled."""
    jobs = [
        cron(requeue_stale_work, minute=set(range(0, 60, 5)), second=45, unique=True, timeout=120)
    ]
    if settings.watch_enabled:
        jobs.append(
            cron(
                scan_watch_folder_job,
                second=set(range(0, 60, settings.watch_interval_seconds)),
                run_at_startup=True,
                unique=True,
                timeout=300,
            )
        )
    if configured_providers(settings):
        jobs.append(
            cron(enrich_pending, minute=set(range(0, 60, 10)), second=30, unique=True, timeout=600)
        )
    return jobs


class WorkerSettings:
    """Settings object read by the ``arq`` CLI."""

    functions: ClassVar[list[WorkerCoroutine]] = [
        ping,
        ingest_file,
        run_detection,
        enrich_alerts,
        sweep_iocs,
    ]
    cron_jobs: ClassVar[list[CronJob]] = build_cron_jobs(get_settings())
    on_startup: ClassVar[StartupShutdown] = startup
    on_shutdown: ClassVar[StartupShutdown] = shutdown
    redis_settings: ClassVar[RedisSettings] = RedisSettings.from_dsn(str(get_settings().redis_url))
    queue_name: ClassVar[str] = QUEUE_NAME
    max_jobs: ClassVar[int] = 4
    job_timeout: ClassVar[int] = 60 * 60
    health_check_interval: ClassVar[int] = 30
