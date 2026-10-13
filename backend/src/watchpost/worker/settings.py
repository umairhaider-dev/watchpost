"""arq worker configuration.

Start the worker with ``arq watchpost.worker.settings.WorkerSettings``.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from arq.connections import RedisSettings
from arq.cron import CronJob, cron
from arq.typing import StartupShutdown, WorkerCoroutine

from watchpost import __version__
from watchpost.core.config import Settings, get_settings, log_configuration_warnings
from watchpost.core.logging import configure_logging
from watchpost.db.session import create_engine, create_session_factory
from watchpost.worker.queue import QUEUE_NAME
from watchpost.worker.tasks import (
    CONTEXT_KEY,
    WorkerContext,
    ingest_file,
    ping,
    run_detection,
    scan_watch_folder_job,
    worker_context,
)

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    """Open the database engine once per worker process."""
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    log_configuration_warnings(settings)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings)
    ctx[CONTEXT_KEY] = WorkerContext(
        settings=settings,
        engine=engine,
        session_factory=create_session_factory(engine),
    )
    if settings.watch_enabled:
        logger.info("Watching %s every %d s", settings.watch_dir, settings.watch_interval_seconds)
    logger.info("Watchpost worker %s started (env=%s)", __version__, settings.env.value)


async def shutdown(ctx: dict[str, Any]) -> None:
    """Dispose of the database engine."""
    await worker_context(ctx).engine.dispose()
    logger.info("Watchpost worker stopped")


def build_cron_jobs(settings: Settings) -> list[CronJob]:
    """The periodic folder scan, if enabled."""
    if not settings.watch_enabled:
        return []
    seconds = set(range(0, 60, settings.watch_interval_seconds))
    return [
        cron(
            scan_watch_folder_job,
            second=seconds,
            run_at_startup=True,
            unique=True,
            timeout=300,
        )
    ]


class WorkerSettings:
    """Settings object read by the ``arq`` CLI."""

    functions: ClassVar[list[WorkerCoroutine]] = [ping, ingest_file, run_detection]
    cron_jobs: ClassVar[list[CronJob]] = build_cron_jobs(get_settings())
    on_startup: ClassVar[StartupShutdown] = startup
    on_shutdown: ClassVar[StartupShutdown] = shutdown
    redis_settings: ClassVar[RedisSettings] = RedisSettings.from_dsn(str(get_settings().redis_url))
    queue_name: ClassVar[str] = QUEUE_NAME
    max_jobs: ClassVar[int] = 4
    job_timeout: ClassVar[int] = 60 * 60
    health_check_interval: ClassVar[int] = 30
