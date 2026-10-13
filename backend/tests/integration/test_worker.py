from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from arq.connections import ArqRedis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import DetectionRun, DetectionTrigger, IngestionJob, IngestOrigin
from watchpost.worker.queue import DETECTION_JOB, INGEST_FILE_JOB, QUEUE_NAME, ArqJobQueue
from watchpost.worker.settings import WorkerSettings, build_cron_jobs, shutdown, startup
from watchpost.worker.tasks import (
    CONTEXT_KEY,
    WorkerContext,
    ingest_file,
    job_queue,
    ping,
    queue_detection_for_job,
    run_detection,
    scan_watch_folder_job,
    worker_context,
)

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


class FakeArqRedis(ArqRedis):
    """An ArqRedis that records enqueue calls instead of talking to Redis."""

    def __init__(self, *, already_queued: bool = False) -> None:
        super().__init__()
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.already_queued = already_queued

    async def enqueue_job(self, function: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((function, args, kwargs))
        return None if self.already_queued else object()


def make_ctx(
    settings: Settings,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    redis: ArqRedis | None = None,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        CONTEXT_KEY: WorkerContext(
            settings=settings, engine=engine, session_factory=session_factory
        )
    }
    if redis is not None:
        ctx["redis"] = redis
    return ctx


async def test_startup_ping_and_shutdown() -> None:
    ctx: dict[str, Any] = {"job_id": "test-job"}

    await startup(ctx)
    try:
        assert isinstance(ctx[CONTEXT_KEY], WorkerContext)
        assert await ping(ctx) == "pong"
    finally:
        await shutdown(ctx)


async def test_job_without_startup_context_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match="worker context missing"):
        await ping({})


def test_worker_context_rejects_wrong_type() -> None:
    with pytest.raises(RuntimeError):
        worker_context({CONTEXT_KEY: object()})


def test_worker_settings_register_jobs() -> None:
    assert ping in WorkerSettings.functions
    assert ingest_file in WorkerSettings.functions
    assert run_detection in WorkerSettings.functions
    assert WorkerSettings.queue_name == QUEUE_NAME
    assert WorkerSettings.redis_settings.host


def test_cron_follows_settings(settings: Settings) -> None:
    every_fifteen = settings.model_copy(update={"watch_interval_seconds": 15})
    disabled = settings.model_copy(update={"watch_enabled": False})

    [job] = build_cron_jobs(every_fifteen)

    assert job.second == {0, 15, 30, 45}
    assert job.run_at_startup
    assert build_cron_jobs(disabled) == []


async def test_ingest_file_task(
    db_session: AsyncSession,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    app_settings.upload_dir.mkdir(parents=True)
    path = app_settings.upload_dir / "auth.log"
    shutil.copy(SAMPLES / "auth.log", path)
    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename="auth.log",
        stored_path=str(path),
        parser="auto",
        file_size=path.stat().st_size,
    )
    db_session.add(job)
    await db_session.flush()
    redis = FakeArqRedis()
    ctx = make_ctx(app_settings, engine, session_factory, redis)

    assert await ingest_file(ctx, job.id) == "completed"
    assert await ingest_file(ctx, job.id) == "skipped"

    # A completed ingestion queues a detection run over the new events.
    [(function, (run_id,), kwargs)] = redis.calls
    assert function == DETECTION_JOB
    assert kwargs["_job_id"] == f"detect:{run_id}"
    run = await db_session.get(DetectionRun, run_id)
    assert run is not None
    assert run.ingest_job_id == job.id
    assert run.trigger is DetectionTrigger.INGESTION

    assert await run_detection(ctx, run_id) == "completed"
    assert await run_detection(ctx, run_id) == "skipped"


async def test_no_detection_is_queued_when_nothing_new_was_stored(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename="dupes.log",
        stored_path="unused",
        parser="auto",
        file_size=1,
        events_inserted=0,
    )
    db_session.add(job)
    await db_session.flush()
    queue = ArqJobQueue(FakeArqRedis())

    assert await queue_detection_for_job(session_factory, queue, job.id) is None


async def test_enqueue_detection_is_idempotent() -> None:
    await ArqJobQueue(FakeArqRedis(already_queued=True)).enqueue_detection(3)


async def test_scan_job_enqueues_through_arq(
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    app_settings.watch_dir.mkdir(parents=True)
    shutil.copy(SAMPLES / "auth.log", app_settings.watch_dir / "auth.log")
    # Back-date the file so it counts as settled without waiting.
    target = app_settings.watch_dir / "auth.log"
    stat = target.stat()
    os.utime(target, (stat.st_atime - 120, stat.st_mtime - 120))
    redis = FakeArqRedis()

    queued = await scan_watch_folder_job(make_ctx(app_settings, engine, session_factory, redis))

    assert queued == 1
    [(function, args, kwargs)] = redis.calls
    assert function == INGEST_FILE_JOB
    assert kwargs == {"_job_id": f"ingest:{args[0]}", "_queue_name": QUEUE_NAME}


async def test_enqueue_is_idempotent() -> None:
    queue = ArqJobQueue(FakeArqRedis(already_queued=True))

    await queue.enqueue_ingestion(7)  # logs and returns instead of failing


def test_job_queue_requires_arq_connection() -> None:
    with pytest.raises(RuntimeError, match="Redis connection"):
        job_queue({})
