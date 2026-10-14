from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from arq.connections import ArqRedis
from fakeredis import FakeAsyncRedis
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.fake_services import FakeServices, make_enricher
from tests.integration.helpers import import_sample_feed, ingest_sample
from watchpost.core.config import Settings
from watchpost.db.models import (
    Alert,
    DetectionRun,
    DetectionTrigger,
    IngestionJob,
    IngestOrigin,
    IngestStatus,
    Rule,
)
from watchpost.intel.enrichment import Enricher
from watchpost.intel.matching import INTEL_RULE_ID, SweepResult
from watchpost.worker.queue import (
    DETECTION_JOB,
    ENRICH_ALERTS_JOB,
    INGEST_FILE_JOB,
    QUEUE_NAME,
    SWEEP_IOCS_JOB,
    ArqJobQueue,
)
from watchpost.worker.settings import WorkerSettings, build_cron_jobs, shutdown, startup
from watchpost.worker.tasks import (
    CONTEXT_KEY,
    WorkerContext,
    enrich_alerts,
    enrich_pending,
    enricher,
    ingest_file,
    job_queue,
    ping,
    queue_detection_for_job,
    queue_detection_for_sweep,
    requeue_stale_work,
    run_detection,
    scan_watch_folder_job,
    sweep_iocs,
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
    enrichment: Enricher | None = None,
) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        CONTEXT_KEY: WorkerContext(
            settings=settings,
            engine=engine,
            session_factory=session_factory,
            enricher=enrichment,
        )
    }
    if redis is not None:
        ctx["redis"] = redis
    return ctx


async def test_startup_ping_and_shutdown() -> None:
    redis = FakeAsyncRedis()
    ctx: dict[str, Any] = {"job_id": "test-job", "redis": redis}

    await startup(ctx)
    try:
        wctx = ctx[CONTEXT_KEY]
        assert isinstance(wctx, WorkerContext)
        assert enricher(ctx) is wctx.enricher
        assert await ping(ctx) == "pong"
    finally:
        await shutdown(ctx)
        await redis.aclose()
    assert wctx.http is not None and wctx.http.is_closed


async def test_startup_needs_arq_redis() -> None:
    with pytest.raises(RuntimeError, match="Redis connection"):
        await startup({})


def test_enrichment_jobs_need_the_enricher(
    settings: Settings,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    with pytest.raises(RuntimeError, match="enrichment is not set up"):
        enricher(make_ctx(settings, engine, session_factory))


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
    assert enrich_alerts in WorkerSettings.functions
    assert sweep_iocs in WorkerSettings.functions
    assert WorkerSettings.queue_name == QUEUE_NAME
    assert WorkerSettings.redis_settings.host


def test_cron_follows_settings(settings: Settings) -> None:
    every_fifteen = settings.model_copy(update={"watch_interval_seconds": 15})
    disabled = settings.model_copy(update={"watch_enabled": False})

    requeue, scan = build_cron_jobs(every_fifteen)

    assert requeue.coroutine is requeue_stale_work
    assert requeue.minute == set(range(0, 60, 5))
    assert scan.coroutine is scan_watch_folder_job
    assert scan.second == {0, 15, 30, 45}
    assert scan.run_at_startup
    assert [job.coroutine for job in build_cron_jobs(disabled)] == [requeue_stale_work]


def test_pending_enrichment_is_retried_only_with_providers(settings: Settings) -> None:
    online = settings.model_copy(
        update={"watch_enabled": False, "virustotal_api_key": SecretStr("v-key")}
    )

    _, job = build_cron_jobs(online)

    assert job.coroutine is enrich_pending
    assert job.minute == {0, 10, 20, 30, 40, 50}


@pytest.mark.usefixtures("rules")
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

    # New alerts are handed to the enrichment job.
    function, (alert_ids,), kwargs = redis.calls[-1]
    assert function == ENRICH_ALERTS_JOB
    assert kwargs == {"_queue_name": QUEUE_NAME}
    assert sorted(alert_ids) == list(await db_session.scalars(select(Alert.id).order_by(Alert.id)))
    assert len(alert_ids) > 0


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


async def test_enrichment_and_sweep_enqueue_through_arq() -> None:
    redis = FakeArqRedis()
    queue = ArqJobQueue(redis)

    await queue.enqueue_enrichment([])
    await queue.enqueue_enrichment((4, 5))
    await queue.enqueue_sweep(None)
    await queue.enqueue_sweep([9])

    assert redis.calls == [
        (ENRICH_ALERTS_JOB, ([4, 5],), {"_queue_name": QUEUE_NAME}),
        (SWEEP_IOCS_JOB, (None,), {"_queue_name": QUEUE_NAME}),
        (SWEEP_IOCS_JOB, ([9],), {"_queue_name": QUEUE_NAME}),
    ]


@pytest.mark.usefixtures("rules")
async def test_enrichment_jobs(
    db_session: AsyncSession,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    fake_redis: FakeAsyncRedis,
) -> None:
    await import_sample_feed(db_session)
    job_id = await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    redis = FakeArqRedis()
    async with FakeServices().client() as client:
        service = make_enricher(session_factory, fake_redis, client, providers=[])
        ctx = make_ctx(app_settings, engine, session_factory, redis, service)
        run_id = await queue_detection_for_job(session_factory, ArqJobQueue(redis), job_id)
        assert run_id is not None
        await run_detection(ctx, run_id)
        _, (alert_ids,), _ = redis.calls[-1]

        assert await enrich_alerts(ctx, alert_ids) == len(alert_ids)
        assert await enrich_pending(ctx) == 0

        # An alert left waiting on a rate limit is picked up by the cron job.
        await db_session.execute(
            update(Alert).where(Alert.id == alert_ids[0]).values(enrichment={"pending": True})
        )
        assert await enrich_pending(ctx) == 1

    db_session.expire_all()
    alerts = list(await db_session.scalars(select(Alert).where(Alert.id.in_(alert_ids))))
    assert all(alert.enrichment["pending"] is False for alert in alerts)
    assert any(alert.enrichment["verdict"] == "malicious" for alert in alerts)


@pytest.mark.usefixtures("rules")
async def test_sweep_job_alerts_on_events_stored_before_the_indicators(
    db_session: AsyncSession,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    ioc_ids = await import_sample_feed(db_session)
    redis = FakeArqRedis()
    ctx = make_ctx(app_settings, engine, session_factory, redis)

    assert await sweep_iocs(ctx, ioc_ids) > 0

    [(function, (run_id,), _)] = redis.calls
    assert function == DETECTION_JOB
    run = await db_session.get(DetectionRun, run_id)
    assert run is not None
    assert run.trigger is DetectionTrigger.INTEL
    assert run.rule_ids == [INTEL_RULE_ID]
    assert run.range_start is not None and run.range_end is not None
    assert await run_detection(ctx, run_id) == "completed"
    intel_alerts = await db_session.scalars(select(Alert).where(Alert.rule_id == INTEL_RULE_ID))
    assert [alert.source_ip for alert in intel_alerts] == ["203.0.113.45"]

    # A second sweep finds the same matches but nothing new to alert on.
    assert await sweep_iocs(ctx, ioc_ids) > 0
    assert [call[0] for call in redis.calls] == [DETECTION_JOB, ENRICH_ALERTS_JOB]


@pytest.mark.usefixtures("rules")
async def test_no_sweep_detection_when_the_rule_is_disabled(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    await db_session.execute(update(Rule).where(Rule.id == INTEL_RULE_ID).values(enabled=False))
    queue = ArqJobQueue(FakeArqRedis())
    now = datetime.now(UTC)
    matched = SweepResult(events_matched=1, new_links=1, first=now, last=now)

    assert await queue_detection_for_sweep(session_factory, queue, matched) is None
    assert await queue_detection_for_sweep(session_factory, queue, SweepResult()) is None


async def test_work_stuck_in_queued_is_queued_again(
    db_session: AsyncSession,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    long_ago = datetime.now(UTC) - timedelta(minutes=30)
    stuck_job = IngestionJob(
        origin=IngestOrigin.WATCH_FOLDER,
        filename="auth.log",
        stored_path="unused",
        parser="auto",
        file_size=1,
        created_at=long_ago,
    )
    fresh_job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename="new.log",
        stored_path="unused",
        parser="auto",
        file_size=1,
    )
    finished_job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename="old.log",
        stored_path="unused",
        parser="auto",
        file_size=1,
        status=IngestStatus.COMPLETED,
        created_at=long_ago,
    )
    stuck_run = DetectionRun(trigger=DetectionTrigger.INTEL, created_at=long_ago)
    db_session.add_all([stuck_job, fresh_job, finished_job, stuck_run])
    await db_session.flush()
    redis = FakeArqRedis()

    checked = await requeue_stale_work(make_ctx(app_settings, engine, session_factory, redis))

    assert checked == 2
    assert [(function, args) for function, args, _ in redis.calls] == [
        (INGEST_FILE_JOB, (stuck_job.id,)),
        (DETECTION_JOB, (stuck_run.id,)),
    ]


def test_job_queue_requires_arq_connection() -> None:
    with pytest.raises(RuntimeError, match="Redis connection"):
        job_queue({})
