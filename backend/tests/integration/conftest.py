"""Fixtures for API-level integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from pathlib import Path

import pytest
from fakeredis import FakeAsyncRedis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.integration.helpers import RULES_DIR
from watchpost.api.app import create_app
from watchpost.api.deps import AppResources, get_session
from watchpost.core.config import Settings
from watchpost.detection.store import sync_builtin_rules


class RecordingQueue:
    """JobQueue stand-in that remembers what was enqueued."""

    def __init__(self) -> None:
        self.job_ids: list[int] = []
        self.detection_runs: list[int] = []
        self.enrichments: list[list[int]] = []
        self.sweeps: list[list[int] | None] = []
        self.fail = False

    async def enqueue_ingestion(self, job_id: int) -> None:
        if self.fail:
            msg = "redis is down"
            raise RedisConnectionError(msg)
        self.job_ids.append(job_id)

    async def enqueue_detection(self, run_id: int) -> None:
        if self.fail:
            msg = "redis is down"
            raise RedisConnectionError(msg)
        self.detection_runs.append(run_id)

    async def enqueue_enrichment(self, alert_ids: Sequence[int]) -> None:
        if self.fail:
            msg = "redis is down"
            raise RedisConnectionError(msg)
        self.enrichments.append(list(alert_ids))

    async def enqueue_sweep(self, ioc_ids: Sequence[int] | None) -> None:
        if self.fail:
            msg = "redis is down"
            raise RedisConnectionError(msg)
        self.sweeps.append(list(ioc_ids) if ioc_ids is not None else None)


@pytest.fixture
def app_settings(settings: Settings, tmp_path: Path) -> Settings:
    """Settings with upload and watch folders inside the test's temp dir."""
    return settings.model_copy(
        update={
            "upload_dir": tmp_path / "uploads",
            "watch_dir": tmp_path / "watch",
            "watch_settle_seconds": 0,
            "ingest_batch_size": 100,
        }
    )


@pytest.fixture
def session_factory(db_session: AsyncSession) -> async_sessionmaker[AsyncSession]:
    """A factory whose sessions all join the test's transaction.

    Code under test opens and commits its own sessions; binding them to the
    test connection with savepoints keeps everything rolled back afterwards.
    """
    return async_sessionmaker(
        bind=db_session.bind,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


@pytest.fixture
async def rules(db_session: AsyncSession) -> None:
    """The built-in rules, loaded into the database."""
    await sync_builtin_rules(db_session, RULES_DIR)


@pytest.fixture
def queue() -> RecordingQueue:
    return RecordingQueue()


@pytest.fixture
async def fake_redis() -> AsyncIterator[FakeAsyncRedis]:
    redis = FakeAsyncRedis()
    yield redis
    await redis.aclose()


@pytest.fixture
def app(
    app_settings: Settings,
    engine: AsyncEngine,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
    queue: RecordingQueue,
    session_factory: async_sessionmaker[AsyncSession],
) -> FastAPI:
    """The real application wired to the test database, an in-memory Redis and a fake queue.

    Request sessions share the test's transaction, so anything a test inserts
    is visible to the API and rolled back afterwards.
    """
    application = create_app(app_settings)
    application.state.resources = AppResources(
        engine=engine,
        session_factory=session_factory,
        redis=fake_redis,
        queue=queue,
    )

    async def _session_override() -> AsyncIterator[AsyncSession]:
        yield db_session

    application.dependency_overrides[get_session] = _session_override
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http
