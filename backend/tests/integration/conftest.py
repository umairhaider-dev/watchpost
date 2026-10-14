"""Fixtures for API-level integration tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import pytest
from fakeredis import FakeAsyncRedis
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.fake_services import FakeServices, make_enricher
from tests.integration.helpers import RULES_DIR
from watchpost.api.app import create_app
from watchpost.api.deps import AppResources, current_user, get_session
from watchpost.core.config import Settings
from watchpost.core.passwords import hash_password
from watchpost.db.models import User, UserRole
from watchpost.detection.store import sync_builtin_rules
from watchpost.intel.enrichment import Enricher


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
def services() -> FakeServices:
    """Offline AbuseIPDB and VirusTotal stand-ins that record every request."""
    return FakeServices()


@pytest.fixture
async def enricher(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
) -> AsyncIterator[Enricher]:
    """An enricher with no providers configured (the default, offline setup)."""
    async with services.client() as client:
        yield make_enricher(session_factory, fake_redis, client, providers=[])


# Hashed once for the whole run: Argon2 is deliberately slow.
TEST_PASSWORD = "correct-horse-battery"
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)


async def add_user(session: AsyncSession, username: str, role: UserRole) -> User:
    """A user with :data:`TEST_PASSWORD`, without paying for a fresh hash."""
    user = User(username=username, password_hash=TEST_PASSWORD_HASH, role=role)
    session.add(user)
    await session.flush()
    return user


@pytest.fixture
async def admin(db_session: AsyncSession) -> User:
    """The user the default ``client`` is signed in as.

    Committed (to a savepoint of the test transaction), so a route that rolls
    back its own work cannot take the signed-in user with it.
    """
    user = await add_user(db_session, "test.admin", UserRole.ADMIN)
    await db_session.commit()
    return user


@dataclass(frozen=True, slots=True)
class AppParts:
    """What every test application is wired to."""

    settings: Settings
    engine: AsyncEngine
    db_session: AsyncSession
    redis: FakeAsyncRedis
    queue: RecordingQueue
    session_factory: async_sessionmaker[AsyncSession]
    enricher: Enricher

    def build(self) -> FastAPI:
        """A fresh application on these resources; nobody is signed in.

        Request sessions share the test's transaction, so anything a test
        inserts is visible to the API and rolled back afterwards.
        """
        application = create_app(self.settings)
        application.state.resources = AppResources(
            engine=self.engine,
            session_factory=self.session_factory,
            redis=self.redis,
            queue=self.queue,
            enricher=self.enricher,
        )
        db_session = self.db_session

        async def _session_override() -> AsyncIterator[AsyncSession]:
            yield db_session

        application.dependency_overrides[get_session] = _session_override
        return application


@pytest.fixture
def app_parts(
    app_settings: Settings,
    engine: AsyncEngine,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
    queue: RecordingQueue,
    session_factory: async_sessionmaker[AsyncSession],
    enricher: Enricher,
) -> AppParts:
    return AppParts(app_settings, engine, db_session, fake_redis, queue, session_factory, enricher)


@pytest.fixture
def anonymous_app(app_parts: AppParts) -> FastAPI:
    """The real application with nobody signed in."""
    return app_parts.build()


@pytest.fixture
def app(app_parts: AppParts, admin: User) -> FastAPI:
    """A separate application instance with :func:`admin` signed in for every request.

    Sign-in itself, CSRF and roles are covered by the auth tests, which use
    ``anonymous_client``.
    """
    application = app_parts.build()
    admin_id = admin.id

    async def _signed_in(session: Annotated[AsyncSession, Depends(get_session)]) -> User:
        # Loaded through the request's session, as real sign-in does, so it is
        # fresh even after a test expires everything in the session.
        user = await session.get(User, admin_id)
        assert user is not None
        return user

    application.dependency_overrides[current_user] = _signed_in
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


@pytest.fixture
async def anonymous_client(anonymous_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=anonymous_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http
