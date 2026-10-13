"""Shared pytest fixtures.

Unit tests run without any services. Integration tests (everything under
``tests/integration``) need PostgreSQL; point ``WATCHPOST_TEST_DATABASE_URL``
at a disposable database whose name contains ``test``, because the suite
drops and recreates its schema.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

# Configure the environment before any watchpost module reads settings.
TEST_DATABASE_URL = os.environ.get(
    "WATCHPOST_TEST_DATABASE_URL",
    "postgresql+asyncpg://watchpost:watchpost@localhost:5432/watchpost_test",
)
os.environ["WATCHPOST_ENV"] = "test"
os.environ["WATCHPOST_DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("WATCHPOST_SECRET_KEY", "test-only-secret-key-0123456789abcdef")

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import Connection, make_url, text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine  # noqa: E402

from watchpost.core.config import Settings, get_settings  # noqa: E402
from watchpost.db.session import create_engine  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parent.parent
INTEGRATION_DIR = Path(__file__).resolve().parent / "integration"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Tag everything under tests/integration so ``-m "not integration"`` works."""
    for item in items:
        if INTEGRATION_DIR in Path(item.path).parents:
            item.add_marker(pytest.mark.integration)


def alembic_config() -> Config:
    """Alembic config pointing at the project's migration scripts."""
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["configure_logger"] = False
    return config


def run_alembic(connection: Connection, action: str, revision: str) -> None:
    """Run an Alembic command on an existing connection (used via ``run_sync``)."""
    config = alembic_config()
    config.attributes["connection"] = connection
    getattr(command, action)(config, revision)


async def _ensure_database_exists(url: str) -> None:
    target = make_url(url)
    database = target.database or ""
    if "test" not in database:
        msg = f"refusing to run integration tests against non-test database {database!r}"
        raise RuntimeError(msg)
    admin = create_async_engine(
        target.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
    )
    try:
        async with admin.connect() as conn:
            exists = await conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": database}
            )
            if not exists:
                await conn.execute(text(f'CREATE DATABASE "{database}"'))
    finally:
        await admin.dispose()


@pytest.fixture(scope="session")
def settings() -> Settings:
    return get_settings()


@pytest.fixture(scope="session")
async def engine(settings: Settings) -> AsyncIterator[AsyncEngine]:
    """Engine bound to a freshly migrated test database."""
    await _ensure_database_exists(TEST_DATABASE_URL)
    engine = create_engine(settings)
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
        await conn.run_sync(run_alembic, "upgrade", "head")
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """A session whose work is rolled back after each test.

    Code under test may call ``commit()``; with ``create_savepoint`` that only
    releases a savepoint inside the outer transaction, which is discarded.
    """
    async with engine.connect() as conn:
        transaction = await conn.begin()
        session = AsyncSession(
            bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            await session.close()
            await transaction.rollback()
