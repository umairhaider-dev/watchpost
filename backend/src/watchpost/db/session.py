"""Async engine and session factory construction."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from watchpost.core.config import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Build the async engine used by both the API and the worker."""
    return create_async_engine(
        str(settings.database_url),
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_pool_size,
        pool_pre_ping=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return a session factory bound to ``engine``.

    ``expire_on_commit`` is disabled so objects stay readable after commit,
    which avoids surprise lazy loads (not allowed under asyncio) when building
    API responses.
    """
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
