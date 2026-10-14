"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable
from dataclasses import dataclass
from typing import Annotated, Any, Protocol

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.datastructures import State

from watchpost.core.config import Settings
from watchpost.db.models import User
from watchpost.intel.enrichment import Enricher
from watchpost.worker.queue import JobQueue


class RedisPinger(Protocol):
    """The slice of the Redis client the API relies on directly."""

    def ping(self) -> Awaitable[Any]: ...


@dataclass(slots=True)
class AppResources:
    """Long-lived resources created in the application lifespan."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: RedisPinger
    queue: JobQueue
    enricher: Enricher


def get_settings(request: Request) -> Settings:
    """Settings the app was created with (overridable in tests)."""
    settings = request.app.state.settings
    if not isinstance(settings, Settings):  # pragma: no cover - wiring error
        msg = "application settings are not initialised"
        raise TypeError(msg)
    return settings


def resources_from_state(state: State) -> AppResources:
    """Return the resources stored on ``app.state`` by the lifespan handler."""
    resources = getattr(state, "resources", None)
    if not isinstance(resources, AppResources):
        msg = "application resources are not initialised; is the lifespan running?"
        raise TypeError(msg)
    return resources


def get_resources(request: Request) -> AppResources:
    """Resources set up by the lifespan handler."""
    return resources_from_state(request.app.state)


async def get_session(
    resources: Annotated[AppResources, Depends(get_resources)],
) -> AsyncIterator[AsyncSession]:
    """Yield a database session scoped to one request."""
    async with resources.session_factory() as session:
        yield session


def get_redis(resources: Annotated[AppResources, Depends(get_resources)]) -> RedisPinger:
    """Redis client shared by the app."""
    return resources.redis


def get_queue(resources: Annotated[AppResources, Depends(get_resources)]) -> JobQueue:
    """Queue for background jobs."""
    return resources.queue


def get_enricher(resources: Annotated[AppResources, Depends(get_resources)]) -> Enricher:
    """Indicator lookups shared by the app."""
    return resources.enricher


async def current_user() -> User | None:
    """The user making the request.

    There is no sign-in yet, so every request is anonymous and actions are
    recorded without a user.
    """
    return None


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[RedisPinger, Depends(get_redis)]
QueueDep = Annotated[JobQueue, Depends(get_queue)]
EnricherDep = Annotated[Enricher, Depends(get_enricher)]
ActorDep = Annotated[User | None, Depends(current_user)]
