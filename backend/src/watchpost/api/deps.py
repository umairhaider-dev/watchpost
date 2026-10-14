"""Shared FastAPI dependencies: resources, the signed-in user and access control.

Requests are authenticated by the session cookie set at sign-in, or by an
``Authorization: Bearer`` token for scripts. Every route except health and
sign-in requires a user; viewers may only read, analysts may also change
things, and a few routes (rule edits, user management, the audit log) are
for admins only. Cookie-authenticated requests that change state must
carry the session's CSRF token in the ``X-CSRF-Token`` header.
"""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Awaitable
from dataclasses import dataclass
from typing import Annotated, Any, Protocol

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.datastructures import State

from watchpost.audit import RequestContext, request_context
from watchpost.auth.throttle import LoginThrottle
from watchpost.auth.tokens import (
    CSRF_HEADER,
    SESSION_COOKIE,
    InvalidSessionError,
    read_session,
)
from watchpost.core.config import Settings
from watchpost.db.models import User, UserRole
from watchpost.intel.enrichment import Enricher
from watchpost.worker.queue import JobQueue

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Reads "Authorization: Bearer" and documents the token endpoint in OpenAPI.
bearer_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


class RedisPinger(Protocol):
    """The slice of the Redis client the health check relies on."""

    def ping(self) -> Awaitable[Any]: ...


@dataclass(slots=True)
class AppResources:
    """Long-lived resources created in the application lifespan."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
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


def get_login_throttle(
    resources: Annotated[AppResources, Depends(get_resources)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginThrottle:
    return LoginThrottle(
        resources.redis, settings.login_max_failures, settings.login_window_minutes * 60
    )


def client_address(request: Request) -> str | None:
    """The caller's address (the proxy passes it on; see ``FORWARDED_ALLOW_IPS``)."""
    return request.client.host if request.client else None


async def bind_request_context(request: Request) -> None:
    """Make the caller's address and user agent available to the audit log."""
    request_context.set(RequestContext(client_address(request), request.headers.get("user-agent")))


def _credentials(request: Request, bearer: str | None) -> tuple[str, bool] | None:
    """The session token and whether it came from the cookie (as opposed to a header)."""
    if bearer:
        return bearer, False
    cookie = request.cookies.get(SESSION_COOKIE)
    return (cookie, True) if cookie else None


async def current_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    bearer: Annotated[str | None, Depends(bearer_scheme)],
) -> User | None:
    """The signed-in user, or ``None`` for an anonymous or expired session.

    Raises:
        HTTPException: 403 when a cookie session changes state without the
            matching CSRF token.
    """
    credentials = _credentials(request, bearer)
    if credentials is None:
        return None
    token, from_cookie = credentials
    try:
        claims = read_session(token, settings)
    except InvalidSessionError:
        return None
    user = await session.get(User, claims.user_id)
    if user is None or not user.is_active or user.session_version != claims.session_version:
        return None
    if from_cookie and request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(sent.encode(), claims.csrf.encode()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    return user


async def require_user(user: Annotated[User | None, Depends(current_user)]) -> User:
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "sign in to continue",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def authorize(request: Request, user: Annotated[User, Depends(require_user)]) -> None:
    """Router-wide access rule: any user may read; changing data needs an analyst."""
    if request.method not in SAFE_METHODS and not user.role.allows(UserRole.ANALYST):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "viewers have read-only access")


async def require_admin(user: Annotated[User, Depends(require_user)]) -> User:
    if not user.role.allows(UserRole.ADMIN):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only admins can do this")
    return user


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
RedisDep = Annotated[RedisPinger, Depends(get_redis)]
QueueDep = Annotated[JobQueue, Depends(get_queue)]
EnricherDep = Annotated[Enricher, Depends(get_enricher)]
ThrottleDep = Annotated[LoginThrottle, Depends(get_login_throttle)]
ActorDep = Annotated[User | None, Depends(current_user)]
UserDep = Annotated[User, Depends(require_user)]
AdminDep = Annotated[User, Depends(require_admin)]
