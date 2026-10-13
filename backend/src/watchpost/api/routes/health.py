"""Liveness and readiness probes."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from watchpost import __version__
from watchpost.api.deps import RedisDep, SessionDep, SettingsDep

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

CHECK_TIMEOUT_SECONDS = 3.0


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    environment: str


class DependencyCheck(BaseModel):
    status: Literal["ok", "error"]
    latency_ms: float | None = None
    error: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, DependencyCheck]


@router.get("", response_model=HealthResponse)
async def liveness(settings: SettingsDep) -> HealthResponse:
    """Report that the process is up. Does not touch any dependency."""
    return HealthResponse(status="ok", version=__version__, environment=settings.env.value)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
async def readiness(session: SessionDep, redis: RedisDep, response: Response) -> ReadinessResponse:
    """Check that PostgreSQL and Redis are reachable."""

    async def check_database() -> None:
        await session.execute(text("SELECT 1"))

    async def check_redis() -> None:
        await redis.ping()

    checks = {
        "database": await _timed_check("database", check_database),
        "redis": await _timed_check("redis", check_redis),
    }
    healthy = all(check.status == "ok" for check in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="ok" if healthy else "degraded", checks=checks)


async def _timed_check(name: str, probe: Callable[[], Awaitable[None]]) -> DependencyCheck:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(probe(), timeout=CHECK_TIMEOUT_SECONDS)
    except TimeoutError:
        logger.warning("Readiness check for %s timed out", name)
        return DependencyCheck(status="error", error="timed out")
    except (SQLAlchemyError, RedisError, OSError) as exc:
        logger.warning("Readiness check for %s failed: %s", name, exc)
        return DependencyCheck(status="error", error=type(exc).__name__)
    latency = (time.perf_counter() - started) * 1000
    return DependencyCheck(status="ok", latency_ms=round(latency, 2))
