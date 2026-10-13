from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from arq.connections import ArqRedis
from fastapi import FastAPI
from httpx import AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import make_url
from sqlalchemy.exc import OperationalError

from tests.conftest import TEST_DATABASE_URL
from watchpost import __version__
from watchpost.api.app import lifespan
from watchpost.api.deps import get_redis, get_session, resources_from_state
from watchpost.api.routes import health


class BrokenRedis:
    async def ping(self) -> bool:
        raise RedisConnectionError("connection refused")


class SlowRedis:
    async def ping(self) -> bool:
        await asyncio.sleep(1)
        return True


class BrokenSession:
    async def execute(self, *_: object) -> None:
        raise OperationalError("SELECT 1", {}, ConnectionRefusedError("db down"))


async def test_liveness(client: AsyncClient) -> None:
    response = await client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "environment": "test"}


async def test_readiness_reports_ok_when_dependencies_respond(client: AsyncClient) -> None:
    response = await client.get("/api/health/ready")

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "ok"
    assert body["checks"]["database"]["status"] == "ok"
    assert body["checks"]["redis"]["status"] == "ok"
    assert body["checks"]["database"]["latency_ms"] >= 0


async def test_readiness_fails_when_redis_is_down(app: FastAPI, client: AsyncClient) -> None:
    app.dependency_overrides[get_redis] = BrokenRedis

    response = await client.get("/api/health/ready")

    body = response.json()
    assert response.status_code == 503
    assert body["status"] == "degraded"
    assert body["checks"]["redis"] == {
        "status": "error",
        "latency_ms": None,
        "error": "ConnectionError",
    }
    assert body["checks"]["database"]["status"] == "ok"


async def test_readiness_fails_when_database_is_down(app: FastAPI, client: AsyncClient) -> None:
    async def broken_session() -> AsyncIterator[BrokenSession]:
        yield BrokenSession()

    app.dependency_overrides[get_session] = broken_session

    response = await client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["database"]["error"] == "OperationalError"


async def test_readiness_times_out_slow_dependencies(
    app: FastAPI, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(health, "CHECK_TIMEOUT_SECONDS", 0.05)
    app.dependency_overrides[get_redis] = SlowRedis

    response = await client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["redis"]["error"] == "timed out"


async def test_openapi_schema_is_served_under_api_prefix(client: AsyncClient) -> None:
    response = await client.get("/api/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "Watchpost"


async def test_cors_allows_configured_origin_only(client: AsyncClient) -> None:
    allowed = await client.options(
        "/api/health",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    denied = await client.options(
        "/api/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers


async def test_lifespan_creates_and_releases_resources(app: FastAPI) -> None:
    del app.state.resources
    with pytest.raises(TypeError, match="not initialised"):
        resources_from_state(app.state)

    async with lifespan(app):
        resources = resources_from_state(app.state)
        assert resources.engine.url.database == make_url(TEST_DATABASE_URL).database
        assert isinstance(resources.redis, ArqRedis)
