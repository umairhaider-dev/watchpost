from __future__ import annotations

from collections.abc import AsyncIterator

from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from watchpost.api.middleware import RequestSizeLimitMiddleware


async def echo_size(request: Request) -> PlainTextResponse:
    body = await request.body()
    return PlainTextResponse(str(len(body)))


def make_client() -> AsyncClient:
    # Mounted like FastAPI's add_middleware does: inside the error middleware.
    app = Starlette(
        routes=[
            Route("/upload", echo_size, methods=["POST"]),
            Route("/other", echo_size, methods=["POST"]),
        ],
        middleware=[
            Middleware(
                RequestSizeLimitMiddleware,
                default_max_bytes=10,
                path_limits=[("/upload", 100)],
            )
        ],
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_bodies_within_the_limit_pass() -> None:
    async with make_client() as client:
        assert (await client.post("/upload", content=b"x" * 100)).text == "100"
        assert (await client.post("/other", content=b"x" * 10)).text == "10"


async def test_declared_length_over_the_limit_is_rejected() -> None:
    async with make_client() as client:
        response = await client.post("/other", content=b"x" * 11)

    assert response.status_code == 413
    assert "limit" in response.json()["detail"]


async def test_streamed_body_over_the_limit_is_cut_off() -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(5):
            yield b"x" * 30

    async with make_client() as client:
        response = await client.post("/upload", content=chunks())

    assert response.status_code == 413


def test_limit_for_path() -> None:
    middleware = RequestSizeLimitMiddleware(
        echo_size,  # type: ignore[arg-type]
        default_max_bytes=1,
        path_limits=[("/api/ingest/uploads", 5)],
    )

    assert middleware.limit_for("/api/ingest/uploads") == 5
    assert middleware.limit_for("/api/health") == 1
