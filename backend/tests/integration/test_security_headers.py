from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from watchpost.api.app import create_app
from watchpost.api.middleware import HSTS
from watchpost.core.config import Environment, Settings


async def test_security_headers_on_every_response(anonymous_client: AsyncClient) -> None:
    for path in ("/api/health", "/api/alerts", "/api/no-such-route"):
        response = await anonymous_client.get(path)
        headers = response.headers
        assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["cache-control"] == "no-store"
        assert "strict-transport-security" not in headers  # not production

    docs = await anonymous_client.get("/api/docs")
    assert "cdn.jsdelivr.net" in docs.headers["content-security-policy"]


async def test_cors_allows_only_configured_origins(
    anonymous_client: AsyncClient, app_settings: Settings
) -> None:
    allowed = app_settings.cors_origins[0]
    preflight = await anonymous_client.options(
        "/api/alerts/1",
        headers={
            "Origin": allowed,
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )
    assert preflight.headers["access-control-allow-origin"] == allowed
    assert preflight.headers["access-control-allow-credentials"] == "true"
    assert "x-csrf-token" in preflight.headers["access-control-allow-headers"].lower()

    foreign = await anonymous_client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in foreign.headers


async def test_production_sends_hsts(app_settings: Settings) -> None:
    production = create_app(app_settings.model_copy(update={"env": Environment.PRODUCTION}))
    transport = ASGITransport(app=production)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        response = await http.get("/api/health")

    assert response.headers["strict-transport-security"] == HSTS
