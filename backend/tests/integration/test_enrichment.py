from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import FakeAsyncRedis, FakeServer
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fake_services import MIMIKATZ_SHA256, FakeServices, make_enricher, virustotal
from watchpost.core.config import Settings
from watchpost.db.models import EnrichmentCache, EnrichmentStatus, IocType
from watchpost.intel.enrichment import (
    ERROR_CACHE_TTL,
    Enricher,
    LookupStatus,
    ProviderResult,
    build_enricher,
    http_client,
)
from watchpost.intel.providers import Verdict

OTHER_SHA256 = "a" * 64


@pytest.fixture
def services() -> FakeServices:
    return FakeServices()


@pytest.fixture
async def enricher(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
) -> AsyncIterator[Enricher]:
    async with services.client() as client:
        yield make_enricher(session_factory, fake_redis, client)


async def cache_rows(session: AsyncSession) -> list[EnrichmentCache]:
    session.expire_all()
    return list(await session.scalars(select(EnrichmentCache).order_by(EnrichmentCache.id)))


async def test_lookup_asks_once_then_answers_from_the_cache(
    enricher: Enricher, services: FakeServices, db_session: AsyncSession
) -> None:
    services.vt_detections[MIMIKATZ_SHA256] = 52

    [first] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)
    [second] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)

    assert first.provider == "virustotal"
    assert first.status is LookupStatus.OK
    assert first.verdict is Verdict.MALICIOUS
    assert first.data["malicious"] == 52
    assert not first.cached
    assert second.cached
    assert second.data == first.data
    assert len(services.requests) == 1
    [row] = await cache_rows(db_session)
    assert (row.provider, row.indicator_type, row.indicator) == (
        "virustotal",
        IocType.SHA256,
        MIMIKATZ_SHA256,
    )
    assert row.expires_at - row.fetched_at == timedelta(hours=24)


async def test_refresh_and_expiry_ask_again_and_update_the_cache(
    enricher: Enricher, services: FakeServices, db_session: AsyncSession
) -> None:
    services.vt_detections[MIMIKATZ_SHA256] = 1
    await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)

    services.vt_detections[MIMIKATZ_SHA256] = 30
    [refreshed] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256, refresh=True)
    assert refreshed.verdict is Verdict.MALICIOUS

    await db_session.execute(
        update(EnrichmentCache).values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
    )
    [expired] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)
    assert not expired.cached

    assert len(services.requests) == 3
    assert len(await cache_rows(db_session)) == 1


async def test_internal_indicators_are_never_sent(
    enricher: Enricher, services: FakeServices
) -> None:
    for ioc_type, value in (
        (IocType.IP, "203.0.113.45"),
        (IocType.IP, "10.20.0.30"),
        (IocType.DOMAIN, "update-check.example.net"),
        (IocType.DOMAIN, "dc01.corp"),
    ):
        assert await enricher.lookup(ioc_type, value) == []

    assert services.requests == []


async def test_unknown_indicators_are_cached_as_not_found(
    enricher: Enricher, services: FakeServices, db_session: AsyncSession
) -> None:
    [result] = await enricher.lookup(IocType.SHA256, OTHER_SHA256)
    [again] = await enricher.lookup(IocType.SHA256, OTHER_SHA256)

    assert result.status is LookupStatus.NOT_FOUND
    assert result.verdict is Verdict.UNKNOWN
    assert again.cached
    assert len(services.requests) == 1
    [row] = await cache_rows(db_session)
    assert row.status is EnrichmentStatus.NOT_FOUND


async def test_errors_are_cached_only_briefly(
    enricher: Enricher, services: FakeServices, db_session: AsyncSession
) -> None:
    services.fail_with = 503

    [result] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)

    assert result.status is LookupStatus.ERROR
    assert result.data == {"error": "VirusTotal answered HTTP 503"}
    [row] = await cache_rows(db_session)
    assert row.expires_at - row.fetched_at == ERROR_CACHE_TTL


async def test_exhausted_budget_postpones_lookups(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
    db_session: AsyncSession,
) -> None:
    async with services.client() as client:
        enricher = make_enricher(session_factory, fake_redis, client, [virustotal(per_minute=1)])
        [first] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)
        [second] = await enricher.lookup(IocType.SHA256, OTHER_SHA256)

    assert first.status is LookupStatus.NOT_FOUND
    assert second.status is LookupStatus.RATE_LIMITED
    assert second.fetched_at is None
    assert len(services.requests) == 1
    assert [row.indicator for row in await cache_rows(db_session)] == [MIMIKATZ_SHA256]


async def test_rate_limit_reply_pauses_the_provider(
    enricher: Enricher, services: FakeServices, db_session: AsyncSession
) -> None:
    services.fail_with = 429
    services.fail_headers = {"Retry-After": "300"}

    [limited] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)
    services.fail_with = None
    [still_paused] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)

    assert limited.status is LookupStatus.RATE_LIMITED
    assert still_paused.status is LookupStatus.RATE_LIMITED
    assert len(services.requests) == 1
    assert await cache_rows(db_session) == []
    [status] = [s for s in await enricher.status() if s.name == "virustotal"]
    assert status.cooling_down


async def test_redis_outage_postpones_instead_of_failing(
    session_factory: async_sessionmaker[AsyncSession],
    services: FakeServices,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = FakeServer()
    server.connected = False
    redis = FakeAsyncRedis(server=server)
    async with services.client() as client:
        enricher = make_enricher(session_factory, redis, client)
        [result] = await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)
        statuses = await enricher.status()

    assert result.status is LookupStatus.RATE_LIMITED
    assert services.requests == []
    assert "Rate limit store unavailable" in caplog.text
    assert all(status.configured and status.remaining == {} for status in statuses)
    await redis.aclose()


async def test_provider_status_reports_budgets(enricher: Enricher, services: FakeServices) -> None:
    services.vt_detections[MIMIKATZ_SHA256] = 0
    await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256)

    statuses = {status.name: status for status in await enricher.status()}

    assert statuses["virustotal"].remaining == {"4/min": 3, "500/day": 499}
    assert statuses["abuseipdb"].remaining == {"1000/day": 1000}
    assert not statuses["virustotal"].cooling_down
    assert enricher.online


async def test_build_enricher_without_keys_is_offline(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
) -> None:
    async with http_client(settings) as client:
        enricher = build_enricher(settings, session_factory, fake_redis, client)
        statuses = await enricher.status()

        assert not enricher.online
        assert await enricher.lookup(IocType.SHA256, MIMIKATZ_SHA256) == []
    assert [(status.label, status.configured) for status in statuses] == [
        ("AbuseIPDB", False),
        ("VirusTotal", False),
    ]


def test_results_serialise_for_storage() -> None:
    fetched = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
    result = ProviderResult(
        "abuseipdb", LookupStatus.OK, Verdict.CLEAN, data={"score": 0}, fetched_at=fetched
    )

    assert result.as_dict() == {
        "provider": "abuseipdb",
        "label": "AbuseIPDB",
        "status": "ok",
        "verdict": "clean",
        "data": {"score": 0},
        "fetched_at": "2026-10-12T09:00:00+00:00",
        "cached": False,
    }
    postponed = ProviderResult("virustotal", LookupStatus.RATE_LIMITED).as_dict()
    assert postponed["fetched_at"] is None
    assert postponed["verdict"] == "unknown"
