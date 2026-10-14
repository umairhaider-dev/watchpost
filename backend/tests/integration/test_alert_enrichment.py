from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fake_services import MIMIKATZ_SHA256, FakeServices, make_enricher, virustotal
from tests.integration.helpers import detect_job, import_sample_feed, ingest_sample
from watchpost.core.config import Settings
from watchpost.db.models import Alert, Ioc, IocType, alert_events, event_ioc_matches
from watchpost.intel.alerts import (
    MAX_INDICATORS_PER_ALERT,
    Key,
    enrich_alert,
    enrich_alerts,
    intel_verdict,
    local_intel,
    pending_alert_ids,
    prioritised,
)
from watchpost.intel.enrichment import Enricher
from watchpost.intel.matching import INTEL_RULE_ID
from watchpost.intel.providers import Verdict
from watchpost.intel.ratelimit import RateLimiter

pytestmark = pytest.mark.usefixtures("rules")

# The same process creation event also reports the file's MD5.
MIMIKATZ_MD5 = "0b5e0c3d9a8f7e6d5c4b3a2918172635"
VT_FILES = "https://www.virustotal.com/api/v3/files"


@pytest.fixture
async def offline(
    session_factory: async_sessionmaker[AsyncSession], fake_redis: FakeAsyncRedis
) -> AsyncIterator[Enricher]:
    async with FakeServices().client() as client:
        yield make_enricher(session_factory, fake_redis, client, providers=[])


@pytest.fixture
async def online(
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
) -> AsyncIterator[Enricher]:
    async with services.client() as client:
        yield make_enricher(session_factory, fake_redis, client)


async def brute_force_alert(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> int:
    await import_sample_feed(db_session)
    await detect_job(
        db_session,
        session_factory,
        await ingest_sample(db_session, session_factory, settings, "auth.log"),
    )
    alert_id = await db_session.scalar(
        select(Alert.id).where(
            Alert.rule_id == "ssh-brute-force", Alert.source_ip == "203.0.113.45"
        )
    )
    assert alert_id is not None
    return alert_id


async def hash_alert(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> int:
    """The indicator-match alert whose evidence contains the known-bad file hash."""
    await import_sample_feed(db_session)
    await detect_job(
        db_session,
        session_factory,
        await ingest_sample(db_session, session_factory, settings, "sysmon.json"),
    )
    alert_id = await db_session.scalar(
        select(Alert.id)
        .join(alert_events, alert_events.c.alert_id == Alert.id)
        .join(event_ioc_matches, event_ioc_matches.c.event_id == alert_events.c.event_id)
        .join(Ioc, Ioc.id == event_ioc_matches.c.ioc_id)
        .where(Alert.rule_id == INTEL_RULE_ID, Ioc.value == MIMIKATZ_SHA256)
    )
    assert alert_id is not None
    return alert_id


async def stored_enrichment(session: AsyncSession, alert_id: int) -> dict[str, object]:
    session.expire_all()
    alert = await session.get(Alert, alert_id)
    assert alert is not None
    return alert.enrichment


async def test_offline_enrichment_uses_the_local_indicator_store(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    offline: Enricher,
) -> None:
    alert_id = await brute_force_alert(db_session, session_factory, app_settings)

    enrichment = await enrich_alert(offline, alert_id)

    assert enrichment is not None
    assert enrichment["verdict"] == "malicious"
    assert enrichment["pending"] is False
    assert enrichment["online"] is False
    [indicator] = enrichment["indicators"]
    assert indicator["type"] == "ip"
    assert indicator["value"] == "203.0.113.45"
    assert indicator["fields"] == ["source.ip"]
    assert indicator["verdict"] == "malicious"
    assert indicator["shared"] is False
    assert indicator["providers"] == []
    [intel] = indicator["intel"]
    assert intel["source"] == "iocs.csv"
    assert intel["confidence"] == 85
    assert intel["tags"] == ["brute-force", "ssh"]
    assert await stored_enrichment(db_session, alert_id) == enrichment


async def test_public_hashes_are_looked_up_and_internal_names_are_not(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    online: Enricher,
    services: FakeServices,
) -> None:
    services.vt_detections[MIMIKATZ_SHA256] = 52
    alert_id = await hash_alert(db_session, session_factory, app_settings)

    enrichment = await enrich_alert(online, alert_id)

    assert enrichment is not None
    by_value = {item["value"]: item for item in enrichment["indicators"]}
    sha = by_value[MIMIKATZ_SHA256]
    assert sha["type"] == "sha256"
    assert sha["fields"] == ["Hashes"]
    assert sha["shared"] is True
    [lookup] = sha["providers"]
    assert lookup["provider"] == "virustotal"
    assert lookup["status"] == "ok"
    assert lookup["verdict"] == "malicious"
    assert lookup["data"]["malicious"] == 52
    assert by_value[MIMIKATZ_MD5]["providers"][0]["status"] == "not_found"
    assert by_value[MIMIKATZ_MD5]["intel"] == []
    # Known-bad first; only the hashes went out, never internal names or addresses.
    assert services.urls == [f"{VT_FILES}/{MIMIKATZ_SHA256}", f"{VT_FILES}/{MIMIKATZ_MD5}"]
    assert all(item["providers"] == [] for item in enrichment["indicators"] if not item["shared"])


async def test_postponed_lookups_leave_the_alert_pending_until_retried(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    online: Enricher,
    services: FakeServices,
    fake_redis: FakeAsyncRedis,
) -> None:
    alert_id = await hash_alert(db_session, session_factory, app_settings)
    limiter = RateLimiter(fake_redis)
    await limiter.cooldown("virustotal", 600)

    enrichment = await enrich_alert(online, alert_id)

    assert enrichment is not None and enrichment["pending"] is True
    async with session_factory() as session:
        assert await pending_alert_ids(session) == [alert_id]
    assert services.requests == []

    await fake_redis.flushall()
    retried = await enrich_alerts(online, [alert_id])

    assert (retried.enriched, retried.pending) == (1, 0)
    async with session_factory() as session:
        assert await pending_alert_ids(session) == []
    assert len(services.requests) == 2  # both hashes, once each


async def test_refresh_skips_the_cache(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
) -> None:
    alert_id = await hash_alert(db_session, session_factory, app_settings)
    async with services.client() as client:
        enricher = make_enricher(session_factory, fake_redis, client, [virustotal()])
        await enrich_alert(enricher, alert_id)
        await enrich_alert(enricher, alert_id)
        await enrich_alert(enricher, alert_id, refresh=True)

    # Two hashes, asked about on the first pass and again on the refresh.
    assert len(services.requests) == 4


async def test_missing_alerts_are_counted(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    offline: Enricher,
) -> None:
    alert_id = await brute_force_alert(db_session, session_factory, app_settings)

    summary = await enrich_alerts(offline, [alert_id, 999_999])

    assert (summary.enriched, summary.pending, summary.missing) == (1, 0, 1)
    assert await enrich_alert(offline, 999_999) is None


async def test_local_intel_matches_parent_domains_and_ignores_inactive(
    db_session: AsyncSession,
) -> None:
    await import_sample_feed(db_session)
    scanner = await db_session.scalar(select(Ioc).where(Ioc.value == "198.51.100.23"))
    assert scanner is not None
    scanner.is_active = False
    await db_session.flush()

    found = await local_intel(
        db_session,
        [
            (IocType.DOMAIN, "cdn.update-check.example.net"),
            (IocType.IP, "198.51.100.23"),
            (IocType.IP, "10.20.0.30"),
        ],
    )

    [domain] = found[IocType.DOMAIN, "cdn.update-check.example.net"]
    assert domain.value == "update-check.example.net"
    assert found[IocType.IP, "198.51.100.23"] == []
    assert found[IocType.IP, "10.20.0.30"] == []
    assert await local_intel(db_session, []) == {}


def test_low_confidence_intel_is_only_suspicious() -> None:
    assert intel_verdict(Ioc(confidence=40)) is Verdict.SUSPICIOUS
    assert intel_verdict(Ioc(confidence=85)) is Verdict.MALICIOUS
    assert intel_verdict(Ioc(confidence=None)) is Verdict.MALICIOUS


def test_known_bad_indicators_and_the_source_come_first() -> None:
    found: dict[Key, list[str]] = {
        (IocType.IP, f"10.0.0.{n}"): ["destination.ip"] for n in range(MAX_INDICATORS_PER_ALERT)
    }
    found[IocType.IP, "192.168.1.31"] = ["source.ip"]
    found[IocType.SHA256, MIMIKATZ_SHA256] = ["Hashes"]
    intel = {(IocType.SHA256, MIMIKATZ_SHA256): [Ioc(confidence=95)]}

    ordered = prioritised(found, intel)

    assert len(ordered) == MAX_INDICATORS_PER_ALERT
    assert ordered[0] == (IocType.SHA256, MIMIKATZ_SHA256)
    assert ordered[1] == (IocType.IP, "192.168.1.31")
    assert ordered[2] == (IocType.IP, "10.0.0.0")
