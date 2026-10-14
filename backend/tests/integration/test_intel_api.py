from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fakeredis import FakeAsyncRedis
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.fake_services import MIMIKATZ_SHA256, FakeServices, make_enricher
from tests.integration.conftest import RecordingQueue
from tests.integration.helpers import SAMPLES, detect_job, import_sample_feed, ingest_sample
from watchpost.core.config import Settings
from watchpost.db.models import Alert, Event, Ioc, IocType, event_ioc_matches
from watchpost.intel.enrichment import Enricher

IMPORT = "/api/intel/import"
IOCS = "/api/intel/iocs"
SAMPLE_FEED = (SAMPLES / "iocs.csv").read_bytes()


async def import_file(
    client: AsyncClient, name: str, content: bytes, **form: str
) -> tuple[int, Any]:
    response = await client.post(IMPORT, files={"file": (name, content, "text/csv")}, data=form)
    return response.status_code, response.json()


async def flagged(session: AsyncSession) -> int:
    session.expire_all()
    count = await session.scalar(
        select(func.count()).select_from(Event).where(Event.ioc_matched.is_(True))
    )
    return count or 0


async def ioc_id(session: AsyncSession, value: str) -> int:
    found = await session.scalar(select(Ioc.id).where(Ioc.value == value))
    assert found is not None
    return found


@pytest.fixture
async def online(
    app: FastAPI,
    session_factory: async_sessionmaker[AsyncSession],
    fake_redis: FakeAsyncRedis,
    services: FakeServices,
) -> AsyncIterator[Enricher]:
    """Switch the app to an enricher with both providers configured."""
    async with services.client() as http:
        enricher = make_enricher(session_factory, fake_redis, http)
        app.state.resources.enricher = enricher
        yield enricher


# --------------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------------


async def test_import_creates_then_updates_and_queues_a_sweep(
    client: AsyncClient, queue: RecordingQueue
) -> None:
    code, body = await import_file(client, "iocs.csv", SAMPLE_FEED)

    assert code == 200
    assert body["filename"] == "iocs.csv"
    assert body["source"] == "iocs.csv"
    assert (body["indicators"], body["created"], body["updated"]) == (5, 5, 0)
    assert body["problem_count"] == 0
    assert body["sweep_queued"] is True
    [swept] = queue.sweeps
    assert swept is not None and len(swept) == 5

    code, again = await import_file(client, "iocs.csv", SAMPLE_FEED)
    assert code == 200
    assert (again["created"], again["updated"]) == (0, 5)


async def test_import_options_and_problem_lines(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    feed = b"# partner list\n203.0.113.77\nloader[.]example[.]org\nnot an indicator\n"

    code, body = await import_file(
        client,
        "partner.txt",
        feed,
        source="partner-feed",
        confidence="60",
        tags="Partner, shared",
        expires_in_days="30",
    )

    assert code == 200
    assert (body["created"], body["problem_count"]) == (2, 1)
    [problem] = body["problems"]
    assert problem["line"] == 4
    ioc = await db_session.scalar(select(Ioc).where(Ioc.value == "loader.example.org"))
    assert ioc is not None
    assert (ioc.source, ioc.confidence, ioc.tags) == ("partner-feed", 60, ["partner", "shared"])
    assert ioc.expires_at is not None
    assert ioc.expires_at - datetime.now(UTC) > timedelta(days=29)


@pytest.mark.parametrize(
    ("name", "content", "code", "message"),
    [
        ("feed.bin", bytes(64), 415, "not a UTF-8 text file"),
        ("feed.csv", b"name,comment\nx,y\n", 422, "column"),
        ("feed.txt", b"nothing useful\nhere either\n", 422, "no usable indicators"),
    ],
)
async def test_unusable_feeds_are_rejected(
    client: AsyncClient, name: str, content: bytes, code: int, message: str
) -> None:
    status_code, body = await import_file(client, name, content)

    assert status_code == code
    assert message in body["detail"]


async def test_oversized_feed_is_rejected(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("watchpost.api.routes.intel.MAX_FEED_BYTES", 100)

    code, body = await import_file(client, "big.txt", b"203.0.113.9\n" * 20)

    assert code == 413
    assert "limited to" in body["detail"]


async def test_import_still_saves_when_the_queue_is_down(
    client: AsyncClient, queue: RecordingQueue, db_session: AsyncSession
) -> None:
    queue.fail = True

    code, body = await import_file(client, "iocs.csv", SAMPLE_FEED)

    assert code == 200
    assert body["sweep_queued"] is False
    assert await db_session.scalar(select(func.count()).select_from(Ioc)) == 5


async def test_large_imports_sweep_every_active_indicator(
    client: AsyncClient, queue: RecordingQueue, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("watchpost.api.routes.intel.MAX_SWEEP_IDS", 3)

    code, _ = await import_file(client, "iocs.csv", SAMPLE_FEED)

    assert code == 200
    assert queue.sweeps == [None]


async def test_sweep_everything(client: AsyncClient, queue: RecordingQueue) -> None:
    response = await client.post("/api/intel/sweep")
    assert response.status_code == 202
    assert queue.sweeps == [None]

    queue.fail = True
    assert (await client.post("/api/intel/sweep")).status_code == 503


# --------------------------------------------------------------------------
# Single indicators
# --------------------------------------------------------------------------


async def test_add_indicator_normalises_and_upserts(
    client: AsyncClient, queue: RecordingQueue
) -> None:
    created = await client.post(
        IOCS,
        json={
            "value": "hxxp://update-check[.]example[.]net/payload.ps1",
            "description": "Loader C2",
            "confidence": 90,
            "tags": ["C2", " loader ", "c2"],
        },
    )

    assert created.status_code == 201
    body = created.json()
    assert (body["ioc_type"], body["value"]) == ("domain", "update-check.example.net")
    assert body["tags"] == ["c2", "loader"]
    assert body["source"] == "manual"
    assert body["match_count"] == 0
    assert queue.sweeps == [[body["id"]]]

    updated = await client.post(IOCS, json={"value": "update-check.example.net"})
    assert updated.status_code == 200
    assert updated.json()["id"] == body["id"]
    assert updated.json()["description"] == "Loader C2"  # kept when not given


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"value": "not a thing"}, "not an IP address, domain or file hash"),
        ({"value": "10.0.0.0/8"}, "CIDR ranges are not supported"),
        ({"value": "203.0.113.5", "ioc_type": "domain"}, "looks like an IP address"),
    ],
)
async def test_invalid_indicators_are_rejected(
    client: AsyncClient, payload: dict[str, str], message: str
) -> None:
    response = await client.post(IOCS, json=payload)

    assert response.status_code == 422
    assert message in response.json()["detail"]


async def test_list_filters_and_match_counts(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    async def values(**params: Any) -> list[str]:
        response = await client.get(IOCS, params=params)
        assert response.status_code == 200
        return sorted(item["value"] for item in response.json()["items"])

    everything = (await client.get(IOCS)).json()
    assert everything["total"] == 5
    assert await values(q="203.0.113") == ["203.0.113.45"]
    assert await values(q="MIMIKATZ") == [MIMIKATZ_SHA256]
    assert await values(q="update-check[.]example") == ["update-check.example.net"]
    assert await values(ioc_type="ip") == ["198.51.100.200", "198.51.100.23", "203.0.113.45"]
    assert await values(matched=True) == ["203.0.113.45"]
    assert len(await values(matched=False)) == 4
    assert await values(active=False) == []
    assert len(await values(source="iocs.csv")) == 5
    page = (await client.get(IOCS, params={"limit": 2, "offset": 4})).json()
    assert (len(page["items"]), page["total"]) == (1, 5)

    [matched] = (await client.get(IOCS, params={"matched": True})).json()["items"]
    assert matched["match_count"] == await flagged(db_session) > 0
    assert matched["last_matched_at"] is not None


async def test_indicator_detail_shows_matching_events(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    response = await client.get(f"{IOCS}/{await ioc_id(db_session, '203.0.113.45')}")

    assert response.status_code == 200
    body = response.json()
    assert body["match_count"] == len(body["matches"]) > 0
    assert {match["field"] for match in body["matches"]} == {"source.ip"}
    assert all(match["source_ip"] == "203.0.113.45" for match in body["matches"])
    stamps = [match["timestamp"] for match in body["matches"]]
    assert stamps == sorted(stamps, reverse=True)
    assert (await client.get(f"{IOCS}/999999")).status_code == 404


async def test_update_indicator(
    client: AsyncClient, db_session: AsyncSession, queue: RecordingQueue
) -> None:
    await import_sample_feed(db_session)
    target = await ioc_id(db_session, "198.51.100.23")
    url = f"{IOCS}/{target}"

    off = await client.patch(url, json={"is_active": False, "description": None})
    assert off.status_code == 200
    assert off.json()["is_active"] is False
    assert off.json()["description"] is None
    assert queue.sweeps == []

    on = await client.patch(url, json={"is_active": True, "tags": ["Scanner"], "confidence": 20})
    assert on.status_code == 200
    assert (on.json()["tags"], on.json()["confidence"]) == (["scanner"], 20)
    assert queue.sweeps == [[target]]

    for payload in ({"is_active": None}, {"tags": None}, {"confidence": 101}):
        assert (await client.patch(url, json=payload)).status_code == 422
    assert (await client.patch(f"{IOCS}/999999", json={})).status_code == 404


async def test_delete_indicator_clears_flags_it_alone_set(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    attacker = await ioc_id(db_session, "203.0.113.45")
    before = await flagged(db_session)
    # One of the flagged events is also matched by a second indicator.
    other = Ioc(ioc_type=IocType.IP, value="203.0.113.46")
    db_session.add(other)
    await db_session.flush()
    shared_event = await db_session.scalar(
        select(event_ioc_matches.c.event_id).where(event_ioc_matches.c.ioc_id == attacker)
    )
    await db_session.execute(
        pg_insert(event_ioc_matches).values(
            event_id=shared_event, ioc_id=other.id, field="source.ip"
        )
    )

    response = await client.delete(f"{IOCS}/{attacker}")

    assert response.status_code == 204
    assert before > 1
    assert await flagged(db_session) == 1
    assert (await client.delete(f"{IOCS}/{attacker}")).status_code == 404


async def test_summary_counts(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    body = (await client.get("/api/intel/summary")).json()

    assert body["total"] == body["active"] == 5
    assert body["by_type"] == {"ip": 3, "domain": 1, "sha256": 1}
    assert body["matched_events"] == await flagged(db_session)
    assert body["indicators_matched"] == 1


# --------------------------------------------------------------------------
# Lookups and providers
# --------------------------------------------------------------------------


async def test_lookup_offline_uses_the_local_store(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await import_sample_feed(db_session)

    known = (await client.get("/api/intel/lookup", params={"value": "203.0.113.45"})).json()
    assert known["ioc_type"] == "ip"
    assert known["verdict"] == "malicious"
    assert (known["shared"], known["online"]) == (False, False)
    assert [ioc["value"] for ioc in known["intel"]] == ["203.0.113.45"]
    assert known["providers"] == []

    sub = (
        await client.get("/api/intel/lookup", params={"value": "cdn.update-check[.]example[.]net"})
    ).json()
    assert sub["value"] == "cdn.update-check.example.net"
    assert [ioc["value"] for ioc in sub["intel"]] == ["update-check.example.net"]

    unknown = (await client.get("/api/intel/lookup", params={"value": "a" * 64})).json()
    assert (unknown["verdict"], unknown["intel"]) == ("unknown", [])

    bad = await client.get("/api/intel/lookup", params={"value": "nope"})
    assert bad.status_code == 422


@pytest.mark.usefixtures("online")
async def test_lookup_online_asks_providers_and_caches(
    client: AsyncClient, services: FakeServices
) -> None:
    services.vt_detections[MIMIKATZ_SHA256] = 52
    params = {"value": MIMIKATZ_SHA256.upper(), "ioc_type": "sha256"}

    first = (await client.get("/api/intel/lookup", params=params)).json()
    cached = (await client.get("/api/intel/lookup", params=params)).json()
    refreshed = (await client.get("/api/intel/lookup", params={**params, "refresh": True})).json()

    [result] = first["providers"]
    assert (result["provider"], result["status"], result["verdict"]) == (
        "virustotal",
        "ok",
        "malicious",
    )
    assert first["verdict"] == "malicious"
    assert first["online"] is True
    assert cached["providers"][0]["cached"] is True
    assert refreshed["providers"][0]["cached"] is False
    assert len(services.requests) == 2


async def test_provider_status_offline(client: AsyncClient) -> None:
    body = (await client.get("/api/intel/providers")).json()

    assert body["online"] is False
    assert body["cache_hours"] == 24
    assert [(p["name"], p["configured"]) for p in body["providers"]] == [
        ("abuseipdb", False),
        ("virustotal", False),
    ]


@pytest.mark.usefixtures("online")
async def test_provider_status_online(client: AsyncClient) -> None:
    body = (await client.get("/api/intel/providers")).json()

    assert body["online"] is True
    budgets = {p["name"]: p["remaining"] for p in body["providers"]}
    assert budgets == {
        "abuseipdb": {"1000/day": 1000},
        "virustotal": {"4/min": 4, "500/day": 500},
    }


# --------------------------------------------------------------------------
# Alerts and events
# --------------------------------------------------------------------------


@pytest.mark.usefixtures("rules")
async def test_enrich_alert_on_demand(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    job_id = await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    await detect_job(db_session, session_factory, job_id)
    alert_id = await db_session.scalar(select(Alert.id).where(Alert.rule_id == "ssh-brute-force"))

    response = await client.post(f"/api/alerts/{alert_id}/enrich")

    assert response.status_code == 200
    enrichment = response.json()
    assert enrichment["verdict"] == "malicious"
    assert enrichment["indicators"][0]["value"] == "203.0.113.45"
    detail = (await client.get(f"/api/alerts/{alert_id}")).json()
    assert detail["enrichment"] == enrichment
    assert (await client.post("/api/alerts/999999/enrich")).status_code == 404


async def test_events_filter_and_indicators(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    hits = (await client.get("/api/events", params={"ioc_matched": True, "limit": 500})).json()
    misses = (await client.get("/api/events", params={"ioc_matched": False, "limit": 500})).json()

    assert len(hits["items"]) == await flagged(db_session)
    assert all(event["ioc_matched"] for event in hits["items"])
    assert not any(event["ioc_matched"] for event in misses["items"])
    assert len(hits["items"]) + len(misses["items"]) == 46

    event_id = hits["items"][0]["id"]
    [indicator] = (await client.get(f"/api/events/{event_id}/indicators")).json()
    assert indicator["value"] == "203.0.113.45"
    assert indicator["field"] == "source.ip"
    assert indicator["confidence"] == 85
    assert (await client.get("/api/events/999999/indicators")).status_code == 404
