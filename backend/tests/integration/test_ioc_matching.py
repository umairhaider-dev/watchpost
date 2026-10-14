from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.helpers import import_sample_feed, ingest_sample
from watchpost.core.config import Settings
from watchpost.db.models import Event, Ioc, IocType, event_ioc_matches
from watchpost.intel.matching import sweep_events


async def matched(session: AsyncSession) -> dict[str, list[str]]:
    """Indicator value -> fields it matched, across all events."""
    rows = await session.execute(
        select(Ioc.value, event_ioc_matches.c.field)
        .join(event_ioc_matches, event_ioc_matches.c.ioc_id == Ioc.id)
        .order_by(Ioc.value, event_ioc_matches.c.field)
    )
    found: dict[str, list[str]] = {}
    for value, field in rows:
        found.setdefault(value, []).append(field)
    return found


async def flagged_events(session: AsyncSession) -> int:
    return (
        await session.scalar(
            select(func.count()).select_from(Event).where(Event.ioc_matched.is_(True))
        )
    ) or 0


async def test_ingestion_flags_matching_events(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await import_sample_feed(db_session)

    for name in ("auth.log", "sysmon.json", "access.log"):
        await ingest_sample(db_session, session_factory, app_settings, name)

    found = await matched(db_session)
    assert set(found) == {
        "203.0.113.45",
        "198.51.100.23",
        "update-check.example.net",
        "3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
    }
    assert set(found["update-check.example.net"]) == {"QueryName", "DestinationHostname"}
    assert found["3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"] == ["Hashes"]
    assert set(found["203.0.113.45"]) == {"source.ip"}
    linked = await db_session.scalar(
        select(func.count(func.distinct(event_ioc_matches.c.event_id)))
    )
    assert await flagged_events(db_session) == linked


async def test_sweep_flags_events_stored_before_the_indicators(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    assert await flagged_events(db_session) == 0

    ioc_ids = await import_sample_feed(db_session)
    result = await sweep_events(session_factory, ioc_ids=ioc_ids)

    assert result.events_scanned == 46
    assert result.events_matched == await flagged_events(db_session) > 0
    assert result.new_links == result.events_matched  # one indicator per event here
    assert result.first is not None and result.last is not None
    assert result.first <= result.last

    again = await sweep_events(session_factory, ioc_ids=ioc_ids)
    assert again.new_links == 0
    assert again.events_matched == result.events_matched
    assert again.first is None and again.last is None  # nothing new to run detection over


async def test_sweep_respects_since_and_inactive_or_expired_indicators(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    await import_sample_feed(db_session)
    for ioc in await db_session.scalars(select(Ioc)):
        if ioc.value == "203.0.113.45":
            ioc.expires_at = datetime.now(UTC) - timedelta(days=1)
    await db_session.flush()

    assert (await sweep_events(session_factory)).events_matched == 0
    assert (
        await sweep_events(session_factory, since=datetime(2030, 1, 1, tzinfo=UTC))
    ).events_scanned == 0


async def test_sweep_without_indicators_is_a_no_op(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    result = await sweep_events(session_factory)

    assert (result.events_scanned, result.events_matched) == (0, 0)


async def test_ip_indicator_types_are_matched_exactly(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    db_session.add(Ioc(ioc_type=IocType.IP, value="203.0.113.4"))  # a prefix of the attacker IP
    await db_session.flush()

    await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    assert await flagged_events(db_session) == 0
