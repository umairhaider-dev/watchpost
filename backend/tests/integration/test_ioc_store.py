from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Ioc, IocType
from watchpost.intel.feeds import FeedEntry
from watchpost.intel.store import upsert_iocs


async def all_iocs(session: AsyncSession) -> dict[str, Ioc]:
    found = {}
    for ioc in await session.scalars(select(Ioc)):
        await session.refresh(ioc)
        found[ioc.value] = ioc
    return found


async def test_import_creates_indicators_with_defaults(db_session: AsyncSession) -> None:
    entries = [
        FeedEntry(line=1, ioc_type=IocType.IP, value="203.0.113.45", tags=("ssh",)),
        FeedEntry(
            line=2, ioc_type=IocType.DOMAIN, value="evil.example", confidence=95, source="feed-x"
        ),
    ]

    result = await upsert_iocs(
        db_session,
        entries,
        source="weekly.txt",
        default_confidence=70,
        extra_tags=["Imported", " "],
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )

    iocs = await all_iocs(db_session)
    assert (result.created, result.updated, len(result.ioc_ids)) == (2, 0, 2)
    ip = iocs["203.0.113.45"]
    assert ip.source == "weekly.txt"
    assert ip.confidence == 70
    assert ip.tags == ["imported", "ssh"]
    assert ip.is_active is True
    assert ip.expires_at == datetime(2027, 1, 1, tzinfo=UTC)
    assert iocs["evil.example"].source == "feed-x"
    assert iocs["evil.example"].confidence == 95


async def test_reimport_updates_and_reactivates(db_session: AsyncSession) -> None:
    first = [
        FeedEntry(
            line=1, ioc_type=IocType.IP, value="203.0.113.45", description="scanner", confidence=50
        )
    ]
    await upsert_iocs(db_session, first, source="feed")
    ioc = (await all_iocs(db_session))["203.0.113.45"]
    ioc.is_active = False
    await db_session.flush()

    again = [FeedEntry(line=1, ioc_type=IocType.IP, value="203.0.113.45", tags=("ssh",))]
    result = await upsert_iocs(db_session, again, source="feed-v2")

    ioc = (await all_iocs(db_session))["203.0.113.45"]
    assert (result.created, result.updated) == (0, 1)
    assert ioc.is_active is True
    assert ioc.description == "scanner"  # kept: the new feed had none
    assert ioc.confidence == 50
    assert ioc.source == "feed-v2"
    assert ioc.tags == ["ssh"]


async def test_large_imports_are_batched(db_session: AsyncSession) -> None:
    entries = [
        FeedEntry(line=n, ioc_type=IocType.IP, value=f"198.51.100.{n % 250}") for n in range(250)
    ] + [
        FeedEntry(line=1000 + n, ioc_type=IocType.DOMAIN, value=f"host{n}.evil.example")
        for n in range(1200)
    ]

    result = await upsert_iocs(db_session, entries, source="big")

    assert result.created == 1450
