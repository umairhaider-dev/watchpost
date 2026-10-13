from __future__ import annotations

from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_event
from watchpost.db.models import Event

START = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)


async def seed(session: AsyncSession, count: int, log_source: str = "linux_auth") -> None:
    rows = [
        make_event(
            raw_line=f"{log_source}-{n}",
            log_source=log_source,
            timestamp=START + timedelta(minutes=n),
        ).to_row()
        for n in range(count)
    ]
    await session.execute(insert(Event), rows)


async def test_events_are_newest_first(client: AsyncClient, db_session: AsyncSession) -> None:
    await seed(db_session, 5)

    body = (await client.get("/api/events")).json()

    timestamps = [item["timestamp"] for item in body["items"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert body["next_cursor"] is None
    first = body["items"][0]
    assert first["source_ip"] == "203.0.113.45"
    assert first["event_action"] == "ssh_login"
    assert first["raw_event"] == {"line": "linux_auth-4"}


async def test_keyset_pagination_walks_every_event_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await seed(db_session, 7)
    seen: list[int] = []
    cursor = None

    while True:
        params: dict[str, str | int] = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        body = (await client.get("/api/events", params=params)).json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert len(seen) == len(set(seen)) == 7


async def test_filter_by_log_source(client: AsyncClient, db_session: AsyncSession) -> None:
    await seed(db_session, 2, "linux_auth")
    await seed(db_session, 3, "web_access")

    body = (await client.get("/api/events", params={"log_source": "web_access"})).json()

    assert len(body["items"]) == 3
    assert {item["log_source"] for item in body["items"]} == {"web_access"}


async def test_invalid_cursor_and_source(client: AsyncClient) -> None:
    bad_cursor = await client.get("/api/events", params={"cursor": "not-a-cursor!!"})
    bad_source = await client.get("/api/events", params={"log_source": "syslog"})
    bad_limit = await client.get("/api/events", params={"limit": 0})

    assert bad_cursor.status_code == 422
    assert bad_source.status_code == 422
    assert bad_limit.status_code == 422
