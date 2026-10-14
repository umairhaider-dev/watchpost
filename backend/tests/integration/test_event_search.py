from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_event, store_events
from watchpost.db.models import Event, LogSource
from watchpost.search import QueryError, compile_query

START = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
AUTH = {"category": "authentication", "action": "ssh_login"}


def at(minutes: int) -> datetime:
    return START + timedelta(minutes=minutes)


EVENTS: dict[str, dict[str, Any]] = {
    "root_failure": {
        "timestamp": at(0),
        "user": {"name": "root"},
        "event": {**AUTH, "outcome": "failure"},
        "message": "Failed password for root from 203.0.113.45",
    },
    "backup_success": {
        "timestamp": at(1),
        "source": {"ip": "10.20.0.30", "port": 40022},
        "user": {"name": "backup"},
        "event": {**AUTH, "outcome": "success"},
        "message": "Accepted publickey for backup",
    },
    "deploy_sudo": {
        "timestamp": at(2),
        "source": {},
        "user": {"name": "deploy"},
        "event": {"category": "process", "action": "sudo", "outcome": "success"},
        "process": {"name": "sudo", "command_line": "/usr/bin/journalctl -u nginx"},
        "message": "deploy ran journalctl as root",
    },
    "admin_probe": {
        "timestamp": at(3),
        "log_source": LogSource.WEB_ACCESS,
        "host": {"name": "shop-01"},
        "source": {"ip": "198.51.100.23"},
        "user": {},
        "event": {"category": "web", "action": "http_request", "outcome": "failure"},
        "process": {},
        "url": {"original": "/admin/login.php?id=1%27"},
        "http": {"request": {"method": "GET"}, "response": {"status_code": 404}},
        "message": None,
    },
    "server_error": {
        "timestamp": at(4),
        "log_source": LogSource.WEB_ACCESS,
        "host": {"name": "shop-01"},
        "source": {"ip": "198.51.100.23"},
        "user": {},
        "event": {"category": "web", "action": "http_request", "outcome": "failure"},
        "process": {},
        "url": {"original": "/api/orders"},
        "http": {"request": {"method": "POST"}, "response": {"status_code": 503}},
        "message": None,
    },
    "lsass_read": {
        "timestamp": at(5),
        "log_source": LogSource.SYSMON,
        "host": {"name": "WS-FIN-07"},
        "source": {},
        "destination": {"ip": "203.0.113.99", "port": 443},
        "user": {"name": "carol"},
        "event": {"category": "process", "action": "process_access", "outcome": None},
        "process": {"name": "m.exe", "command_line": "m.exe sekurlsa::logonpasswords"},
        "threat": {"matched": True},
        "message": None,
    },
    "next_day": {
        "timestamp": at(24 * 60),
        "host": {},
        "source": {},
        "user": {"name": "root"},
        "event": {**AUTH, "outcome": "failure"},
        "message": "Failed password for root",
    },
}


@pytest.fixture
async def ids(db_session: AsyncSession) -> dict[str, int]:
    events = []
    for name, overrides in EVENTS.items():
        raw: dict[str, Any] = {"line": name}
        if name == "lsass_read":
            raw = {"event_data": {"TargetImage": r"C:\Windows\system32\lsass.exe"}}
        events.append(make_event(raw_line=name, raw_event=raw, **overrides))
    stored = await store_events(db_session, *events)
    return dict(zip(EVENTS, stored, strict=True))


async def search(session: AsyncSession, ids: dict[str, int], query: str) -> list[str]:
    condition = compile_query(query)
    assert condition is not None
    names = {event_id: name for name, event_id in ids.items()}
    rows = await session.scalars(select(Event.id).where(condition).order_by(Event.timestamp))
    return [names[row] for row in rows]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        # keyword fields: exact, case-sensitive; patterns are case-insensitive
        ("user.name:root", ["root_failure", "next_day"]),
        ("user.name:ROOT", []),
        ("user:ROO*", ["root_failure", "next_day"]),
        ("host.name:ws-fin-07", []),
        ("host:ws-fin-??", ["lsass_read"]),
        ("event.outcome:success", ["backup_success", "deploy_sudo"]),
        # text fields: case-insensitive substring
        ("process.command_line:SEKURLSA", ["lsass_read"]),
        ("url:admin", ["admin_probe"]),
        ("url:/api/*", ["server_error"]),
        ("url:%27", ["admin_probe"]),
        ("url:_", []),
        # free text searches message, command line and URL
        ("journalctl", ["deploy_sudo"]),
        ('"failed password"', ["root_failure", "next_day"]),
        ("logonpasswords", ["lsass_read"]),
        # IP addresses and networks
        ("source.ip:198.51.100.23", ["admin_probe", "server_error"]),
        ("source.ip:10.0.0.0/8", ["backup_success"]),
        ("ip:203.0.113.0/24", ["root_failure", "lsass_read"]),
        ("destination.ip:*", ["lsass_read"]),
        # numbers and comparisons
        ("status:404", ["admin_probe"]),
        ("http.response.status_code:>=500", ["server_error"]),
        ("status:<500", ["admin_probe"]),
        # timestamps
        ("@timestamp:2026-10-13", ["next_day"]),
        ("timestamp:>2026-10-12", ["next_day"]),
        ("timestamp:<=2026-10-12", list(EVENTS)[:-1]),
        ("timestamp:>=2026-10-12T09:04:00Z", ["server_error", "lsass_read", "next_day"]),
        ("timestamp:<2026-10-12T09:01:00", ["root_failure"]),
        ("timestamp:*", list(EVENTS)),
        # booleans and the raw record
        ("threat.matched:true", ["lsass_read"]),
        ("raw.event_data.TargetImage:*lsass.exe", ["lsass_read"]),
        ("raw.event_data.TargetImage:*", ["lsass_read"]),
        # boolean logic; NOT keeps events where the field is missing
        ("user.name:root event.outcome:failure", ["root_failure", "next_day"]),
        ("user.name:root AND NOT host.name:web-01", ["next_day"]),
        ("user:deploy OR user:carol", ["deploy_sudo", "lsass_read"]),
        ("(user:deploy OR user:carol) -action:sudo", ["lsass_read"]),
        ("log_source:web_access -status:404", ["server_error"]),
        ("NOT user.name:*", ["admin_probe", "server_error"]),
    ],
)
async def test_queries(
    db_session: AsyncSession, ids: dict[str, int], query: str, expected: list[str]
) -> None:
    assert await search(db_session, ids, query) == expected


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("hostname:web-01", "unknown field 'hostname'; did you mean host.name?"),
        ("bogus.field:x", "unknown field 'bogus.field'"),
        ("source.ip:web-01", "is not an IP address or network"),
        ("source.ip:10.0.*", "CIDR network"),
        ("source.ip:>10.0.0.1", "CIDR network"),
        ("status:abc", "takes a whole number"),
        ("@timestamp:yesterday", "takes an ISO date or time"),
        ("threat.matched:maybe", "true or false"),
        ("user.name:>a", "keyword and cannot be compared"),
        ("message:>a", "text and cannot be compared"),
        ("raw.a..b:x", "not a valid path"),
        ("raw.a.b.c.d.e.f.g.h.i:x", "not a valid path"),
        ("raw.a.:x", "not a valid path"),
    ],
)
def test_invalid_queries(query: str, message: str) -> None:
    with pytest.raises(QueryError, match=message.replace("?", r"\?").replace("(", r"\(")):
        compile_query(query)


def test_empty_query_compiles_to_nothing() -> None:
    assert compile_query("  ") is None


async def test_search_api_with_time_range_and_paging(
    client: AsyncClient, ids: dict[str, int]
) -> None:
    del ids

    async def fetch(**params: str | int) -> dict[str, Any]:
        response = await client.get("/api/events", params=params)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    failures = await fetch(q="event.outcome:failure")
    assert failures["items"][0]["message"] == "Failed password for root"

    first_hour = await fetch(
        q="user.name:root",
        start=START.isoformat(),
        end=(START + timedelta(hours=1)).isoformat(),
    )
    assert len(first_hour["items"]) == 1

    page = await fetch(q="log_source:linux_auth", limit=2)
    assert len(page["items"]) == 2
    rest = await fetch(q="log_source:linux_auth", limit=2, cursor=page["next_cursor"])
    assert len(rest["items"]) == 2
    assert rest["next_cursor"] is None

    bad = await client.get("/api/events", params={"q": "hostname:x"})
    assert bad.status_code == 422
    assert "did you mean host.name" in bad.json()["detail"]
