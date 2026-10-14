"""Small builders for test data."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Alert, AlertStatus, Event, LogSource, Severity
from watchpost.events import NormalizedEvent, compute_event_hash

DEFAULT_TIME = datetime(2026, 3, 14, 9, 26, 53, tzinfo=UTC)


def make_event(raw_line: str = "sample line", **overrides: Any) -> NormalizedEvent:
    """Build a valid SSH-failure style event; keyword arguments override fields."""
    source = overrides.pop("log_source", LogSource.LINUX_AUTH)
    data: dict[str, Any] = {
        "timestamp": DEFAULT_TIME,
        "log_source": source,
        "event_hash": compute_event_hash(source, raw_line),
        "raw_event": {"line": raw_line},
        "host": {"name": "web-01"},
        "source": {"ip": "203.0.113.45", "port": 52114},
        "user": {"name": "alice"},
        "event": {
            "category": "authentication",
            "action": "ssh_login",
            "outcome": "failure",
        },
        "process": {"name": "sshd", "pid": 4120},
        "message": "Failed password for alice",
    }
    data.update(overrides)
    return NormalizedEvent.model_validate(data)


_alert_numbers = iter(range(1, 1_000_000))


def make_alert(**overrides: Any) -> Alert:
    """An unsaved open alert with a unique group key; keyword arguments override fields."""
    number = next(_alert_numbers)
    data: dict[str, Any] = {
        "rule_id": None,
        "title": f"Test alert {number}",
        "severity": Severity.MEDIUM,
        "status": AlertStatus.NEW,
        "group_key": f"test-alert|{number}",
        "first_seen": DEFAULT_TIME,
        "last_seen": DEFAULT_TIME + timedelta(minutes=5),
        "event_count": 1,
        "host_name": "web-01",
        "source_ip": "203.0.113.45",
        "user_name": "alice",
        "mitre_tactics": ["TA0006"],
        "mitre_techniques": ["T1110.001"],
    }
    data.update(overrides)
    return Alert(**data)


async def store_events(session: AsyncSession, *events: NormalizedEvent) -> list[int]:
    """Insert events and return their IDs, in order."""
    ids = await session.scalars(
        insert(Event).returning(Event.id, sort_by_parameter_order=True),
        [event.to_row() for event in events],
    )
    return list(ids)
