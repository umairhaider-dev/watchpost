"""Small builders for test data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from watchpost.db.models import LogSource
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
