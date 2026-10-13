from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from tests.factories import make_event
from watchpost.db.models import Event
from watchpost.events import FIELDS, FIELDS_BY_NAME, FieldKind, NormalizedEvent

EVENT_COLUMNS = set(Event.__table__.columns.keys())


def test_every_registry_field_maps_to_an_event_column() -> None:
    missing = [spec.name for spec in FIELDS if spec.column not in EVENT_COLUMNS]

    assert missing == []


def test_registry_names_and_columns_are_unique() -> None:
    assert len(FIELDS_BY_NAME) == len(FIELDS)
    assert len({spec.column for spec in FIELDS}) == len(FIELDS)


def test_registry_paths_resolve_on_the_model() -> None:
    event = make_event()
    for spec in FIELDS:
        event.get(spec)  # raises AttributeError if a path does not exist


def test_field_path_strips_at_prefix() -> None:
    assert FIELDS_BY_NAME["@timestamp"].path == ("timestamp",)
    assert FIELDS_BY_NAME["process.parent.name"].path == ("process", "parent", "name")


def test_to_row_produces_only_known_columns() -> None:
    row = make_event().to_row()

    assert set(row) <= EVENT_COLUMNS
    assert row["source_ip"] == "203.0.113.45"
    assert row["event_outcome"] == "failure"
    assert row["log_source"] == "linux_auth"
    assert row["raw_event"] == {"line": "sample line"}
    assert row["url_original"] is None


def test_to_row_converts_enums_and_ips_to_plain_values() -> None:
    row = make_event().to_row()

    assert type(row["log_source"]) is str
    assert type(row["event_category"]) is str
    assert type(row["source_ip"]) is str


def test_flatten_uses_dotted_names_and_skips_empty_fields() -> None:
    flat = make_event().flatten()

    assert flat["source.ip"] == "203.0.113.45"
    assert flat["user.name"] == "alice"
    assert flat["event.action"] == "ssh_login"
    assert flat["process.name"] == "sshd"
    assert "url.original" not in flat
    assert "process.parent.name" not in flat


def test_nested_http_fields_flatten() -> None:
    event = make_event(
        log_source="web_access",
        url={"original": "/index.php?id=1"},
        http={"request": {"method": "GET"}, "response": {"status_code": 404}},
        user_agent={"original": "curl/8.5"},
    )

    flat = event.flatten()

    assert flat["http.request.method"] == "GET"
    assert flat["http.response.status_code"] == 404
    assert flat["url.original"] == "/index.php?id=1"
    assert flat["user_agent.original"] == "curl/8.5"


def test_naive_timestamp_is_assumed_utc() -> None:
    event = make_event(timestamp=datetime(2026, 1, 1, 12, 0))  # noqa: DTZ001

    assert event.timestamp == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_aware_timestamp_is_converted_to_utc() -> None:
    plus_five = timezone(timedelta(hours=5))
    event = make_event(timestamp=datetime(2026, 1, 1, 17, 0, tzinfo=plus_five))

    assert event.timestamp == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert event.timestamp.utcoffset() == timedelta(0)


def test_ipv6_addresses_are_normalised() -> None:
    event = make_event(source={"ip": "2001:DB8:0:0:0:0:0:1"})

    assert event.flatten()["source.ip"] == "2001:db8::1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"source": {"ip": "999.1.1.1"}},
        {"source": {"ip": "203.0.113.1", "port": 70000}},
        {"event": {"outcome": "maybe"}},
        {"event": {"category": "not-a-category"}},
        {"log_source": "syslog"},
        {"event_hash": "not-a-hash"},
        {"http": {"response": {"status_code": 42}}},
        {"unexpected_field": True},
        {"host": {"name": "web-01", "os": "linux"}},
    ],
)
def test_invalid_values_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_event(**overrides)


def test_strings_are_stripped() -> None:
    event = make_event(user={"name": "  alice  "})

    assert event.user.name == "alice"


def test_minimal_event_only_needs_core_fields() -> None:
    event = NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        log_source="json",  # type: ignore[arg-type]
        event_hash="a" * 64,
        raw_event={},
    )

    assert event.flatten() == {
        "@timestamp": event.timestamp,
        "log_source": "json",
        "threat.matched": False,
    }


def test_threat_match_flag_maps_to_ioc_column() -> None:
    event = make_event(threat={"matched": True})

    assert event.to_row()["ioc_matched"] is True
    assert event.flatten()["threat.matched"] is True
    assert make_event().to_row()["ioc_matched"] is False


def test_field_kinds_cover_ip_fields() -> None:
    ip_fields = {spec.name for spec in FIELDS if spec.kind is FieldKind.IP}

    assert ip_fields == {"source.ip", "destination.ip"}
