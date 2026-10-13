from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers import GenericJsonParser, ParseContext
from watchpost.ingestion.parsers.base import canonical_json
from watchpost.ingestion.readers import Sample


def parse(record: dict[str, Any], context: ParseContext) -> NormalizedEvent:
    return GenericJsonParser(context).parse_record(record)


def test_flat_aliases(context: ParseContext) -> None:
    record = {
        "timestamp": "2026-10-12T09:40:55Z",
        "event": "login",
        "user": "bob",
        "src_ip": "198.51.100.14",
        "src_port": "40112",
        "outcome": "failed",
        "hostname": "api-01",
        "msg": "bad password",
    }

    event = parse(record, context)
    flat = event.flatten()

    assert event.log_source == "json"
    assert event.timestamp == datetime(2026, 10, 12, 9, 40, 55, tzinfo=UTC)
    assert flat["event.action"] == "login"
    assert flat["user.name"] == "bob"
    assert flat["source.ip"] == "198.51.100.14"
    assert flat["source.port"] == 40112
    assert flat["event.outcome"] == "failure"
    assert flat["host.name"] == "api-01"
    assert flat["message"] == "bad password"
    assert event.raw_event == {"original": record}


def test_ecs_nested_record(context: ParseContext) -> None:
    record = {
        "@timestamp": "2026-10-12T09:46:10.000Z",
        "event": {"category": ["web"], "action": "file_download", "outcome": "success"},
        "user": {"name": "carol"},
        "source": {"ip": "192.168.1.40", "port": 51000},
        "destination": {"ip": "10.0.0.8", "port": 443},
        "url": {"original": "/reports/q3.pdf"},
        "http": {"request": {"method": "get"}, "response": {"status_code": 200}},
        "process": {"name": "nginx", "pid": 812, "parent": {"pid": 1}},
        "host": {"name": "files-01"},
        "user_agent": {"original": "curl/8.5"},
    }

    flat = parse(record, context).flatten()

    assert flat["event.category"] == "web"
    assert flat["event.action"] == "file_download"
    assert flat["user.name"] == "carol"
    assert flat["destination.port"] == 443
    assert flat["http.request.method"] == "GET"
    assert flat["http.response.status_code"] == 200
    assert flat["process.parent.pid"] == 1
    assert flat["host.name"] == "files-01"
    assert flat["user_agent.original"] == "curl/8.5"


def test_dotted_keys(context: ParseContext) -> None:
    record = {"@timestamp": "2026-10-12T09:00:00Z", "source.ip": "10.1.1.1", "user.name": "eve"}

    flat = parse(record, context).flatten()

    assert flat["source.ip"] == "10.1.1.1"
    assert flat["user.name"] == "eve"


@pytest.mark.parametrize(
    ("timestamp_field", "value"),
    [("time", 1791798060000), ("ts", 1791798060), ("date", "2026-10-12 09:41:00")],
)
def test_timestamp_aliases(timestamp_field: str, value: object, context: ParseContext) -> None:
    event = parse({timestamp_field: value, "msg": "x"}, context)

    assert event.timestamp == datetime(2026, 10, 12, 9, 41, tzinfo=UTC)


def test_bad_values_are_dropped_not_fatal(context: ParseContext) -> None:
    record = {
        "timestamp": "2026-10-12T09:00:00Z",
        "src_ip": "unknown",
        "ip": "10.9.9.9",
        "src_port": "port-80",
        "status": "teapot",
        "category": "not-ecs",
        "method": "G3T",
    }

    flat = parse(record, context).flatten()

    assert flat["source.ip"] == "10.9.9.9"  # first alias invalid, next one used
    assert "source.port" not in flat
    assert "http.response.status_code" not in flat
    assert "event.category" not in flat
    assert "http.request.method" not in flat


@pytest.mark.parametrize(
    ("value", "expected"),
    [("ok", "success"), ("ALLOWED", "success"), ("denied", "failure"), ("weird", None)],
)
def test_outcome_synonyms(value: str, expected: str | None, context: ParseContext) -> None:
    flat = parse({"timestamp": "2026-10-12T09:00:00Z", "result": value}, context).flatten()

    assert flat.get("event.outcome") == expected


def test_status_used_as_http_code_or_outcome(context: ParseContext) -> None:
    web = parse({"timestamp": "2026-10-12T09:00:00Z", "status": 404}, context).flatten()
    auth = parse({"timestamp": "2026-10-12T09:00:00Z", "status": "failed"}, context).flatten()

    assert web["http.response.status_code"] == 404
    assert auth["event.outcome"] == "failure"


def test_default_host_applies_only_when_missing() -> None:
    context = ParseContext(reference_time=datetime(2026, 10, 13, tzinfo=UTC), default_host="app-01")

    assert parse({"timestamp": "2026-10-12T09:00:00Z"}, context).host.name == "app-01"
    assert parse({"timestamp": "2026-10-12T09:00:00Z", "host": "x"}, context).host.name == "x"


@pytest.mark.parametrize(
    "record",
    [
        {"msg": "no time at all"},
        {"timestamp": "yesterday"},
        {"timestamp": {"nested": True}},
    ],
)
def test_missing_timestamp_is_malformed(record: dict[str, Any], context: ParseContext) -> None:
    with pytest.raises(ParseError, match="no usable timestamp"):
        parse(record, context)


def test_hash_ignores_key_order(context: ParseContext) -> None:
    first = parse({"timestamp": "2026-10-12T09:00:00Z", "a": 1, "b": 2}, context)
    second = parse({"b": 2, "a": 1, "timestamp": "2026-10-12T09:00:00Z"}, context)

    assert first.event_hash == second.event_hash
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_sniff() -> None:
    timed = Sample(lines=[], records=[{"timestamp": "2026-10-12T09:00:00Z"}] * 2)
    untimed = Sample(lines=[], records=[{"x": 1}])

    assert GenericJsonParser.sniff(timed) == pytest.approx(0.6)
    assert GenericJsonParser.sniff(untimed) == 0
    assert GenericJsonParser.sniff(Sample(lines=["text"], records=[])) == 0
