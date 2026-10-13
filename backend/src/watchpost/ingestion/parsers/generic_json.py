"""Parser for arbitrary JSON log records (one object per line, or an array).

Fields are found by trying, in order, the ECS name (nested ``{"source":
{"ip": ...}}`` or flattened ``"source.ip"``) and then common aliases such as
``src_ip``, ``username`` or ``status_code``. Values that do not fit their
field (an IP column holding "unknown") are dropped rather than rejecting the
record; the full original record is always stored.

A record without a usable timestamp is reported as malformed, because an
event that cannot be placed on a timeline is of little use to an analyst.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from watchpost.db.models import EventCategory, EventOutcome, LogSource
from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers.base import JsonParser, build_event, canonical_json
from watchpost.ingestion.readers import Sample
from watchpost.ingestion.values import (
    clean_int,
    clean_ip,
    clean_port,
    clean_str,
    parse_timestamp,
)

_ALIASES: dict[str, tuple[str, ...]] = {
    "@timestamp": (
        "@timestamp",
        "timestamp",
        "time",
        "ts",
        "datetime",
        "date",
        "event_time",
        "eventTime",
        "EventTime",
        "created_at",
        "logged_at",
    ),
    "host.name": ("host.name", "hostname", "host", "computer", "computer_name", "device"),
    "source.ip": (
        "source.ip",
        "src_ip",
        "srcip",
        "source_ip",
        "src",
        "client_ip",
        "clientip",
        "remote_addr",
        "remote_ip",
        "ip",
    ),
    "source.port": ("source.port", "src_port", "srcport", "sport", "source_port", "client_port"),
    "destination.ip": (
        "destination.ip",
        "dst_ip",
        "dest_ip",
        "dstip",
        "destination_ip",
        "dst",
        "server_ip",
    ),
    "destination.port": (
        "destination.port",
        "dst_port",
        "dest_port",
        "dport",
        "destination_port",
        "server_port",
    ),
    "user.name": ("user.name", "user", "username", "user_name", "userName", "account"),
    "event.category": ("event.category", "category"),
    "event.action": ("event.action", "action", "event_type", "eventName", "event"),
    "event.outcome": ("event.outcome", "outcome", "result", "status"),
    "event.code": ("event.code", "event_id", "eventid", "code"),
    "process.name": ("process.name", "process_name", "process", "program", "app"),
    "process.pid": ("process.pid", "pid"),
    "process.executable": ("process.executable", "executable", "image", "exe"),
    "process.command_line": (
        "process.command_line",
        "command_line",
        "commandline",
        "cmdline",
        "cmd",
    ),
    "process.parent.name": ("process.parent.name", "parent_process", "parent_name"),
    "process.parent.pid": ("process.parent.pid", "ppid", "parent_pid"),
    "url.original": ("url.original", "url", "uri", "request_uri", "path"),
    "http.request.method": ("http.request.method", "method", "http_method", "request_method"),
    "http.response.status_code": (
        "http.response.status_code",
        "status_code",
        "http_status",
        "response_code",
        "status",
    ),
    "user_agent.original": (
        "user_agent.original",
        "user_agent",
        "useragent",
        "http_user_agent",
        "ua",
    ),
    "message": ("message", "msg", "description", "log"),
}

_OUTCOME_SYNONYMS = {
    "success": EventOutcome.SUCCESS,
    "succeeded": EventOutcome.SUCCESS,
    "successful": EventOutcome.SUCCESS,
    "ok": EventOutcome.SUCCESS,
    "allowed": EventOutcome.SUCCESS,
    "allow": EventOutcome.SUCCESS,
    "accepted": EventOutcome.SUCCESS,
    "failure": EventOutcome.FAILURE,
    "failed": EventOutcome.FAILURE,
    "fail": EventOutcome.FAILURE,
    "error": EventOutcome.FAILURE,
    "denied": EventOutcome.FAILURE,
    "deny": EventOutcome.FAILURE,
    "blocked": EventOutcome.FAILURE,
    "rejected": EventOutcome.FAILURE,
    "unknown": EventOutcome.UNKNOWN,
}
_CATEGORIES = {category.value for category in EventCategory}


def _lookup(record: dict[str, Any], name: str) -> Any:
    """Value of ``name`` as a flat key or a nested path; ``None`` if absent."""
    if name in record:
        return record[name]
    node: Any = record
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _candidates(record: dict[str, Any], field: str) -> list[Any]:
    """Scalar values found under the field's ECS name and aliases, in priority order."""
    found = []
    for alias in _ALIASES[field]:
        value = _lookup(record, alias)
        if value is not None and not isinstance(value, dict):
            found.append(value)
    return found


def _first_valid(record: dict[str, Any], field: str, clean: Any) -> Any:
    for value in _candidates(record, field):
        cleaned = clean(value)
        if cleaned is not None:
            return cleaned
    return None


def _category(value: Any) -> EventCategory | None:
    values = value if isinstance(value, list) else [value]
    for item in values:
        text = (clean_str(item) or "").lower()
        if text in _CATEGORIES:
            return EventCategory(text)
    return None


def _outcome(value: Any) -> EventOutcome | None:
    return _OUTCOME_SYNONYMS.get((clean_str(value) or "").lower())


def _status_code(value: Any) -> int | None:
    return clean_int(value, minimum=100, maximum=599)


def _method(value: Any) -> str | None:
    text = clean_str(value, max_length=16)
    return text.upper() if text and text.isalpha() else None


def _timestamp(record: dict[str, Any]) -> datetime:
    for value in _candidates(record, "@timestamp"):
        try:
            return parse_timestamp(value)
        except ValueError:
            continue
    msg = "no usable timestamp (looked for @timestamp, timestamp, time, ts, ...)"
    raise ParseError(msg)


class GenericJsonParser(JsonParser):
    """Any JSON object per record, mapped by ECS names and common aliases."""

    name: ClassVar[str] = "json"
    label: ClassVar[str] = "Generic JSON lines"
    description: ClassVar[str] = (
        "One JSON object per line (or a JSON array). Fields are matched by ECS "
        "name or common aliases such as src_ip, username and status_code."
    )

    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent:
        fields: dict[str, Any] = {
            "host.name": _first_valid(record, "host.name", clean_str) or self.context.default_host,
            "source.ip": _first_valid(record, "source.ip", clean_ip),
            "source.port": _first_valid(record, "source.port", clean_port),
            "destination.ip": _first_valid(record, "destination.ip", clean_ip),
            "destination.port": _first_valid(record, "destination.port", clean_port),
            "user.name": _first_valid(record, "user.name", clean_str),
            "event.category": _first_valid(record, "event.category", _category),
            "event.action": _first_valid(record, "event.action", clean_str),
            "event.outcome": _first_valid(record, "event.outcome", _outcome),
            "event.code": _first_valid(record, "event.code", clean_str),
            "process.name": _first_valid(record, "process.name", clean_str),
            "process.pid": _first_valid(record, "process.pid", clean_int),
            "process.executable": _first_valid(record, "process.executable", clean_str),
            "process.command_line": _first_valid(record, "process.command_line", clean_str),
            "process.parent.name": _first_valid(record, "process.parent.name", clean_str),
            "process.parent.pid": _first_valid(record, "process.parent.pid", clean_int),
            "url.original": _first_valid(record, "url.original", clean_str),
            "http.request.method": _first_valid(record, "http.request.method", _method),
            "http.response.status_code": _first_valid(
                record, "http.response.status_code", _status_code
            ),
            "user_agent.original": _first_valid(record, "user_agent.original", clean_str),
            "message": _first_valid(record, "message", clean_str),
        }
        return build_event(
            timestamp=_timestamp(record),
            log_source=LogSource.JSON,
            raw_line=canonical_json(record),
            raw_event={"original": record},
            fields=fields,
        )

    @classmethod
    def sniff(cls, sample: Sample) -> float:
        if not sample.records:
            return 0.0
        hits = 0
        for record in sample.records:
            try:
                _timestamp(record)
            except ParseError:
                continue
            hits += 1
        # Lower than the specific parsers so they win when they also match.
        return 0.6 * hits / len(sample.records)
