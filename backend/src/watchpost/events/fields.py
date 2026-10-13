"""Registry of normalised event fields.

Each field has an ECS-style dotted name (what rules and search queries use)
and the ``events`` table column that stores it. Keeping the mapping in one
place means the parser output, the detection engine and the query language
cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FieldKind(StrEnum):
    """How a field is compared and indexed."""

    KEYWORD = "keyword"  # exact-match strings (host names, actions)
    TEXT = "text"  # free text where substring matching is expected
    IP = "ip"
    INTEGER = "integer"
    DATETIME = "datetime"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One normalised field."""

    name: str
    column: str
    kind: FieldKind
    description: str

    @property
    def path(self) -> tuple[str, ...]:
        """Attribute path inside :class:`NormalizedEvent` (``@timestamp`` -> ``timestamp``)."""
        return tuple(self.name.removeprefix("@").split("."))


FIELDS: tuple[FieldSpec, ...] = (
    FieldSpec("@timestamp", "timestamp", FieldKind.DATETIME, "When the event happened (UTC)."),
    FieldSpec("log_source", "log_source", FieldKind.KEYWORD, "Parser that produced the event."),
    FieldSpec("host.name", "host_name", FieldKind.KEYWORD, "Host that recorded the event."),
    FieldSpec("source.ip", "source_ip", FieldKind.IP, "Address the activity came from."),
    FieldSpec("source.port", "source_port", FieldKind.INTEGER, "Source port."),
    FieldSpec("destination.ip", "destination_ip", FieldKind.IP, "Address the activity targeted."),
    FieldSpec("destination.port", "destination_port", FieldKind.INTEGER, "Destination port."),
    FieldSpec("user.name", "user_name", FieldKind.KEYWORD, "Account involved in the event."),
    FieldSpec("event.category", "event_category", FieldKind.KEYWORD, "ECS event category."),
    FieldSpec("event.action", "event_action", FieldKind.KEYWORD, "What happened, e.g. ssh_login."),
    FieldSpec("event.outcome", "event_outcome", FieldKind.KEYWORD, "success, failure or unknown."),
    FieldSpec("event.code", "event_code", FieldKind.KEYWORD, "Source-specific ID, e.g. 4625."),
    FieldSpec("process.name", "process_name", FieldKind.KEYWORD, "Process image name."),
    FieldSpec("process.pid", "process_pid", FieldKind.INTEGER, "Process ID."),
    FieldSpec("process.executable", "process_executable", FieldKind.TEXT, "Full image path."),
    FieldSpec("process.command_line", "process_command_line", FieldKind.TEXT, "Command line."),
    FieldSpec("process.parent.name", "process_parent_name", FieldKind.KEYWORD, "Parent image."),
    FieldSpec("process.parent.pid", "process_parent_pid", FieldKind.INTEGER, "Parent PID."),
    FieldSpec("url.original", "url_original", FieldKind.TEXT, "Requested URL as logged."),
    FieldSpec("http.request.method", "http_method", FieldKind.KEYWORD, "HTTP method."),
    FieldSpec("http.response.status_code", "http_status_code", FieldKind.INTEGER, "HTTP status."),
    FieldSpec("user_agent.original", "user_agent", FieldKind.TEXT, "Client user agent."),
    FieldSpec("message", "message", FieldKind.TEXT, "Human-readable summary."),
)

FIELDS_BY_NAME: dict[str, FieldSpec] = {spec.name: spec for spec in FIELDS}
