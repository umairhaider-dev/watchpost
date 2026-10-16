"""Pydantic model for a normalised event (inspired by Elastic Common Schema).

Parsers build :class:`NormalizedEvent` instances; the ingestion pipeline turns
them into ``events`` rows with :meth:`NormalizedEvent.to_row`, which is what
the detection engine and the search read back. :meth:`NormalizedEvent.flatten`
gives the same values keyed by the dotted names rules and queries use
(``source.ip``, ``process.command_line``, ...).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from operator import attrgetter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from watchpost.db.models.enums import EventCategory, EventOutcome, LogSource
from watchpost.events.fields import FIELDS, FieldSpec

_SHA256_HEX = r"^[0-9a-f]{64}$"


class _Section(BaseModel):
    """Base for nested ECS field groups."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HostFields(_Section):
    name: str | None = Field(default=None, max_length=255)


class EndpointFields(_Section):
    ip: IPvAnyAddress | None = None
    port: int | None = Field(default=None, ge=0, le=65535)


class UserFields(_Section):
    name: str | None = Field(default=None, max_length=255)


class EventFields(_Section):
    category: EventCategory | None = None
    action: str | None = Field(default=None, max_length=128)
    outcome: EventOutcome | None = None
    code: str | None = Field(default=None, max_length=32)


class ParentProcessFields(_Section):
    name: str | None = Field(default=None, max_length=255)
    pid: int | None = Field(default=None, ge=0)


class ProcessFields(_Section):
    name: str | None = Field(default=None, max_length=255)
    pid: int | None = Field(default=None, ge=0)
    executable: str | None = None
    command_line: str | None = None
    parent: ParentProcessFields = Field(default_factory=ParentProcessFields)


class UrlFields(_Section):
    original: str | None = None


class HttpRequestFields(_Section):
    method: str | None = Field(default=None, max_length=16)


class HttpResponseFields(_Section):
    status_code: int | None = Field(default=None, ge=100, le=599)


class HttpFields(_Section):
    request: HttpRequestFields = Field(default_factory=HttpRequestFields)
    response: HttpResponseFields = Field(default_factory=HttpResponseFields)


class UserAgentFields(_Section):
    original: str | None = None


class ThreatFields(_Section):
    # Set by indicator matching after parsing, never by parsers.
    matched: bool = False


class NormalizedEvent(BaseModel):
    """A parsed log record in the platform's common schema."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    timestamp: datetime
    log_source: LogSource
    event_hash: str = Field(pattern=_SHA256_HEX)
    raw_event: dict[str, Any]

    host: HostFields = Field(default_factory=HostFields)
    source: EndpointFields = Field(default_factory=EndpointFields)
    destination: EndpointFields = Field(default_factory=EndpointFields)
    user: UserFields = Field(default_factory=UserFields)
    event: EventFields = Field(default_factory=EventFields)
    process: ProcessFields = Field(default_factory=ProcessFields)
    url: UrlFields = Field(default_factory=UrlFields)
    http: HttpFields = Field(default_factory=HttpFields)
    user_agent: UserAgentFields = Field(default_factory=UserAgentFields)
    threat: ThreatFields = Field(default_factory=ThreatFields)
    message: str | None = None

    @field_validator("timestamp")
    @classmethod
    def _to_utc(cls, value: datetime) -> datetime:
        """Store every timestamp in UTC; naive values are assumed to be UTC already."""
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def get(self, spec: FieldSpec) -> Any:
        """Return the value of a registry field, converted to a plain Python type."""
        node: Any = self
        for part in spec.path:
            node = getattr(node, part)
            if node is None:
                return None
        if isinstance(node, IPv4Address | IPv6Address):
            return str(node)
        if isinstance(node, LogSource | EventCategory | EventOutcome):
            return node.value
        return node

    def flatten(self) -> dict[str, Any]:
        """Return ``{dotted_name: value}`` for every populated registry field."""
        flat: dict[str, Any] = {}
        for spec in FIELDS:
            value = self.get(spec)
            if value is not None:
                flat[spec.name] = value
        return flat

    def to_row(self) -> dict[str, Any]:
        """Return a dict ready for a bulk insert into the ``events`` table.

        Same values as :meth:`get` for every field, but with the attribute
        lookups prepared once: this runs for every event ingested.
        """
        row: dict[str, Any] = {}
        for column, getter in _ROW_GETTERS:
            value = getter(self)
            if isinstance(value, Enum):
                value = value.value
            elif isinstance(value, IPv4Address | IPv6Address):
                value = str(value)
            row[column] = value
        row["event_hash"] = self.event_hash
        row["raw_event"] = self.raw_event
        return row


# Every section of NormalizedEvent always exists, so dotted lookups never meet None.
_ROW_GETTERS = tuple((spec.column, attrgetter(".".join(spec.path))) for spec in FIELDS)
