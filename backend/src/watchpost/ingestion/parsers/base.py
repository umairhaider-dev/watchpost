"""Parser interface and the helper every parser uses to build events."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar

from pydantic import ValidationError
from sqlalchemy import String

from watchpost.db.models import Event, LogSource
from watchpost.events import FIELDS, FIELDS_BY_NAME, NormalizedEvent, compute_event_hash
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.readers import Sample


class InputFormat(StrEnum):
    """How a parser expects its input to be split into records."""

    LINES = "lines"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Facts about the file being parsed that are not in the records themselves.

    ``reference_time`` anchors year-less syslog timestamps; ``default_host``
    fills ``host.name`` for formats that do not record it (web access logs).
    """

    reference_time: datetime
    default_host: str | None = None


class Parser(ABC):
    """Base class for all log format parsers."""

    name: ClassVar[str]
    label: ClassVar[str]
    description: ClassVar[str]
    input_format: ClassVar[InputFormat]

    def __init__(self, context: ParseContext) -> None:
        self.context = context

    @classmethod
    @abstractmethod
    def sniff(cls, sample: Sample) -> float:
        """Return a confidence between 0 and 1 that ``sample`` is in this format."""


class LineParser(Parser):
    """Parser for line-oriented text logs."""

    input_format: ClassVar[InputFormat] = InputFormat.LINES

    @abstractmethod
    def parse_line(self, line: str) -> NormalizedEvent | None:
        """Parse one line.

        Returns ``None`` for lines that are valid but carry no event (they are
        counted as skipped). Raises :class:`ParseError` for malformed lines.
        """


class JsonParser(Parser):
    """Parser for JSON records (JSON lines, arrays or concatenated objects)."""

    input_format: ClassVar[InputFormat] = InputFormat.JSON

    @abstractmethod
    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent | None:
        """Parse one JSON object; same contract as :meth:`LineParser.parse_line`."""


def canonical_json(record: Mapping[str, Any]) -> str:
    """Stable serialisation of a JSON record, used as its dedup "raw line".

    Sorting keys means the same event exported as JSON lines or inside a
    pretty-printed array produces the same hash.
    """
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


# Truncation limits come from the column definitions so they cannot drift.
_FIELD_LIMITS: dict[str, int] = {}
for _spec in FIELDS:
    _column_type = Event.__table__.c[_spec.column].type
    if isinstance(_column_type, String) and _column_type.length:
        _FIELD_LIMITS[_spec.name] = _column_type.length


def build_event(
    *,
    timestamp: datetime,
    log_source: LogSource,
    raw_line: str,
    raw_event: dict[str, Any],
    fields: Mapping[str, Any],
) -> NormalizedEvent:
    """Assemble and validate a :class:`NormalizedEvent` from dotted field names.

    ``fields`` uses registry names such as ``source.ip``; ``None`` values are
    ignored and over-long strings are truncated to their column size.

    Raises:
        ParseError: if the assembled event fails validation.
    """
    data: dict[str, Any] = {
        "timestamp": timestamp,
        "log_source": log_source,
        "event_hash": compute_event_hash(log_source, raw_line),
        "raw_event": raw_event,
    }
    for name, value in fields.items():
        if value is None:
            continue
        spec = FIELDS_BY_NAME[name]
        limit = _FIELD_LIMITS.get(name)
        too_long = limit is not None and isinstance(value, str) and len(value) > limit
        node = data
        for part in spec.path[:-1]:
            node = node.setdefault(part, {})
        node[spec.path[-1]] = value[:limit] if too_long else value
    try:
        return NormalizedEvent.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first["loc"])
        msg = f"invalid value for {location}: {first['msg']}"
        raise ParseError(msg) from exc
