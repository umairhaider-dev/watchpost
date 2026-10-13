"""From a byte stream to rows in the ``events`` table.

:func:`parse_events` is a synchronous generator (parsing is CPU-bound) that
yields normalised events and records every malformed or skipped record in a
:class:`ParseStats`. :func:`insert_events` writes one batch with
``ON CONFLICT DO NOTHING`` on the event hash, so re-ingesting a file is safe
and the number of duplicates is exact.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Event
from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers import JsonParser, LineParser, Parser
from watchpost.ingestion.readers import (
    ByteStream,
    detect_json_layout,
    iter_json_records,
    iter_lines,
)

logger = logging.getLogger(__name__)

MAX_MALFORMED_SAMPLES = 100
EXCERPT_LENGTH = 300


@dataclass(frozen=True, slots=True)
class MalformedSample:
    """A record that could not be parsed, kept for the ingestion report."""

    line: int
    reason: str
    excerpt: str


@dataclass(slots=True)
class ParseStats:
    """Running totals for one file. ``records_read`` counts non-blank records."""

    records_read: int = 0
    events_parsed: int = 0
    malformed: int = 0
    skipped: int = 0
    samples: list[MalformedSample] = field(default_factory=list)

    def add_malformed(self, line: int, reason: str, text: str) -> None:
        self.malformed += 1
        if len(self.samples) < MAX_MALFORMED_SAMPLES:
            self.samples.append(MalformedSample(line, reason, text[:EXCERPT_LENGTH]))

    def samples_as_json(self) -> list[dict[str, Any]]:
        return [asdict(sample) for sample in self.samples]


def parse_events(
    stream: ByteStream, parser: Parser, stats: ParseStats
) -> Iterator[NormalizedEvent]:
    """Yield events parsed from ``stream``, updating ``stats`` as it goes."""
    for _number, event in parse_numbered_events(stream, parser, stats):
        yield event


def parse_numbered_events(
    stream: ByteStream, parser: Parser, stats: ParseStats
) -> Iterator[tuple[int, NormalizedEvent]]:
    """Like :func:`parse_events`, with each event's line (or record) number."""
    if isinstance(parser, LineParser):
        yield from _parse_lines(stream, parser, stats)
    elif isinstance(parser, JsonParser):
        yield from _parse_json(stream, parser, stats)
    else:  # pragma: no cover - every parser derives from one of the two
        msg = f"unsupported parser type: {type(parser).__name__}"
        raise TypeError(msg)


def _parse_lines(
    stream: ByteStream, parser: LineParser, stats: ParseStats
) -> Iterator[tuple[int, NormalizedEvent]]:
    for line in iter_lines(stream):
        stats.records_read += 1
        if line.truncated:
            stats.add_malformed(line.number, "line is too long", line.text)
            continue
        try:
            event = parser.parse_line(line.text)
        except ParseError as exc:
            stats.add_malformed(line.number, str(exc), line.text)
            continue
        if event is None:
            stats.skipped += 1
            continue
        stats.events_parsed += 1
        yield line.number, event


def _parse_json(
    stream: ByteStream, parser: JsonParser, stats: ParseStats
) -> Iterator[tuple[int, NormalizedEvent]]:
    peek = getattr(stream, "peek", None)
    head: bytes = peek(4096) if callable(peek) else b""
    for record in iter_json_records(stream, detect_json_layout(head)):
        stats.records_read += 1
        if record.value is None:
            stats.add_malformed(record.number, record.error or "invalid record", record.text)
            continue
        try:
            event = parser.parse_record(record.value)
        except ParseError as exc:
            stats.add_malformed(record.number, str(exc), record.text)
            continue
        if event is None:
            stats.skipped += 1
            continue
        stats.events_parsed += 1
        yield record.number, event


def take_rows(
    events: Iterator[NormalizedEvent], size: int, ingest_job_id: int | None = None
) -> list[dict[str, Any]]:
    """Pull up to ``size`` events and convert them to insert rows.

    Kept separate so the worker can run it in a thread while the event loop
    stays free for database I/O. ``ingest_job_id`` tags each row with the job
    that stored it, so detection can later scan exactly that job's events.
    """
    rows: list[dict[str, Any]] = []
    for event in events:
        row = event.to_row()
        row["ingest_job_id"] = ingest_job_id
        rows.append(row)
        if len(rows) >= size:
            break
    return rows


_INSERT_EVENTS = (
    pg_insert(Event).on_conflict_do_nothing(index_elements=[Event.event_hash]).returning(Event.id)
)


async def insert_events(session: AsyncSession, rows: Sequence[dict[str, Any]]) -> int:
    """Insert a batch, skipping events whose hash already exists.

    Returns:
        The number of rows actually inserted; the rest were duplicates.
    """
    if not rows:
        return 0
    result = await session.execute(_INSERT_EVENTS, list(rows))
    return len(result.all())
