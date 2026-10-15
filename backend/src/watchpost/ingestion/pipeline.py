"""From a byte stream to rows in the ``events`` table.

:func:`parse_events` is a synchronous generator (parsing is CPU-bound) that
yields normalised events and records every malformed or skipped record in a
:class:`ParseStats`. :func:`insert_events` writes one batch: it copies the
rows into a temporary table with ``COPY`` and moves them into ``events`` with
``ON CONFLICT DO NOTHING`` on the event hash, so re-ingesting a file is safe
and the number of duplicates is exact.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import text
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


# Every column the ingestion pipeline fills; ``id`` and ``ingested_at`` come from the database.
_COLUMNS: tuple[str, ...] = tuple(
    column.name for column in Event.__table__.columns if column.name not in {"id", "ingested_at"}
)
_COLUMN_LIST = ", ".join(_COLUMNS)
_STAGE = "event_stage"
# The statements below are built from the table definition only; row values
# always travel separately through COPY.
_CREATE_STAGE = text(
    f"CREATE TEMPORARY TABLE IF NOT EXISTS {_STAGE} AS "  # noqa: S608
    f"SELECT {_COLUMN_LIST} FROM events WITH NO DATA"
)
_MOVE_STAGED = text(
    f"INSERT INTO events ({_COLUMN_LIST}) SELECT {_COLUMN_LIST} FROM {_STAGE} "  # noqa: S608
    "ON CONFLICT (event_hash) DO NOTHING RETURNING id, event_hash"
)
# Temporary tables are never vacuumed, so the stage is truncated, not deleted from.
_CLEAR_STAGE = text(f"TRUNCATE {_STAGE}")


def _copy_record(row: dict[str, Any]) -> tuple[Any, ...]:
    record = []
    for column in _COLUMNS:
        value = row.get(column)
        if column == "raw_event":
            value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        elif column == "ioc_matched":
            value = bool(value)
        record.append(value)
    return tuple(record)


async def insert_events(
    session: AsyncSession, rows: Sequence[dict[str, Any]]
) -> list[tuple[int, str]]:
    """Insert a batch, skipping events whose hash already exists.

    ``COPY`` into a per-connection temporary table followed by one
    ``INSERT ... SELECT`` is several times faster than a multi-row ``INSERT``
    and keeps the deduplication on the event hash. Everything happens inside
    the session's transaction.

    Returns:
        ``(id, event_hash)`` for the rows actually inserted; the rest were duplicates.
    """
    if not rows:
        return []
    # Going through the session first also starts its transaction on the connection.
    await session.execute(_CREATE_STAGE)
    connection = await session.connection()
    raw = await connection.get_raw_connection()
    driver = raw.driver_connection
    if driver is None:  # pragma: no cover - the pool hands out open connections
        msg = "the database connection is closed"
        raise RuntimeError(msg)
    # COPY is specific to the driver: asyncpg's copy_records_to_table.
    await driver.copy_records_to_table(
        _STAGE, records=[_copy_record(row) for row in rows], columns=_COLUMNS
    )
    result = await session.execute(_MOVE_STAGED)
    stored = [(int(event_id), str(event_hash)) for event_id, event_hash in result]
    await session.execute(_CLEAR_STAGE)
    return stored
