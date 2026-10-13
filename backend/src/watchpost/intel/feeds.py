"""Reading indicator feeds from TXT and CSV files.

**TXT**: one indicator per line, type detected from the value. Blank lines
and lines starting with ``#``, ``;`` or ``//`` are skipped, as is anything
after a ``#`` on a line.

**CSV**: a header row is required. The indicator comes from a ``value``
(or ``indicator``, ``ioc``, ``observable``) column, or from a column named
after its type (``ip``, ``domain``, ``hash``). Optional columns:
``type``, ``description``, ``confidence`` (0-100 or low/medium/high),
``tags`` (separated by ``;`` or ``|``), ``source`` and ``expires``.
Unknown columns are ignored.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime

from watchpost.db.models import IocType
from watchpost.ingestion.values import parse_timestamp
from watchpost.intel.indicators import IndicatorError, normalize_indicator, parse_declared_type

MAX_FEED_ENTRIES = 200_000
MAX_PROBLEMS_KEPT = 100
_COMMENT_PREFIXES = ("#", ";", "//")
_VALUE_COLUMNS = ("value", "indicator", "ioc", "observable")
_TYPED_COLUMNS: dict[str, tuple[IocType | None, bool]] = {
    "ip": (IocType.IP, False),
    "ip_address": (IocType.IP, False),
    "domain": (IocType.DOMAIN, False),
    "hash": (None, True),
    "md5": (IocType.MD5, False),
    "sha1": (IocType.SHA1, False),
    "sha256": (IocType.SHA256, False),
}
_COLUMN_ALIASES = {
    "type": ("type", "ioc_type", "indicator_type", "kind"),
    "description": ("description", "comment", "notes", "threat", "malware"),
    "confidence": ("confidence", "score"),
    "tags": ("tags", "labels"),
    "source": ("source", "feed"),
    "expires": ("expires", "expires_at", "valid_until", "expiration"),
}
_CONFIDENCE_WORDS = {"low": 30, "medium": 60, "high": 90}


@dataclass(frozen=True, slots=True)
class FeedEntry:
    line: int
    ioc_type: IocType
    value: str
    description: str | None = None
    confidence: int | None = None
    tags: tuple[str, ...] = ()
    source: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class FeedProblem:
    line: int
    reason: str
    excerpt: str


@dataclass(slots=True)
class ParsedFeed:
    entries: list[FeedEntry] = field(default_factory=list)
    problems: list[FeedProblem] = field(default_factory=list)
    problem_count: int = 0
    duplicates: int = 0
    truncated: bool = False

    def add_problem(self, line: int, reason: str, excerpt: str) -> None:
        self.problem_count += 1
        if len(self.problems) < MAX_PROBLEMS_KEPT:
            self.problems.append(FeedProblem(line, reason, excerpt[:200]))


class FeedFormatError(ValueError):
    """The file as a whole cannot be read as a feed (e.g. a CSV without an indicator column)."""


def parse_feed(data: bytes, filename: str) -> ParsedFeed:
    """Parse a TXT or CSV feed. CSV is chosen by extension or a recognisable header."""
    text = data.decode("utf-8-sig", errors="replace")
    if filename.lower().endswith(".csv") or _looks_like_csv(text):
        return _deduplicate(_parse_csv(text))
    return _deduplicate(_parse_txt(text))


def _looks_like_csv(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        header = {cell.strip().lower() for cell in stripped.split(",")}
        return bool(header & (set(_VALUE_COLUMNS) | set(_TYPED_COLUMNS)))
    return False


def _parse_txt(text: str) -> ParsedFeed:
    feed = ParsedFeed()
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        token = stripped.split("#", 1)[0].strip().split()
        if not token:
            continue
        if len(feed.entries) >= MAX_FEED_ENTRIES:
            feed.truncated = True
            break
        try:
            ioc_type, value = normalize_indicator(token[0])
        except IndicatorError as exc:
            feed.add_problem(number, str(exc), stripped)
            continue
        feed.entries.append(FeedEntry(line=number, ioc_type=ioc_type, value=value))
    return feed


def _column(header: list[str], kind: str) -> str | None:
    for alias in _COLUMN_ALIASES[kind]:
        if alias in header:
            return alias
    return None


def _parse_csv(text: str) -> ParsedFeed:
    lines = [line for line in text.splitlines() if not line.strip().startswith(("#", "//"))]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    header = [name.strip().lower() for name in (reader.fieldnames or [])]
    reader.fieldnames = header
    value_column = next((name for name in _VALUE_COLUMNS if name in header), None)
    typed_column = next((name for name in _TYPED_COLUMNS if name in header), None)
    if value_column is None and typed_column is None:
        msg = f"the CSV has no indicator column; expected one of: {', '.join(_VALUE_COLUMNS)}"
        raise FeedFormatError(msg)
    columns = {kind: _column(header, kind) for kind in _COLUMN_ALIASES}

    feed = ParsedFeed()
    for row in reader:
        number = reader.line_num
        raw_value = (row.get(value_column or "") or row.get(typed_column or "") or "").strip()
        excerpt = ",".join(str(cell) for cell in row.values() if cell is not None)
        if not raw_value:
            feed.add_problem(number, "missing indicator value", excerpt)
            continue
        if len(feed.entries) >= MAX_FEED_ENTRIES:
            feed.truncated = True
            break
        try:
            entry = _csv_entry(number, raw_value, row, columns, value_column, typed_column)
        except (IndicatorError, ValueError) as exc:
            feed.add_problem(number, str(exc), excerpt)
            continue
        feed.entries.append(entry)
    return feed


def _csv_entry(
    number: int,
    raw_value: str,
    row: dict[str, str | None],
    columns: dict[str, str | None],
    value_column: str | None,
    typed_column: str | None,
) -> FeedEntry:
    def cell(kind: str) -> str | None:
        name = columns[kind]
        value = row.get(name) if name else None
        return value.strip() if value and value.strip() else None

    declared: IocType | None = None
    any_hash = False
    if value_column is None and typed_column is not None:
        declared, any_hash = _TYPED_COLUMNS[typed_column]
    else:
        known, declared = parse_declared_type(cell("type"))
        if not known:
            msg = f"unknown indicator type {cell('type')!r}"
            raise IndicatorError(msg)
        any_hash = declared is None and (cell("type") or "").lower() in {
            "hash",
            "filehash",
            "file_hash",
        }
    ioc_type, value = normalize_indicator(raw_value, declared, any_hash=any_hash)

    confidence = None
    if (raw_confidence := cell("confidence")) is not None:
        confidence = _confidence(raw_confidence)
    expires_at = None
    if (raw_expires := cell("expires")) is not None:
        try:
            expires_at = parse_timestamp(raw_expires)
        except ValueError as exc:
            msg = f"invalid expiry date {raw_expires!r}"
            raise ValueError(msg) from exc
    tags = tuple(
        sorted(
            {
                tag.strip().lower()
                for tag in (cell("tags") or "").replace("|", ";").split(";")
                if tag.strip()
            }
        )
    )
    return FeedEntry(
        line=number,
        ioc_type=ioc_type,
        value=value,
        description=cell("description"),
        confidence=confidence,
        tags=tags,
        source=cell("source"),
        expires_at=expires_at,
    )


def _confidence(text: str) -> int:
    lowered = text.lower()
    if lowered in _CONFIDENCE_WORDS:
        return _CONFIDENCE_WORDS[lowered]
    try:
        number = round(float(lowered))
    except ValueError as exc:
        msg = f"confidence {text!r} is not a number from 0 to 100"
        raise ValueError(msg) from exc
    if not 0 <= number <= 100:
        msg = f"confidence {text!r} is not a number from 0 to 100"
        raise ValueError(msg)
    return number


def _deduplicate(feed: ParsedFeed) -> ParsedFeed:
    """Keep the last entry for each (type, value); a feed may repeat itself."""
    latest: dict[tuple[IocType, str], FeedEntry] = {}
    for entry in feed.entries:
        latest[(entry.ioc_type, entry.value)] = entry
    feed.duplicates = len(feed.entries) - len(latest)
    feed.entries = list(latest.values())
    return feed
