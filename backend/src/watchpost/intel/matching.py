"""Matching events against the indicator store.

Indicators are pulled out of an event row (``events`` columns plus
``raw_event``) from these places:

* IPs: ``source.ip`` and ``destination.ip``
* domains: the host of an absolute ``url.original``; Sysmon ``QueryName``
  (DNS) and ``DestinationHostname`` (network); and ECS-style ``domain``,
  ``dns.question.name``, ``url.domain`` and ``destination.domain`` fields
  in JSON records. A domain indicator also matches its subdomains.
* hashes: Sysmon's ``Hashes`` field (``SHA256=...,MD5=...``) and
  ``file.hash.*`` / ``md5`` / ``sha1`` / ``sha256`` fields in JSON records.

Matching happens twice: as events are ingested, and in a sweep over stored
events whenever indicators are imported, so old activity is flagged too.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.db.models import Event, Ioc, IocType, event_ioc_matches
from watchpost.db.streaming import stream_rows
from watchpost.detection.fields import EventRow
from watchpost.ingestion.values import clean_ip
from watchpost.intel.indicators import HASH_TYPES, normalize_domain, parent_domains

logger = logging.getLogger(__name__)

_EVENT_DATA_DOMAINS = ("QueryName", "DestinationHostname")
_ORIGINAL_DOMAINS = (
    ("domain",),
    ("dns", "question", "name"),
    ("url", "domain"),
    ("destination", "domain"),
)
_EVENT_DATA_HASHES = ("Hashes", "Hash")
_ORIGINAL_HASHES = (
    ("file", "hash", "sha256"),
    ("file", "hash", "sha1"),
    ("file", "hash", "md5"),
    ("sha256",),
    ("sha1",),
    ("md5",),
)
_HASH_TYPES_BY_LENGTH = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}


@dataclass(frozen=True, slots=True)
class Observed:
    """An indicator seen in an event, and the field it was found in."""

    ioc_type: IocType
    value: str
    field: str


def _dig(node: Any, path: tuple[str, ...]) -> Any:
    for part in path:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _hashes(text: str, field_name: str) -> list[Observed]:
    """Typed digests from ``SHA256=ABC,MD5=DEF`` or a bare digest."""
    found = []
    for part in text.split(","):
        digest = part.split("=", 1)[-1].strip().lower()
        hash_type = _HASH_TYPES_BY_LENGTH.get(len(digest))
        if hash_type and all(char in "0123456789abcdef" for char in digest):
            found.append(Observed(hash_type, digest, field_name))
    return found


def _host_indicator(host: str, field_name: str) -> Observed | None:
    ip = clean_ip(host)
    if ip is not None:
        return Observed(IocType.IP, ip, field_name)
    domain = normalize_domain(host)
    return Observed(IocType.DOMAIN, domain, field_name) if domain else None


def _from_columns(row: EventRow) -> list[Observed]:
    found: list[Observed] = []
    for field_name, column in (("source.ip", "source_ip"), ("destination.ip", "destination_ip")):
        if value := row.get(column):
            found.append(Observed(IocType.IP, str(value), field_name))
    url = row.get("url_original")
    if isinstance(url, str) and "://" in url:
        host = urlsplit(url).hostname
        if host and (observed := _host_indicator(host, "url.original")):
            found.append(observed)
    return found


def _from_event_data(event_data: dict[str, Any]) -> list[Observed]:
    found: list[Observed] = []
    for key in _EVENT_DATA_DOMAINS:
        value = event_data.get(key)
        if isinstance(value, str) and (observed := _host_indicator(value, key)):
            found.append(observed)
    for key in _EVENT_DATA_HASHES:
        value = event_data.get(key)
        if isinstance(value, str):
            found.extend(_hashes(value, key))
    return found


def _from_original(original: dict[str, Any]) -> list[Observed]:
    found: list[Observed] = []
    for path in _ORIGINAL_DOMAINS:
        value = _dig(original, path)
        if isinstance(value, str) and (domain := normalize_domain(value)):
            found.append(Observed(IocType.DOMAIN, domain, ".".join(path)))
    for path in _ORIGINAL_HASHES:
        value = _dig(original, path)
        if isinstance(value, str):
            found.extend(_hashes(value, ".".join(path)))
    return found


def extract_indicators(row: EventRow) -> list[Observed]:
    """Every IP, domain and hash in an event that could match an indicator."""
    found = _from_columns(row)
    raw = row.get("raw_event")
    if not isinstance(raw, dict):
        return found
    event_data = raw.get("event_data")
    if isinstance(event_data, dict):
        # Windows records: the original export shape varies, event_data does not.
        found.extend(_from_event_data(event_data))
    elif isinstance(raw.get("original"), dict):
        found.extend(_from_original(raw["original"]))
    return found


@dataclass(slots=True)
class IndicatorIndex:
    """Active indicators held in memory for fast lookups."""

    ips: dict[str, int] = field(default_factory=dict)
    domains: dict[str, int] = field(default_factory=dict)
    hashes: dict[str, int] = field(default_factory=dict)  # any hash type; lengths never collide

    @property
    def empty(self) -> bool:
        return not (self.ips or self.domains or self.hashes)

    @property
    def size(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes)

    def add(self, ioc_id: int, ioc_type: IocType, value: str) -> None:
        if ioc_type is IocType.IP:
            self.ips[value] = ioc_id
        elif ioc_type is IocType.DOMAIN:
            self.domains[value] = ioc_id
        elif ioc_type in HASH_TYPES:
            self.hashes[value] = ioc_id

    @classmethod
    async def load(
        cls, session: AsyncSession, ioc_ids: Sequence[int] | None = None
    ) -> IndicatorIndex:
        """Active, unexpired indicators (optionally only the given ones)."""
        query = select(Ioc.id, Ioc.ioc_type, Ioc.value).where(
            Ioc.is_active.is_(True),
            or_(Ioc.expires_at.is_(None), Ioc.expires_at > datetime.now(UTC)),
        )
        if ioc_ids is not None:
            query = query.where(Ioc.id.in_(ioc_ids))
        index = cls()
        for ioc_id, ioc_type, value in await session.execute(query):
            index.add(ioc_id, ioc_type, value)
        return index

    def match(self, row: EventRow) -> list[tuple[int, str]]:
        """``(ioc_id, field)`` for every indicator the event contains."""
        matches: list[tuple[int, str]] = []
        for observed in extract_indicators(row):
            ioc_id: int | None = None
            if observed.ioc_type is IocType.IP:
                ioc_id = self.ips.get(observed.value)
            elif observed.ioc_type is IocType.DOMAIN:
                ioc_id = next(
                    (
                        self.domains[candidate]
                        for candidate in parent_domains(observed.value)
                        if candidate in self.domains
                    ),
                    None,
                )
            else:
                ioc_id = self.hashes.get(observed.value)
            if ioc_id is not None and (ioc_id, observed.field) not in matches:
                matches.append((ioc_id, observed.field))
        return matches

    def annotate(self, rows: Sequence[dict[str, Any]]) -> dict[str, list[tuple[int, str]]]:
        """Flag matching rows (``ioc_matched``) before insert; returns matches by event hash."""
        found: dict[str, list[tuple[int, str]]] = {}
        if self.empty:
            return found
        for row in rows:
            matches = self.match(row)
            if matches:
                row["ioc_matched"] = True
                found[row["event_hash"]] = matches
        return found


async def link_matches(session: AsyncSession, links: Sequence[tuple[int, int, str]]) -> int:
    """Record ``(event_id, ioc_id, field)`` matches; returns how many were new."""
    if not links:
        return 0
    result = await session.execute(
        pg_insert(event_ioc_matches)
        .values([{"event_id": e, "ioc_id": i, "field": f} for e, i, f in links])
        .on_conflict_do_nothing()
        .returning(event_ioc_matches.c.event_id)
    )
    return len(result.all())


@dataclass(slots=True)
class SweepResult:
    events_scanned: int = 0
    events_matched: int = 0
    new_links: int = 0
    first: datetime | None = None
    last: datetime | None = None


async def sweep_events(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    ioc_ids: Sequence[int] | None = None,
    since: datetime | None = None,
) -> SweepResult:
    """Match stored events against indicators and record new matches.

    ``first``/``last`` span the events that gained a match, so the caller can
    run detection over just that period.
    """
    async with session_factory() as session:
        index = await IndicatorIndex.load(session, ioc_ids)
    result = SweepResult()
    if index.empty:
        return result

    query = select(Event.__table__)
    if since is not None:
        query = query.where(Event.__table__.c.timestamp >= since)
    links: list[tuple[int, int, str]] = []
    matched: dict[int, datetime] = {}
    async for rows in stream_rows(session_factory, query):
        result.events_scanned += len(rows)
        for row in rows:
            for ioc_id, field_name in index.match(row):
                links.append((row["id"], ioc_id, field_name))
                matched[row["id"]] = row["timestamp"]

    if not links:
        return result
    async with session_factory() as session:
        for start in range(0, len(links), 5_000):
            result.new_links += await link_matches(session, links[start : start + 5_000])
        ids = list(matched)
        for start in range(0, len(ids), 5_000):
            await session.execute(
                update(Event)
                .where(Event.id.in_(ids[start : start + 5_000]))
                .values(ioc_matched=True)
            )
        await session.commit()
    result.events_matched = len(matched)
    result.first = min(matched.values())
    result.last = max(matched.values())
    logger.info(
        "Indicator sweep: %d events scanned against %d indicators, %d matched (%d new links)",
        result.events_scanned,
        index.size,
        result.events_matched,
        result.new_links,
    )
    return result
