"""Threat intelligence: the indicator store, feed imports and lookups.

Adding or importing indicators queues a sweep that matches them against
events already stored, so old activity is flagged and alerted on too.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from redis.exceptions import RedisError
from sqlalchemy import ColumnElement, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.api.deps import EnricherDep, QueueDep, SessionDep, SettingsDep
from watchpost.db.models import Event, Ioc, IocType, event_ioc_matches
from watchpost.intel.alerts import intel_verdict, local_intel
from watchpost.intel.enrichment import ProviderResult
from watchpost.intel.feeds import MAX_TAG_LENGTH, FeedEntry, FeedFormatError, parse_feed
from watchpost.intel.indicators import IndicatorError, normalize_indicator, refang
from watchpost.intel.providers import Verdict, shareable, worst
from watchpost.intel.store import delete_ioc, upsert_iocs
from watchpost.worker.queue import JobQueue

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intel", tags=["threat intelligence"])

FEED_IMPORT_PATH = "/api/intel/import"
MAX_FEED_BYTES = 20 * 1024 * 1024
MAX_MATCHES_SHOWN = 50
# Past this many indicators a sweep simply checks every active one.
MAX_SWEEP_IDS = 10_000
_NUL = bytes(1)


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------


def _clean_tags(tags: Sequence[str]) -> list[str]:
    return sorted({tag.strip().lower()[:MAX_TAG_LENGTH] for tag in tags if tag.strip()})


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ioc_type: IocType
    value: str
    source: str
    description: str | None
    confidence: int | None
    tags: list[str]
    is_active: bool
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    match_count: int = 0
    last_matched_at: datetime | None = None


class IocPage(BaseModel):
    items: list[IocOut]
    total: int


class IocMatchOut(BaseModel):
    event_id: int
    field: str
    matched_at: datetime
    timestamp: datetime
    log_source: str
    host_name: str | None
    source_ip: str | None
    user_name: str | None
    event_action: str | None
    message: str | None


class IocDetail(IocOut):
    matches: list[IocMatchOut]


class IocCreate(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    ioc_type: IocType | None = Field(
        default=None, description="Leave empty to detect the type from the value"
    )
    description: str | None = Field(default=None, max_length=2000)
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] = Field(default_factory=list, max_length=20)
    source: str = Field(default="manual", min_length=1, max_length=128)
    expires_at: datetime | None = None

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str]) -> list[str]:
        return _clean_tags(value)


class IocUpdate(BaseModel):
    """Fields to change; anything left out stays as it is."""

    is_active: bool | None = None
    description: str | None = Field(default=None, max_length=2000)
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] | None = Field(default=None, max_length=20)
    expires_at: datetime | None = None

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _clean_tags(value)

    @model_validator(mode="after")
    def _required_fields_not_null(self) -> IocUpdate:
        for name in ("is_active", "tags"):
            if name in self.model_fields_set and getattr(self, name) is None:
                msg = f"{name} cannot be null"
                raise ValueError(msg)
        return self


class FeedProblemOut(BaseModel):
    line: int
    reason: str
    excerpt: str


class ImportOut(BaseModel):
    filename: str
    source: str
    indicators: int
    created: int
    updated: int
    duplicates: int
    problem_count: int
    problems: list[FeedProblemOut]
    truncated: bool
    sweep_queued: bool


class SummaryOut(BaseModel):
    total: int
    active: int
    by_type: dict[str, int]
    matched_events: int
    indicators_matched: int


class ProviderStatusOut(BaseModel):
    name: str
    label: str
    configured: bool
    cooling_down: bool
    remaining: dict[str, int]


class ProvidersOut(BaseModel):
    online: bool
    cache_hours: int
    providers: list[ProviderStatusOut]


class ProviderResultOut(BaseModel):
    provider: str
    label: str
    status: str
    verdict: Verdict
    data: dict[str, Any]
    fetched_at: datetime | None
    cached: bool


class LookupOut(BaseModel):
    ioc_type: IocType
    value: str
    verdict: Verdict
    shared: bool
    online: bool
    intel: list[IocOut]
    providers: list[ProviderResultOut]


class SweepOut(BaseModel):
    queued: bool


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


async def _with_match_counts(session: AsyncSession, iocs: Sequence[Ioc]) -> list[IocOut]:
    """IOC models with how many events each matched, and when last."""
    ids = [ioc.id for ioc in iocs]
    counts: dict[int, tuple[int, datetime | None]] = {}
    if ids:
        rows = await session.execute(
            select(
                event_ioc_matches.c.ioc_id,
                func.count(func.distinct(event_ioc_matches.c.event_id)),
                func.max(event_ioc_matches.c.matched_at),
            )
            .where(event_ioc_matches.c.ioc_id.in_(ids))
            .group_by(event_ioc_matches.c.ioc_id)
        )
        counts = {ioc_id: (count, last) for ioc_id, count, last in rows}
    items = []
    for ioc in iocs:
        count, last = counts.get(ioc.id, (0, None))
        items.append(
            IocOut.model_validate(ioc).model_copy(
                update={"match_count": count, "last_matched_at": last}
            )
        )
    return items


async def _get_ioc(session: AsyncSession, ioc_id: int) -> Ioc:
    ioc = await session.get(Ioc, ioc_id)
    if ioc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found")
    return ioc


async def _queue_sweep(queue: JobQueue, ioc_ids: Sequence[int] | None) -> bool:
    """Queue a sweep; a queue outage is logged, not fatal (the indicators are saved)."""
    if ioc_ids is not None and len(ioc_ids) > MAX_SWEEP_IDS:
        ioc_ids = None
    try:
        await queue.enqueue_sweep(ioc_ids)
    except (RedisError, OSError) as exc:
        logger.warning("Could not queue an indicator sweep: %s", exc)
        return False
    return True


def _normalise(value: str, declared: IocType | None) -> tuple[IocType, str]:
    try:
        return normalize_indicator(value, declared, any_hash=False)
    except IndicatorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


# --------------------------------------------------------------------------
# Indicator store
# --------------------------------------------------------------------------


@router.get("/summary", response_model=SummaryOut)
async def intel_summary(session: SessionDep) -> dict[str, Any]:
    """Counts for the threat intelligence page header."""
    by_type = {
        ioc_type.value: count
        for ioc_type, count in await session.execute(
            select(Ioc.ioc_type, func.count()).group_by(Ioc.ioc_type)
        )
    }
    active = await session.scalar(
        select(func.count()).select_from(Ioc).where(Ioc.is_active.is_(True))
    )
    matched_events = await session.scalar(
        select(func.count()).select_from(Event).where(Event.ioc_matched.is_(True))
    )
    indicators_matched = await session.scalar(
        select(func.count(func.distinct(event_ioc_matches.c.ioc_id)))
    )
    return {
        "total": sum(by_type.values()),
        "active": active or 0,
        "by_type": by_type,
        "matched_events": matched_events or 0,
        "indicators_matched": indicators_matched or 0,
    }


@router.get("/iocs", response_model=IocPage)
async def list_iocs(
    session: SessionDep,
    q: Annotated[str | None, Query(max_length=512, description="Part of the value")] = None,
    ioc_type: Annotated[IocType | None, Query()] = None,
    source: Annotated[str | None, Query(max_length=128)] = None,
    active: Annotated[bool | None, Query()] = None,
    matched: Annotated[bool | None, Query(description="Only indicators seen in events")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Indicators, most recently changed first."""
    conditions: list[ColumnElement[bool]] = []
    if q and q.strip():
        needle = refang(q.strip())
        conditions.append(
            or_(
                Ioc.value.contains(needle.lower(), autoescape=True),
                Ioc.description.icontains(needle, autoescape=True),
            )
        )
    if ioc_type is not None:
        conditions.append(Ioc.ioc_type == ioc_type)
    if source:
        conditions.append(Ioc.source == source)
    if active is not None:
        conditions.append(Ioc.is_active.is_(active))
    if matched is not None:
        seen = exists().where(event_ioc_matches.c.ioc_id == Ioc.id)
        conditions.append(seen if matched else ~seen)
    iocs = list(
        await session.scalars(
            select(Ioc)
            .where(*conditions)
            .order_by(Ioc.updated_at.desc(), Ioc.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    total = await session.scalar(select(func.count()).select_from(Ioc).where(*conditions))
    return {"items": await _with_match_counts(session, iocs), "total": total or 0}


@router.post(
    "/iocs",
    response_model=IocOut,
    status_code=status.HTTP_201_CREATED,
    responses={200: {"description": "The indicator already existed and was updated"}},
)
async def add_ioc(
    body: IocCreate, session: SessionDep, queue: QueueDep, response: Response
) -> IocOut:
    """Add one indicator (or refresh it if it is already known)."""
    ioc_type, value = _normalise(body.value, body.ioc_type)
    entry = FeedEntry(
        line=0,
        ioc_type=ioc_type,
        value=value,
        description=body.description,
        confidence=body.confidence,
        tags=tuple(body.tags),
        source=body.source,
        expires_at=body.expires_at,
    )
    result = await upsert_iocs(session, [entry], source=body.source)
    await session.commit()
    [ioc_id] = result.ioc_ids
    if not result.created:
        response.status_code = status.HTTP_200_OK
    await _queue_sweep(queue, [ioc_id])
    ioc = await _get_ioc(session, ioc_id)
    await session.refresh(ioc)
    [out] = await _with_match_counts(session, [ioc])
    return out


@router.post(
    "/import",
    response_model=ImportOut,
    responses={
        413: {"description": "File larger than the import limit"},
        415: {"description": "Not a UTF-8 text file"},
        422: {"description": "The file is not a usable feed"},
    },
)
async def import_feed(
    session: SessionDep,
    queue: QueueDep,
    file: Annotated[UploadFile, File(description="TXT (one indicator per line) or CSV feed")],
    source: Annotated[str | None, Form(max_length=128)] = None,
    confidence: Annotated[int | None, Form(ge=0, le=100)] = None,
    tags: Annotated[str | None, Form(max_length=512, description="Comma-separated")] = None,
    expires_in_days: Annotated[int | None, Form(ge=1, le=3650)] = None,
) -> ImportOut:
    """Import a feed file into the indicator store and sweep stored events for it."""
    try:
        data = await file.read(MAX_FEED_BYTES + 1)
    finally:
        await file.close()
    if len(data) > MAX_FEED_BYTES:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE,
            f"feed files are limited to {MAX_FEED_BYTES // (1024 * 1024)} MiB",
        )
    if _NUL in data[:8192]:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "not a UTF-8 text file")
    filename = (file.filename or "feed.txt").replace("\\", "/").rsplit("/", 1)[-1][:255]
    try:
        feed = parse_feed(data, filename)
    except FeedFormatError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if not feed.entries and feed.problem_count:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"no usable indicators; first problem on line {feed.problems[0].line}: "
            f"{feed.problems[0].reason}",
        )

    source_name = (source or "").strip() or filename
    result = await upsert_iocs(
        session,
        feed.entries,
        source=source_name,
        default_confidence=confidence,
        extra_tags=(tags or "").split(","),
        expires_at=(
            datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None
        ),
    )
    await session.commit()
    swept = await _queue_sweep(queue, result.ioc_ids) if result.ioc_ids else False
    return ImportOut(
        filename=filename,
        source=source_name,
        indicators=len(feed.entries),
        created=result.created,
        updated=result.updated,
        duplicates=feed.duplicates,
        problem_count=feed.problem_count,
        problems=[
            FeedProblemOut(line=p.line, reason=p.reason, excerpt=p.excerpt) for p in feed.problems
        ],
        truncated=feed.truncated,
        sweep_queued=swept,
    )


@router.post("/sweep", response_model=SweepOut, status_code=status.HTTP_202_ACCEPTED)
async def sweep_all(queue: QueueDep) -> SweepOut:
    """Re-check every stored event against all active indicators."""
    if not await _queue_sweep(queue, None):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "job queue unavailable; try again shortly"
        )
    return SweepOut(queued=True)


@router.get("/iocs/{ioc_id}", response_model=IocDetail)
async def get_ioc(ioc_id: int, session: SessionDep) -> dict[str, Any]:
    """One indicator with the most recent events it matched."""
    ioc = await _get_ioc(session, ioc_id)
    [out] = await _with_match_counts(session, [ioc])
    rows = await session.execute(
        select(
            Event.id,
            event_ioc_matches.c.field,
            event_ioc_matches.c.matched_at,
            Event.timestamp,
            Event.log_source,
            Event.host_name,
            Event.source_ip,
            Event.user_name,
            Event.event_action,
            Event.message,
        )
        .join(event_ioc_matches, event_ioc_matches.c.event_id == Event.id)
        .where(event_ioc_matches.c.ioc_id == ioc_id)
        .order_by(Event.timestamp.desc(), Event.id.desc())
        .limit(MAX_MATCHES_SHOWN)
    )
    matches = [
        {
            "event_id": row.id,
            "field": row.field,
            "matched_at": row.matched_at,
            "timestamp": row.timestamp,
            "log_source": row.log_source,
            "host_name": row.host_name,
            "source_ip": row.source_ip,
            "user_name": row.user_name,
            "event_action": row.event_action,
            "message": row.message,
        }
        for row in rows
    ]
    return {**out.model_dump(), "matches": matches}


@router.patch("/iocs/{ioc_id}", response_model=IocOut)
async def update_ioc(ioc_id: int, body: IocUpdate, session: SessionDep, queue: QueueDep) -> IocOut:
    """Change an indicator. Reactivating it sweeps stored events for it again."""
    ioc = await _get_ioc(session, ioc_id)
    changes = body.model_dump(exclude_unset=True)
    reactivated = changes.get("is_active") is True and not ioc.is_active
    for name, value in changes.items():
        setattr(ioc, name, value)
    await session.commit()
    await session.refresh(ioc)
    if reactivated:
        await _queue_sweep(queue, [ioc.id])
    [out] = await _with_match_counts(session, [ioc])
    return out


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_ioc(ioc_id: int, session: SessionDep) -> None:
    """Delete an indicator; events it alone matched are no longer flagged."""
    if not await delete_ioc(session, ioc_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found")
    await session.commit()


# --------------------------------------------------------------------------
# Lookups
# --------------------------------------------------------------------------


@router.get("/lookup", response_model=LookupOut)
async def lookup(
    session: SessionDep,
    enricher: EnricherDep,
    value: Annotated[str, Query(min_length=1, max_length=2048)],
    ioc_type: Annotated[IocType | None, Query()] = None,
    refresh: Annotated[bool, Query(description="Ask providers even if cached")] = False,
) -> LookupOut:
    """What the local store and the configured providers know about one indicator."""
    kind, normalised = _normalise(value, ioc_type)
    matches = (await local_intel(session, [(kind, normalised)]))[kind, normalised]
    results: list[ProviderResult] = await enricher.lookup(kind, normalised, refresh=refresh)
    verdicts = [intel_verdict(ioc) for ioc in matches] + [result.verdict for result in results]
    return LookupOut(
        ioc_type=kind,
        value=normalised,
        verdict=worst(verdicts),
        shared=shareable(kind, normalised),
        online=enricher.online,
        intel=await _with_match_counts(session, matches),
        providers=[ProviderResultOut.model_validate(result.as_dict()) for result in results],
    )


@router.get("/providers", response_model=ProvidersOut)
async def providers(enricher: EnricherDep, settings: SettingsDep) -> ProvidersOut:
    """Which online providers are configured, and their remaining request budget."""
    return ProvidersOut(
        online=enricher.online,
        cache_hours=settings.enrichment_cache_hours,
        providers=[
            ProviderStatusOut(
                name=item.name,
                label=item.label,
                configured=item.configured,
                cooling_down=item.cooling_down,
                remaining=item.remaining,
            )
            for item in await enricher.status()
        ],
    )
