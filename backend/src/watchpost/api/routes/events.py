"""Searching stored events, newest first.

Events are filtered with the query language in :mod:`watchpost.search`
(``user.name:root AND event.outcome:failure``) and a time range.
Pagination is keyset-based on ``(timestamp, id)``, which the
``ix_events_timestamp_id`` index serves directly, so page 1000 is as fast
as page 1. The cursor is opaque to clients.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, tuple_

from watchpost.api.deps import SessionDep
from watchpost.db.models import Event, Ioc, IocType, LogSource, event_ioc_matches
from watchpost.search import QueryError, compile_query

router = APIRouter(prefix="/events", tags=["events"])


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    ingested_at: datetime
    log_source: str
    host_name: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    user_name: str | None
    event_category: str | None
    event_action: str | None
    event_outcome: str | None
    event_code: str | None
    process_name: str | None
    process_pid: int | None
    process_executable: str | None
    process_command_line: str | None
    process_parent_name: str | None
    process_parent_pid: int | None
    url_original: str | None
    http_method: str | None
    http_status_code: int | None
    user_agent: str | None
    message: str | None
    ioc_matched: bool
    raw_event: dict[str, Any]


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None


class EventIndicatorOut(BaseModel):
    """A stored indicator that matched an event, and the field it matched in."""

    ioc_id: int
    ioc_type: IocType
    value: str
    field: str
    source: str
    description: str | None
    confidence: int | None
    tags: list[str]
    is_active: bool


def encode_cursor(event: Event) -> str:
    raw = f"{event.timestamp.isoformat()}|{event.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        timestamp, _, event_id = base64.urlsafe_b64decode(padded).decode().partition("|")
        return datetime.fromisoformat(timestamp), int(event_id)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid cursor") from exc


@router.get("", response_model=EventPage)
async def list_events(
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    q: Annotated[
        str | None,
        Query(
            max_length=2000,
            description="Search query, e.g. user.name:root AND NOT source.ip:10.0.0.0/8",
        ),
    ] = None,
    start: Annotated[datetime | None, Query(description="Events at or after")] = None,
    end: Annotated[datetime | None, Query(description="Events before")] = None,
    log_source: LogSource | None = None,
    ioc_matched: Annotated[
        bool | None, Query(description="Only events that matched a threat indicator")
    ] = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    """Events matching the query and time range, newest first."""
    query = select(Event).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit + 1)
    if q:
        try:
            condition = compile_query(q)
        except QueryError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
        if condition is not None:
            query = query.where(condition)
    if start is not None:
        query = query.where(Event.timestamp >= start)
    if end is not None:
        query = query.where(Event.timestamp < end)
    if log_source is not None:
        query = query.where(Event.log_source == log_source.value)
    if ioc_matched is not None:
        query = query.where(Event.ioc_matched.is_(ioc_matched))
    if cursor:
        timestamp, event_id = decode_cursor(cursor)
        query = query.where(tuple_(Event.timestamp, Event.id) < tuple_(timestamp, event_id))
    events = list(await session.scalars(query))
    next_cursor = encode_cursor(events[limit - 1]) if len(events) > limit else None
    return {"items": events[:limit], "next_cursor": next_cursor}


@router.get("/{event_id}/indicators", response_model=list[EventIndicatorOut])
async def event_indicators(event_id: int, session: SessionDep) -> list[dict[str, Any]]:
    """The threat indicators an event matched."""
    if await session.get(Event, event_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    rows = await session.execute(
        select(Ioc, event_ioc_matches.c.field)
        .join(event_ioc_matches, event_ioc_matches.c.ioc_id == Ioc.id)
        .where(event_ioc_matches.c.event_id == event_id)
        .order_by(Ioc.id, event_ioc_matches.c.field)
    )
    return [
        {
            "ioc_id": ioc.id,
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "field": field,
            "source": ioc.source,
            "description": ioc.description,
            "confidence": ioc.confidence,
            "tags": ioc.tags,
            "is_active": ioc.is_active,
        }
        for ioc, field in rows
    ]
