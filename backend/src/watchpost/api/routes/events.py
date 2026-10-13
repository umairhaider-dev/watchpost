"""Browsing stored events, newest first.

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
from watchpost.db.models import Event, LogSource

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
    log_source: LogSource | None = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> dict[str, Any]:
    """Newest events first, optionally filtered by log source."""
    query = select(Event).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit + 1)
    if log_source is not None:
        query = query.where(Event.log_source == log_source.value)
    if cursor:
        timestamp, event_id = decode_cursor(cursor)
        query = query.where(tuple_(Event.timestamp, Event.id) < tuple_(timestamp, event_id))
    events = list(await session.scalars(query))
    next_cursor = encode_cursor(events[limit - 1]) if len(events) > limit else None
    return {"items": events[:limit], "next_cursor": next_cursor}
