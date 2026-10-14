"""Normalised security events.

This is the largest table by far, so the column set is deliberately flat:
every field the detection engine and search filter on is a real column with
an index where it pays for itself, and the untouched original record lives in
``raw_event`` (JSONB) for anything the normalised schema does not cover.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    false,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base
from watchpost.db.types import IPAddress


class Event(Base):
    """A single log record mapped onto the ECS-inspired normalised schema."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    log_source: Mapped[str] = mapped_column(String(32))

    host_name: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(IPAddress)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(IPAddress)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    user_name: Mapped[str | None] = mapped_column(String(255))

    event_category: Mapped[str | None] = mapped_column(String(32))
    event_action: Mapped[str | None] = mapped_column(String(128))
    event_outcome: Mapped[str | None] = mapped_column(String(16))
    event_code: Mapped[str | None] = mapped_column(String(32))

    process_name: Mapped[str | None] = mapped_column(String(255))
    process_pid: Mapped[int | None] = mapped_column(Integer)
    process_executable: Mapped[str | None] = mapped_column(Text)
    process_command_line: Mapped[str | None] = mapped_column(Text)
    process_parent_name: Mapped[str | None] = mapped_column(String(255))
    process_parent_pid: Mapped[int | None] = mapped_column(Integer)

    url_original: Mapped[str | None] = mapped_column(Text)
    http_method: Mapped[str | None] = mapped_column(String(16))
    http_status_code: Mapped[int | None] = mapped_column(SmallInteger)
    user_agent: Mapped[str | None] = mapped_column(Text)

    message: Mapped[str | None] = mapped_column(Text)
    ioc_matched: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # The job that first stored this event; detection runs scan exactly these.
    ingest_job_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_jobs.id", ondelete="SET NULL")
    )

    __table_args__ = (
        # (timestamp, id) gives stable keyset pagination for the event search.
        Index("ix_events_timestamp_id", "timestamp", "id"),
        Index("ix_events_log_source_timestamp", "log_source", "timestamp"),
        Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),
        Index("ix_events_destination_ip_timestamp", "destination_ip", "timestamp"),
        Index("ix_events_user_name_timestamp", "user_name", "timestamp"),
        Index("ix_events_host_name_timestamp", "host_name", "timestamp"),
        Index("ix_events_category_action", "event_category", "event_action"),
        Index("ix_events_ingest_job_id", "ingest_job_id"),
        Index(
            "ix_events_ioc_matched",
            "timestamp",
            postgresql_where=text("ioc_matched"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Event id={self.id} source={self.log_source} "
            f"action={self.event_action!r} at={self.timestamp.isoformat()}>"
        )
