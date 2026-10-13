"""Ingestion jobs: one row per uploaded or watched file."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import IngestOrigin, IngestStatus


class IngestionJob(TimestampMixin, Base):
    """Progress and outcome of ingesting one file.

    The counters always add up: ``records_read`` equals inserted + duplicate +
    malformed + skipped once the job has finished.
    """

    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    origin: Mapped[IngestOrigin] = mapped_column(str_enum(IngestOrigin, "ingest_origin"))
    status: Mapped[IngestStatus] = mapped_column(
        str_enum(IngestStatus, "ingest_status"),
        default=IngestStatus.QUEUED,
        server_default=IngestStatus.QUEUED,
    )
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(Text)
    parser: Mapped[str] = mapped_column(String(32))
    detected_parser: Mapped[str | None] = mapped_column(String(32))
    host_name: Mapped[str | None] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(BigInteger)
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    # Hash of path, size and mtime: lets the folder watcher pick up each
    # version of a file exactly once.
    watch_fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True)

    bytes_processed: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    records_read: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    events_inserted: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    events_duplicate: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_malformed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_skipped: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    malformed_samples: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    error: Mapped[str | None] = mapped_column(Text)

    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_ingestion_jobs_status", "status"),
        Index("ix_ingestion_jobs_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<IngestionJob id={self.id} file={self.filename!r} status={self.status}>"
