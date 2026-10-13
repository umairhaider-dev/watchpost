"""Detection runs: one row per pass of the rules over a set of events."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Identity, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import DetectionStatus, DetectionTrigger


class DetectionRun(TimestampMixin, Base):
    """Rules evaluated over the events of one ingestion job or one time range.

    ``rule_ids`` is ``None`` for "every enabled rule".
    """

    __tablename__ = "detection_runs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    trigger: Mapped[DetectionTrigger] = mapped_column(
        str_enum(DetectionTrigger, "detection_trigger")
    )
    status: Mapped[DetectionStatus] = mapped_column(
        str_enum(DetectionStatus, "detection_status"),
        default=DetectionStatus.QUEUED,
        server_default=DetectionStatus.QUEUED,
    )
    ingest_job_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("ingestion_jobs.id", ondelete="SET NULL")
    )
    rule_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(64)))
    range_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    range_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    events_scanned: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    hits: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    alerts_created: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    alerts_updated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)

    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_detection_runs_created_at", "created_at"),
        Index("ix_detection_runs_ingest_job_id", "ingest_job_id"),
    )

    def __repr__(self) -> str:
        return f"<DetectionRun id={self.id} trigger={self.trigger} status={self.status}>"
