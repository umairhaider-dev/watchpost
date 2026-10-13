"""Threat intelligence: indicator matches on events and cached enrichment lookups."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    String,
    Table,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, str_enum
from watchpost.db.models.enums import EnrichmentStatus, IocType

# Which indicator matched which event, and in which field. ``events.ioc_matched``
# is the fast flag for filtering; this table says why it is set.
event_ioc_matches = Table(
    "event_ioc_matches",
    Base.metadata,
    Column(
        "event_id",
        BigInteger,
        ForeignKey("events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "ioc_id",
        BigInteger,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("field", String(64), primary_key=True),
    Column(
        "matched_at",
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    ),
    Index("ix_event_ioc_matches_ioc_id", "ioc_id"),
)


class EnrichmentCache(Base):
    """A provider's answer about one indicator, kept until ``expires_at``."""

    __tablename__ = "enrichment_cache"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32))
    indicator_type: Mapped[IocType] = mapped_column(str_enum(IocType, "ioc_type"))
    indicator: Mapped[str] = mapped_column(String(512))
    status: Mapped[EnrichmentStatus] = mapped_column(
        str_enum(EnrichmentStatus, "enrichment_status")
    )
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("provider", "indicator_type", "indicator"),)

    def __repr__(self) -> str:
        return f"<EnrichmentCache {self.provider} {self.indicator_type}={self.indicator!r}>"
