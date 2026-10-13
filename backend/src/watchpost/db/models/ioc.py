"""Indicators of compromise (local threat intelligence store)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Identity,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import IocType


class Ioc(TimestampMixin, Base):
    """A known-bad IP address, domain or file hash.

    ``value`` is stored in canonical form (lower-case hashes and domains,
    normalised IP text) so lookups are simple equality checks.
    """

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    ioc_type: Mapped[IocType] = mapped_column(str_enum(IocType, "ioc_type"))
    value: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(128), default="manual", server_default="manual")
    description: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int | None] = mapped_column(SmallInteger)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), default=list, server_default=text("'{}'")
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("ioc_type", "value"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence_range"),
        Index("ix_iocs_value", "value"),
    )

    def __repr__(self) -> str:
        return f"<Ioc id={self.id} {self.ioc_type}={self.value!r}>"
