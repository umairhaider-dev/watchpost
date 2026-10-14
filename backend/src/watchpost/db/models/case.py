"""Investigation cases, their notes and the events pinned to them as evidence."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import CaseStatus, Severity

if TYPE_CHECKING:
    from watchpost.db.models.alert import Alert
    from watchpost.db.models.event import Event
    from watchpost.db.models.user import User


class Case(TimestampMixin, Base):
    """A unit of investigation grouping related alerts."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"))
    status: Mapped[CaseStatus] = mapped_column(
        str_enum(CaseStatus, "case_status"),
        default=CaseStatus.OPEN,
        server_default=CaseStatus.OPEN,
    )
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolution: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id], lazy="raise")
    created_by: Mapped[User | None] = relationship(foreign_keys=[created_by_id], lazy="raise")
    alerts: Mapped[list[Alert]] = relationship(back_populates="case", lazy="raise")
    notes: Mapped[list[CaseNote]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CaseNote.created_at",
        lazy="raise",
    )
    evidence: Mapped[list[CaseEvidence]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CaseEvidence.created_at",
        lazy="raise",
    )

    __table_args__ = (
        Index("ix_cases_status", "status"),
        Index("ix_cases_assignee_id", "assignee_id"),
        Index("ix_cases_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Case id={self.id} status={self.status} title={self.title!r}>"


class CaseNote(TimestampMixin, Base):
    """A free-text note an analyst adds to a case."""

    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    case_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("cases.id", ondelete="CASCADE"))
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text)

    case: Mapped[Case] = relationship(back_populates="notes", lazy="raise")
    author: Mapped[User | None] = relationship(lazy="raise")

    __table_args__ = (Index("ix_case_notes_case_id_created_at", "case_id", "created_at"),)

    def __repr__(self) -> str:
        return f"<CaseNote id={self.id} case_id={self.case_id}>"


class CaseEvidence(TimestampMixin, Base):
    """An event pinned to a case, with the analyst's note on why it matters."""

    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    case_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("cases.id", ondelete="CASCADE"))
    event_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("events.id", ondelete="CASCADE"))
    note: Mapped[str | None] = mapped_column(Text)
    added_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    case: Mapped[Case] = relationship(back_populates="evidence", lazy="raise")
    event: Mapped[Event] = relationship(lazy="raise")
    added_by: Mapped[User | None] = relationship(lazy="raise")

    __table_args__ = (
        UniqueConstraint("case_id", "event_id"),
        Index("ix_case_evidence_event_id", "event_id"),
    )

    def __repr__(self) -> str:
        return f"<CaseEvidence case_id={self.case_id} event_id={self.event_id}>"
