"""Alerts raised by the detection engine and the events behind them."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Table,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import AlertStatus, Severity
from watchpost.db.types import IPAddress

if TYPE_CHECKING:
    from watchpost.db.models.case import Case
    from watchpost.db.models.event import Event
    from watchpost.db.models.rule import Rule
    from watchpost.db.models.user import User

# Evidence link between an alert and the events that triggered it. The worker
# caps how many events it links per alert so a noisy brute force cannot bloat
# this table; the full count lives in ``alerts.event_count``.
alert_events = Table(
    "alert_events",
    Base.metadata,
    Column(
        "alert_id",
        BigInteger,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "event_id",
        BigInteger,
        ForeignKey("events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_alert_events_event_id", "event_id"),
)

# Only open alerts take part in deduplication: a repeat hit for the same
# group key updates the open alert instead of creating a new one, while a
# closed alert lets the next hit start a fresh one.
OPEN_ALERT_STATUSES = (AlertStatus.NEW, AlertStatus.INVESTIGATING)


class Alert(TimestampMixin, Base):
    """A detection rule hit, possibly aggregating many matching events."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    rule_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("rules.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"))
    status: Mapped[AlertStatus] = mapped_column(
        str_enum(AlertStatus, "alert_status"),
        default=AlertStatus.NEW,
        server_default=AlertStatus.NEW,
    )
    group_key: Mapped[str] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    host_name: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(IPAddress)
    user_name: Mapped[str | None] = mapped_column(String(255))

    mitre_tactics: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), default=list, server_default=text("'{}'")
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), default=list, server_default=text("'{}'")
    )
    enrichment: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    case_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("cases.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rule: Mapped[Rule | None] = relationship(lazy="raise")
    assignee: Mapped[User | None] = relationship(lazy="raise")
    case: Mapped[Case | None] = relationship(back_populates="alerts", lazy="raise")
    events: Mapped[list[Event]] = relationship(secondary=alert_events, lazy="raise")

    __table_args__ = (
        Index(
            "uq_alerts_open_group_key",
            "group_key",
            unique=True,
            postgresql_where=text("status IN ('new', 'investigating')"),
        ),
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_last_seen", "last_seen"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_case_id", "case_id"),
        Index("ix_alerts_assignee_id", "assignee_id"),
        Index("ix_alerts_source_ip", "source_ip"),
        Index("ix_alerts_host_name", "host_name"),
        Index("ix_alerts_user_name", "user_name"),
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} rule={self.rule_id!r} status={self.status}>"
