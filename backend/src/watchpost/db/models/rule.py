"""Detection rules."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Boolean, Index, Integer, String, Text, text, true
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import RuleType, Severity


class Rule(TimestampMixin, Base):
    """A detection rule loaded from YAML.

    ``source_yaml`` is the text an analyst edits; ``definition`` is the parsed
    and validated form the detection engine evaluates.
    """

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"))
    rule_type: Mapped[RuleType] = mapped_column(str_enum(RuleType, "rule_type"))
    mitre_tactics: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), default=list, server_default=text("'{}'")
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), default=list, server_default=text("'{}'")
    )
    false_positives: Mapped[list[str]] = mapped_column(
        ARRAY(Text), default=list, server_default=text("'{}'")
    )
    references: Mapped[list[str]] = mapped_column(
        ARRAY(Text), default=list, server_default=text("'{}'")
    )
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    source_yaml: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    __table_args__ = (
        Index("ix_rules_enabled", "enabled"),
        Index("ix_rules_mitre_techniques", "mitre_techniques", postgresql_using="gin"),
    )

    def __repr__(self) -> str:
        return f"<Rule id={self.id!r} type={self.rule_type} enabled={self.enabled}>"
