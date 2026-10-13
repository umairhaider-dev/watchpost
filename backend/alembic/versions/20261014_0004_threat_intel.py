"""threat intel: indicator matches on events and an enrichment cache

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-14 15:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

IOC_TYPES = ("ip", "domain", "md5", "sha1", "sha256")
ENRICHMENT_STATUSES = ("ok", "not_found", "error")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


def upgrade() -> None:
    op.create_table(
        "event_ioc_matches",
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("ioc_id", sa.BigInteger(), nullable=False),
        sa.Column("field", sa.String(length=64), nullable=False),
        sa.Column(
            "matched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name=op.f("fk_event_ioc_matches_event_id_events"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["ioc_id"],
            ["iocs.id"],
            name=op.f("fk_event_ioc_matches_ioc_id_iocs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id", "ioc_id", "field", name=op.f("pk_event_ioc_matches")),
    )
    op.create_index("ix_event_ioc_matches_ioc_id", "event_ioc_matches", ["ioc_id"])

    op.create_table(
        "enrichment_cache",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("indicator_type", sa.String(length=6), nullable=False),
        sa.Column("indicator", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=9), nullable=False),
        sa.Column(
            "data",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            _in("indicator_type", IOC_TYPES), name=op.f("ck_enrichment_cache_ioc_type")
        ),
        sa.CheckConstraint(
            _in("status", ENRICHMENT_STATUSES), name=op.f("ck_enrichment_cache_enrichment_status")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrichment_cache")),
        sa.UniqueConstraint(
            "provider",
            "indicator_type",
            "indicator",
            name=op.f("uq_enrichment_cache_provider_indicator_type_indicator"),
        ),
    )


def downgrade() -> None:
    op.drop_table("enrichment_cache")
    op.drop_table("event_ioc_matches")
