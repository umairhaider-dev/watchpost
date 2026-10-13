"""detection: rule origin, new_value rules, event job link, detection runs

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-14 09:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_RULE_TYPES = ("match", "threshold", "sequence")
NEW_RULE_TYPES = (*OLD_RULE_TYPES, "new_value")
RULE_ORIGINS = ("builtin", "custom")
TRIGGERS = ("ingestion", "manual")
STATUSES = ("queued", "running", "completed", "failed")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_rules_rule_type"), "rules", type_="check")
    op.create_check_constraint(
        op.f("ck_rules_rule_type"), "rules", _in("rule_type", NEW_RULE_TYPES)
    )
    op.add_column(
        "rules",
        sa.Column("origin", sa.String(length=7), server_default="custom", nullable=False),
    )
    op.create_check_constraint(op.f("ck_rules_rule_origin"), "rules", _in("origin", RULE_ORIGINS))
    op.add_column(
        "rules",
        sa.Column("modified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.add_column("events", sa.Column("ingest_job_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        op.f("fk_events_ingest_job_id_ingestion_jobs"),
        "events",
        "ingestion_jobs",
        ["ingest_job_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_events_ingest_job_id", "events", ["ingest_job_id"])

    op.create_table(
        "detection_runs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("trigger", sa.String(length=9), nullable=False),
        sa.Column("status", sa.String(length=9), server_default="queued", nullable=False),
        sa.Column("ingest_job_id", sa.BigInteger(), nullable=True),
        sa.Column("rule_ids", postgresql.ARRAY(sa.String(length=64)), nullable=True),
        sa.Column("range_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("range_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("events_scanned", sa.Integer(), server_default="0", nullable=False),
        sa.Column("hits", sa.Integer(), server_default="0", nullable=False),
        sa.Column("alerts_created", sa.Integer(), server_default="0", nullable=False),
        sa.Column("alerts_updated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _in("trigger", TRIGGERS), name=op.f("ck_detection_runs_detection_trigger")
        ),
        sa.CheckConstraint(
            _in("status", STATUSES), name=op.f("ck_detection_runs_detection_status")
        ),
        sa.ForeignKeyConstraint(
            ["ingest_job_id"],
            ["ingestion_jobs.id"],
            name=op.f("fk_detection_runs_ingest_job_id_ingestion_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_detection_runs_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_runs")),
    )
    op.create_index("ix_detection_runs_created_at", "detection_runs", ["created_at"])
    op.create_index("ix_detection_runs_ingest_job_id", "detection_runs", ["ingest_job_id"])


def downgrade() -> None:
    op.drop_table("detection_runs")
    op.drop_index("ix_events_ingest_job_id", table_name="events")
    op.drop_constraint(op.f("fk_events_ingest_job_id_ingestion_jobs"), "events", type_="foreignkey")
    op.drop_column("events", "ingest_job_id")
    op.drop_column("rules", "modified")
    op.drop_constraint(op.f("ck_rules_rule_origin"), "rules", type_="check")
    op.drop_column("rules", "origin")
    op.execute("DELETE FROM rules WHERE rule_type = 'new_value'")
    op.drop_constraint(op.f("ck_rules_rule_type"), "rules", type_="check")
    op.create_check_constraint(
        op.f("ck_rules_rule_type"), "rules", _in("rule_type", OLD_RULE_TYPES)
    )
