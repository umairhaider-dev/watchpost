"""ingestion jobs

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-13 14:05:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ORIGINS = ("upload", "watch_folder")
STATUSES = ("queued", "running", "completed", "failed")


def _one_of(column: str, values: Sequence[str], name: str) -> sa.CheckConstraint:
    allowed = ", ".join(f"'{value}'" for value in values)
    return sa.CheckConstraint(f"{column} IN ({allowed})", name=op.f(f"ck_ingestion_jobs_{name}"))


def _counter(name: str, type_: sa.types.TypeEngine[int] | None = None) -> sa.Column[int]:
    return sa.Column(name, type_ or sa.Integer(), server_default="0", nullable=False)


def upgrade() -> None:
    op.create_table(
        "ingestion_jobs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("origin", sa.String(length=12), nullable=False),
        sa.Column("status", sa.String(length=9), server_default="queued", nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("stored_path", sa.Text(), nullable=False),
        sa.Column("parser", sa.String(length=32), nullable=False),
        sa.Column("detected_parser", sa.String(length=32), nullable=True),
        sa.Column("host_name", sa.String(length=255), nullable=True),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("file_sha256", sa.String(length=64), nullable=True),
        sa.Column("watch_fingerprint", sa.String(length=64), nullable=True),
        _counter("bytes_processed", sa.BigInteger()),
        _counter("records_read"),
        _counter("events_inserted"),
        _counter("events_duplicate"),
        _counter("records_malformed"),
        _counter("records_skipped"),
        sa.Column(
            "malformed_samples",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
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
        _one_of("origin", ORIGINS, "ingest_origin"),
        _one_of("status", STATUSES, "ingest_status"),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_ingestion_jobs_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ingestion_jobs")),
        sa.UniqueConstraint("watch_fingerprint", name=op.f("uq_ingestion_jobs_watch_fingerprint")),
    )
    op.create_index("ix_ingestion_jobs_status", "ingestion_jobs", ["status"])
    op.create_index("ix_ingestion_jobs_created_at", "ingestion_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_table("ingestion_jobs")
