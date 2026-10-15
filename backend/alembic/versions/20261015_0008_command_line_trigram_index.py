"""Trigram index on events.process_command_line for substring searches

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-15 15:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # pg_trgm is a trusted extension, so the database owner may create it.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index(
        "ix_events_command_line_trgm",
        "events",
        ["process_command_line"],
        postgresql_using="gin",
        postgresql_ops={"process_command_line": "gin_trgm_ops"},
    )


def downgrade() -> None:
    op.drop_index("ix_events_command_line_trgm", table_name="events")
    # The extension is left installed: other objects may have come to rely on it.
