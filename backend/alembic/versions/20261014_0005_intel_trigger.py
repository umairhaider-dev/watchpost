"""detection runs started by an indicator sweep

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-14 18:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_TRIGGERS = ("ingestion", "manual")
NEW_TRIGGERS = (*OLD_TRIGGERS, "intel")
CONSTRAINT = "ck_detection_runs_detection_trigger"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


def upgrade() -> None:
    op.drop_constraint(op.f(CONSTRAINT), "detection_runs", type_="check")
    op.create_check_constraint(op.f(CONSTRAINT), "detection_runs", _in("trigger", NEW_TRIGGERS))


def downgrade() -> None:
    op.execute("DELETE FROM detection_runs WHERE trigger = 'intel'")
    op.drop_constraint(op.f(CONSTRAINT), "detection_runs", type_="check")
    op.create_check_constraint(op.f(CONSTRAINT), "detection_runs", _in("trigger", OLD_TRIGGERS))
