"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-10-13 12:22:34

Enum-like columns are VARCHAR + CHECK rather than native PostgreSQL enums,
and their allowed values are spelled out here instead of imported from the
application, so this migration keeps describing the same schema even after
the Python enums change.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SEVERITIES = ("informational", "low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "investigating", "true_positive", "false_positive", "closed")
CASE_STATUSES = ("open", "in_progress", "resolved", "closed")
RULE_TYPES = ("match", "threshold", "sequence")
USER_ROLES = ("admin", "analyst", "viewer")
IOC_TYPES = ("ip", "domain", "md5", "sha1", "sha256")


def _one_of(table: str, column: str, values: Sequence[str], name: str) -> sa.CheckConstraint:
    allowed = ", ".join(f"'{value}'" for value in values)
    return sa.CheckConstraint(f"{column} IN ({allowed})", name=op.f(f"ck_{table}_{name}"))


def _timestamps() -> list[sa.Column[Any]]:
    return [
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
    ]


def _text_array(name: str, item_type: sa.types.TypeEngine[str]) -> sa.Column[Any]:
    return sa.Column(
        name, postgresql.ARRAY(item_type), server_default=sa.text("'{}'"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), sa.Identity(always=False), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("full_name", sa.String(length=128), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=7), server_default="viewer", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        _one_of("users", "role", USER_ROLES, "user_role"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("severity", sa.String(length=13), nullable=False),
        sa.Column("rule_type", sa.String(length=9), nullable=False),
        _text_array("mitre_tactics", sa.String(length=16)),
        _text_array("mitre_techniques", sa.String(length=16)),
        _text_array("false_positives", sa.Text()),
        _text_array("references", sa.Text()),
        sa.Column("definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_yaml", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        *_timestamps(),
        _one_of("rules", "severity", SEVERITIES, "severity"),
        _one_of("rules", "rule_type", RULE_TYPES, "rule_type"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rules")),
    )
    op.create_index("ix_rules_enabled", "rules", ["enabled"])
    op.create_index(
        "ix_rules_mitre_techniques", "rules", ["mitre_techniques"], postgresql_using="gin"
    )

    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("log_source", sa.String(length=32), nullable=False),
        sa.Column("host_name", sa.String(length=255), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("event_category", sa.String(length=32), nullable=True),
        sa.Column("event_action", sa.String(length=128), nullable=True),
        sa.Column("event_outcome", sa.String(length=16), nullable=True),
        sa.Column("event_code", sa.String(length=32), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("process_pid", sa.Integer(), nullable=True),
        sa.Column("process_executable", sa.Text(), nullable=True),
        sa.Column("process_command_line", sa.Text(), nullable=True),
        sa.Column("process_parent_name", sa.String(length=255), nullable=True),
        sa.Column("process_parent_pid", sa.Integer(), nullable=True),
        sa.Column("url_original", sa.Text(), nullable=True),
        sa.Column("http_method", sa.String(length=16), nullable=True),
        sa.Column("http_status_code", sa.SmallInteger(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("ioc_matched", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("raw_event", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events")),
        sa.UniqueConstraint("event_hash", name=op.f("uq_events_event_hash")),
    )
    op.create_index("ix_events_timestamp_id", "events", ["timestamp", "id"])
    op.create_index("ix_events_log_source_timestamp", "events", ["log_source", "timestamp"])
    op.create_index("ix_events_source_ip_timestamp", "events", ["source_ip", "timestamp"])
    op.create_index("ix_events_user_name_timestamp", "events", ["user_name", "timestamp"])
    op.create_index("ix_events_host_name_timestamp", "events", ["host_name", "timestamp"])
    op.create_index("ix_events_category_action", "events", ["event_category", "event_action"])
    op.create_index(
        "ix_events_ioc_matched",
        "events",
        ["timestamp"],
        postgresql_where=sa.text("ioc_matched"),
    )

    op.create_table(
        "iocs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("ioc_type", sa.String(length=6), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), server_default="manual", nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("confidence", sa.SmallInteger(), nullable=True),
        _text_array("tags", sa.String(length=64)),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        _one_of("iocs", "ioc_type", IOC_TYPES, "ioc_type"),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name=op.f("ck_iocs_confidence_range")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_iocs")),
        sa.UniqueConstraint("ioc_type", "value", name=op.f("uq_iocs_ioc_type_value")),
    )
    op.create_index("ix_iocs_value", "iocs", ["value"])

    op.create_table(
        "cases",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("severity", sa.String(length=13), nullable=False),
        sa.Column("status", sa.String(length=11), server_default="open", nullable=False),
        sa.Column("assignee_id", sa.Integer(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        _one_of("cases", "severity", SEVERITIES, "severity"),
        _one_of("cases", "status", CASE_STATUSES, "case_status"),
        sa.ForeignKeyConstraint(
            ["assignee_id"],
            ["users.id"],
            name=op.f("fk_cases_assignee_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_cases_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cases")),
    )
    op.create_index("ix_cases_status", "cases", ["status"])
    op.create_index("ix_cases_assignee_id", "cases", ["assignee_id"])
    op.create_index("ix_cases_created_at", "cases", ["created_at"])

    op.create_table(
        "case_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("case_id", sa.BigInteger(), nullable=False),
        sa.Column("author_id", sa.Integer(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_notes_case_id_cases"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_case_notes_author_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_notes")),
    )
    op.create_index("ix_case_notes_case_id_created_at", "case_notes", ["case_id", "created_at"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=13), nullable=False),
        sa.Column("status", sa.String(length=14), server_default="new", nullable=False),
        sa.Column("group_key", sa.String(length=512), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("host_name", sa.String(length=255), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        _text_array("mitre_tactics", sa.String(length=16)),
        _text_array("mitre_techniques", sa.String(length=16)),
        sa.Column(
            "enrichment",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("assignee_id", sa.Integer(), nullable=True),
        sa.Column("case_id", sa.BigInteger(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        _one_of("alerts", "severity", SEVERITIES, "severity"),
        _one_of("alerts", "status", ALERT_STATUSES, "alert_status"),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["rules.id"], name=op.f("fk_alerts_rule_id_rules"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["assignee_id"],
            ["users.id"],
            name=op.f("fk_alerts_assignee_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_alerts_case_id_cases"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    # Deduplication: at most one open alert per group key.
    op.create_index(
        "uq_alerts_open_group_key",
        "alerts",
        ["group_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('new', 'investigating')"),
    )
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])
    op.create_index("ix_alerts_last_seen", "alerts", ["last_seen"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_case_id", "alerts", ["case_id"])
    op.create_index("ix_alerts_assignee_id", "alerts", ["assignee_id"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_host_name", "alerts", ["host_name"])
    op.create_index("ix_alerts_user_name", "alerts", ["user_name"])

    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.BigInteger(), nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_events_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name=op.f("fk_alert_events_event_id_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id", name=op.f("pk_alert_events")),
    )
    op.create_index("ix_alert_events_event_id", "alert_events", ["event_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_audit_log_user_id_users"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])
    op.create_index("ix_audit_log_user_id_occurred_at", "audit_log", ["user_id", "occurred_at"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_target", "audit_log", ["target_type", "target_id"])


def downgrade() -> None:
    # Dropping a table drops its indexes and constraints with it.
    for table in (
        "audit_log",
        "alert_events",
        "alerts",
        "case_notes",
        "cases",
        "iocs",
        "events",
        "rules",
        "users",
    ):
        op.drop_table(table)
