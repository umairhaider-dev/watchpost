from __future__ import annotations

from typing import Any

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection, inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.conftest import run_alembic
from watchpost.db.base import Base

HEAD_REVISION = "0006"

EXPECTED_TABLES = {
    "alembic_version",
    "alert_events",
    "alerts",
    "audit_log",
    "case_evidence",
    "case_notes",
    "cases",
    "detection_runs",
    "enrichment_cache",
    "event_ioc_matches",
    "events",
    "ingestion_jobs",
    "iocs",
    "rules",
    "users",
}


def _diff_against_models(connection: Connection) -> list[Any]:
    context = MigrationContext.configure(connection, opts={"compare_type": True})
    return list(compare_metadata(context, Base.metadata))


async def test_migrations_create_every_table(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sync: set(inspect(sync).get_table_names()))

    assert tables == EXPECTED_TABLES


async def test_migrations_match_models(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        diff = await conn.run_sync(_diff_against_models)

    assert diff == []


async def test_downgrade_and_upgrade_round_trip(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(run_alembic, "downgrade", "base")
        remaining = await conn.run_sync(lambda sync: set(inspect(sync).get_table_names()))
        assert remaining == {"alembic_version"}

        await conn.run_sync(run_alembic, "upgrade", "head")
        version = await conn.scalar(text("SELECT version_num FROM alembic_version"))

    assert version == HEAD_REVISION


async def test_event_indexes_exist(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        indexes = await conn.run_sync(
            lambda sync: {index["name"] for index in inspect(sync).get_indexes("events")}
        )

    assert {
        "ix_events_timestamp_id",
        "ix_events_source_ip_timestamp",
        "ix_events_destination_ip_timestamp",
        "ix_events_user_name_timestamp",
        "ix_events_host_name_timestamp",
        "ix_events_log_source_timestamp",
        "ix_events_ioc_matched",
    } <= indexes
