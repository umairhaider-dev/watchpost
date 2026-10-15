"""The generated data set, end to end: every planted attack is caught, nothing else is."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.datagen import GeneratorConfig, generate
from watchpost.datagen.world import ATTACKER_ADDRESSES, BACKUP_USER, PHISHING_VICTIM
from watchpost.db.models import Alert, DetectionTrigger, Event, IngestionJob, IngestOrigin
from watchpost.detection.runner import create_run, execute_run
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.intel.feeds import parse_feed
from watchpost.intel.store import upsert_iocs

# Accounts and machines the attacks touch; every alert must involve one of them.
ATTACK_USERS = {
    BACKUP_USER.name,
    "svc-update",
    "administrator",
    "helpdesk-svc",
    PHISHING_VICTIM.name,
}
ATTACK_HOSTS = {
    "web-01",
    "DC01.corp.example.local",
    f"{PHISHING_VICTIM.workstation}.corp.example.local",
}


async def test_detection_finds_every_planted_attack_and_nothing_else(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    rules: None,
    tmp_path: Path,
) -> None:
    manifest = generate(
        GeneratorConfig(events=8_000, days=3, end=datetime(2026, 10, 14, tzinfo=UTC), seed=21),
        tmp_path,
    )
    feed = parse_feed((tmp_path / "iocs.csv").read_bytes(), "iocs.csv")
    await upsert_iocs(db_session, feed.entries, source="iocs.csv")
    for item in manifest.files:
        job = IngestionJob(
            origin=IngestOrigin.WATCH_FOLDER,
            filename=item.name,
            stored_path=str(tmp_path / item.name),
            parser="auto",
            file_size=item.size,
        )
        db_session.add(job)
        await db_session.flush()
        await run_ingestion_job(session_factory, app_settings, job.id)

    assert await db_session.scalar(select(func.count()).select_from(Event)) == 8_000

    run = await create_run(db_session, trigger=DetectionTrigger.MANUAL)
    await execute_run(session_factory, run.id)
    alerts = list(await db_session.scalars(select(Alert)))

    expected = {rule for scenario in manifest.scenarios for rule in scenario.rules}
    assert {alert.rule_id for alert in alerts} == expected
    unrelated = [
        (alert.rule_id, alert.host_name, alert.source_ip, alert.user_name)
        for alert in alerts
        if alert.source_ip not in ATTACKER_ADDRESSES
        and alert.user_name not in ATTACK_USERS
        and alert.host_name not in ATTACK_HOSTS
    ]
    assert unrelated == []
    new_sources = {
        alert.user_name: alert.source_ip
        for alert in alerts
        if alert.rule_id == "login-from-new-source-ip"
    }
    assert new_sources == {"backup": "203.0.113.45", "administrator": "203.0.113.80"}
