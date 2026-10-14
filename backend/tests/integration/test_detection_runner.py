from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import (
    Alert,
    AlertStatus,
    DetectionRun,
    DetectionStatus,
    DetectionTrigger,
    IngestionJob,
    IngestOrigin,
    Rule,
    Severity,
    alert_events,
)
from watchpost.detection.runner import Scope, create_run, execute_run
from watchpost.detection.store import sync_builtin_rules
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.intel.feeds import parse_feed
from watchpost.intel.store import upsert_iocs

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples"
RULES_DIR = ROOT / "backend" / "rules"
SAMPLE_FILES = (
    "auth.log",
    "access.log",
    "windows_security.jsonl",
    "sysmon.json",
    "app_events.jsonl",
    "malformed_lines.log",
)


async def ingest(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    path: Path,
) -> int:
    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename=path.name,
        stored_path=str(path),
        parser="auto",
        file_size=path.stat().st_size,
    )
    db_session.add(job)
    await db_session.flush()
    await run_ingestion_job(session_factory, settings, job.id)
    return job.id


async def ingest_sample(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    name: str,
) -> int:
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    target = settings.upload_dir / name
    shutil.copy(SAMPLES / name, target)
    return await ingest(db_session, session_factory, settings, target)


async def detect_job(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession], job_id: int
) -> DetectionRun:
    run = await create_run(db_session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job_id)
    await execute_run(session_factory, run.id)
    await db_session.refresh(run)
    return run


async def alerts_by_rule(session: AsyncSession) -> dict[str, list[Alert]]:
    found: dict[str, list[Alert]] = {}
    for alert in await session.scalars(select(Alert).order_by(Alert.id)):
        await session.refresh(alert)
        found.setdefault(alert.rule_id or "", []).append(alert)
    return found


async def evidence_count(session: AsyncSession, alert_id: int) -> int:
    count = await session.scalar(
        select(func.count()).select_from(alert_events).where(alert_events.c.alert_id == alert_id)
    )
    return count or 0


def write_log(directory: Path, name: str, lines: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def failures(start_second: int, count: int, ip: str = "203.0.113.99", hour: int = 15) -> list[str]:
    return [
        f"Oct 12 {hour}:{(start_second + n) // 60:02d}:{(start_second + n) % 60:02d} web-01 "
        f"sshd[{5000 + start_second + n}]: Failed password for root from {ip} port {50000 + n} ssh2"
        for n in range(count)
    ]


# ------------------------------------------------------------------ end to end


@pytest.mark.usefixtures("rules")
async def test_samples_raise_an_alert_for_every_builtin_rule(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    feed = parse_feed((SAMPLES / "iocs.csv").read_bytes(), "iocs.csv")
    await upsert_iocs(db_session, feed.entries, source="iocs.csv")
    runs = []
    for name in SAMPLE_FILES:
        job_id = await ingest_sample(db_session, session_factory, app_settings, name)
        runs.append(await detect_job(db_session, session_factory, job_id))

    alerts = await alerts_by_rule(db_session)
    rule_ids = set(await db_session.scalars(select(Rule.id)))

    assert all(run.status is DetectionStatus.COMPLETED for run in runs)
    assert set(alerts) == rule_ids
    assert sum(run.alerts_created for run in runs) == sum(len(group) for group in alerts.values())

    [brute_force] = alerts["ssh-brute-force"]
    assert brute_force.title == "SSH brute force: 203.0.113.45"
    assert brute_force.source_ip == "203.0.113.45"
    assert brute_force.severity is Severity.MEDIUM
    assert brute_force.status is AlertStatus.NEW
    assert brute_force.mitre_techniques == ["T1110.001"]
    assert brute_force.event_count == 10
    assert await evidence_count(db_session, brute_force.id) == 10

    [new_ip] = alerts["login-from-new-source-ip"]
    assert new_ip.user_name == "backup"
    assert new_ip.title == "Login from a new source address: backup, 203.0.113.45"

    # The admin group change is logged twice (group and shadow group): one alert.
    [admin_group] = alerts["linux-user-added-to-admin-group"]
    assert admin_group.event_count == 2

    # Encoded PowerShell appears in both Security 4688 and Sysmon 1 on different hosts.
    assert len(alerts["windows-encoded-powershell"]) == 2


@pytest.mark.usefixtures("rules")
async def test_rerunning_detection_creates_no_duplicates(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    job_id = await ingest_sample(db_session, session_factory, app_settings, "auth.log")
    first = await detect_job(db_session, session_factory, job_id)
    counts = {
        alert.id: alert.event_count
        for group in (await alerts_by_rule(db_session)).values()
        for alert in group
    }

    second = await detect_job(db_session, session_factory, job_id)

    after = {
        alert.id: alert.event_count
        for group in (await alerts_by_rule(db_session)).values()
        for alert in group
    }
    assert first.alerts_created > 0
    assert second.alerts_created == 0
    assert second.alerts_updated == first.alerts_created
    assert after == counts


@pytest.mark.usefixtures("rules")
async def test_manual_time_range_run_matches_job_runs(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    job_id = await ingest_sample(db_session, session_factory, app_settings, "access.log")
    run = await create_run(db_session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job_id)
    by_job = await execute_run(session_factory, run.id)
    assert by_job is not None

    manual = await create_run(
        db_session,
        trigger=DetectionTrigger.MANUAL,
        start=datetime(2026, 10, 12, tzinfo=UTC),
        end=datetime(2026, 10, 13, tzinfo=UTC),
    )
    again = await execute_run(session_factory, manual.id)
    await db_session.refresh(manual)

    assert manual.events_scanned == 44
    assert manual.alerts_created == 0
    assert manual.alerts_updated == len(by_job.changed_alert_ids) > 0
    # Same events, no new evidence: nothing needs enriching again.
    assert again is not None and again.changed_alert_ids == []


@pytest.mark.usefixtures("rules")
async def test_closed_alert_lets_new_activity_open_a_new_alert(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    first_job = await ingest(
        db_session,
        session_factory,
        app_settings,
        write_log(app_settings.upload_dir, "one.log", failures(0, 12)),
    )
    await detect_job(db_session, session_factory, first_job)
    [alert] = (await alerts_by_rule(db_session))["ssh-brute-force"]
    alert.status = AlertStatus.CLOSED
    await db_session.flush()

    second_job = await ingest(
        db_session,
        session_factory,
        app_settings,
        write_log(app_settings.upload_dir, "two.log", failures(0, 12, hour=18)),
    )
    await detect_job(db_session, session_factory, second_job)

    brute_force = (await alerts_by_rule(db_session))["ssh-brute-force"]
    assert [a.status for a in brute_force] == [AlertStatus.CLOSED, AlertStatus.NEW]


@pytest.mark.usefixtures("rules")
async def test_brute_force_split_across_two_uploads_is_detected(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    first_job = await ingest(
        db_session,
        session_factory,
        app_settings,
        write_log(app_settings.upload_dir, "part1.log", failures(0, 5)),
    )
    first = await detect_job(db_session, session_factory, first_job)
    assert "ssh-brute-force" not in await alerts_by_rule(db_session)

    second_job = await ingest(
        db_session,
        session_factory,
        app_settings,
        write_log(app_settings.upload_dir, "part2.log", failures(5, 5)),
    )
    await detect_job(db_session, session_factory, second_job)

    [alert] = (await alerts_by_rule(db_session))["ssh-brute-force"]
    assert alert.event_count == 10
    assert first.events_scanned == 5


async def test_run_with_selected_rules_ignores_the_rest(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await sync_builtin_rules(db_session, RULES_DIR)
    (await db_session.get(Rule, "linux-user-created")).enabled = False  # type: ignore[union-attr]
    await db_session.flush()
    job_id = await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    run = await create_run(
        db_session,
        trigger=DetectionTrigger.MANUAL,
        ingest_job_id=job_id,
        rule_ids=["ssh-brute-force", "linux-user-created"],
    )
    await execute_run(session_factory, run.id)

    # Explicitly chosen rules run even when disabled.
    assert set(await alerts_by_rule(db_session)) == {"ssh-brute-force", "linux-user-created"}

    default = await detect_job(db_session, session_factory, job_id)
    assert "linux-user-created" in await alerts_by_rule(db_session)
    assert default.alerts_updated == 1  # linux-user-created is skipped this time


async def test_broken_rules_are_skipped_and_reported(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    await sync_builtin_rules(db_session, RULES_DIR)
    (await db_session.get(Rule, "ssh-brute-force")).source_yaml = "id: ssh-brute-force\n"  # type: ignore[union-attr]
    await db_session.flush()
    job_id = await ingest_sample(db_session, session_factory, app_settings, "auth.log")

    run = await detect_job(db_session, session_factory, job_id)

    assert run.status is DetectionStatus.COMPLETED
    assert run.error == "skipped rules that failed to compile: ssh-brute-force"
    assert "ssh-brute-force" not in await alerts_by_rule(db_session)


async def test_failures_are_recorded_on_the_run(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def explode(*_: object) -> None:
        msg = "boom"
        raise RuntimeError(msg)

    monkeypatch.setattr("watchpost.detection.runner.detect", explode)
    run = await create_run(db_session, trigger=DetectionTrigger.MANUAL)

    outcome = await execute_run(session_factory, run.id)
    assert outcome is not None and outcome.status is DetectionStatus.FAILED
    await db_session.refresh(run)
    assert run.status is DetectionStatus.FAILED
    assert run.error == "detection failed; see worker logs"


async def test_missing_and_finished_runs_are_skipped(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    run = await create_run(db_session, trigger=DetectionTrigger.MANUAL)
    run.status = DetectionStatus.COMPLETED
    await db_session.flush()

    assert await execute_run(session_factory, run.id) is None
    assert await execute_run(session_factory, 999_999) is None


@pytest.mark.usefixtures("rules")
async def test_empty_scope_completes_without_alerts(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    run = await create_run(
        db_session,
        trigger=DetectionTrigger.MANUAL,
        start=datetime(2001, 1, 1, tzinfo=UTC),
        end=datetime(2001, 1, 2, tzinfo=UTC),
    )

    outcome = await execute_run(session_factory, run.id)
    assert outcome is not None and outcome.status is DetectionStatus.COMPLETED
    await db_session.refresh(run)
    assert (run.events_scanned, run.hits, run.alerts_created) == (0, 0, 0)


def test_scope_membership() -> None:
    by_job = Scope(ingest_job_id=7)
    by_time = Scope(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC))
    inside = {"ingest_job_id": 7, "timestamp": datetime(2026, 1, 1, 12, tzinfo=UTC)}
    outside = {"ingest_job_id": 8, "timestamp": datetime(2026, 2, 1, tzinfo=UTC)}

    assert by_job.contains(inside) and not by_job.contains(outside)
    assert by_time.contains(inside) and not by_time.contains(outside)
    assert Scope().contains(outside)
