from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_alert, make_event, store_events
from watchpost.dashboard import DashboardRange, build_dashboard
from watchpost.db.models import (
    AlertStatus,
    Case,
    CaseStatus,
    IngestionJob,
    IngestOrigin,
    IngestStatus,
    Ioc,
    IocType,
    Severity,
)

NOW = datetime(2026, 10, 14, 12, 30, tzinfo=UTC)


def ago(**delta: float) -> datetime:
    return NOW - timedelta(**delta)


async def seed(session: AsyncSession) -> None:
    alerts = [
        # Two brute-force alerts from the same address in the last day.
        make_alert(
            rule_id="ssh-brute-force",
            severity=Severity.MEDIUM,
            first_seen=ago(hours=3),
            last_seen=ago(hours=2),
            event_count=12,
            source_ip="203.0.113.45",
            user_name="root",
        ),
        make_alert(
            rule_id="ssh-brute-force",
            severity=Severity.MEDIUM,
            status=AlertStatus.TRUE_POSITIVE,
            first_seen=ago(hours=30),
            last_seen=ago(hours=29),
            event_count=10,
            source_ip="203.0.113.45",
            user_name="root",
            created_at=ago(hours=29),
            resolved_at=ago(hours=27),
        ),
        make_alert(
            rule_id="sysmon-lsass-memory-access",
            severity=Severity.CRITICAL,
            first_seen=ago(days=2),
            last_seen=ago(days=2),
            event_count=1,
            source_ip=None,
            user_name="carol",
        ),
        make_alert(
            rule_id="web-sql-injection",
            severity=Severity.HIGH,
            status=AlertStatus.FALSE_POSITIVE,
            first_seen=ago(days=3),
            last_seen=ago(days=3),
            event_count=4,
            source_ip="198.51.100.23",
            user_name=None,
            created_at=ago(days=3),
            resolved_at=ago(days=3) + timedelta(hours=4),
        ),
        # Outside the 7-day window.
        make_alert(
            rule_id="web-sql-injection",
            severity=Severity.HIGH,
            first_seen=ago(days=20),
            last_seen=ago(days=20),
            source_ip="198.51.100.23",
        ),
    ]
    session.add_all(alerts)
    session.add_all(
        [
            IngestionJob(
                origin=IngestOrigin.UPLOAD,
                filename=f"file-{n}.log",
                stored_path="unused",
                parser="auto",
                file_size=1,
                status=IngestStatus.COMPLETED,
                events_inserted=events,
                started_at=finished - timedelta(seconds=seconds),
                finished_at=finished,
            )
            for n, (events, seconds, finished) in enumerate(
                [(1000, 2, ago(hours=5)), (3000, 4, ago(days=1, hours=1)), (500, 1, ago(days=40))]
            )
        ]
        + [
            IngestionJob(
                origin=IngestOrigin.UPLOAD,
                filename="broken.log",
                stored_path="unused",
                parser="auto",
                file_size=1,
                status=IngestStatus.FAILED,
                events_inserted=50,
                finished_at=ago(hours=1),
            )
        ]
    )
    session.add_all(
        [
            Case(
                title="Resolved in two hours",
                severity=Severity.MEDIUM,
                status=CaseStatus.RESOLVED,
                created_at=ago(days=1),
                resolved_at=ago(days=1) + timedelta(hours=2),
            ),
            Case(
                title="Resolved in six hours",
                severity=Severity.HIGH,
                status=CaseStatus.CLOSED,
                created_at=ago(days=2),
                resolved_at=ago(days=2) + timedelta(hours=6),
                closed_at=ago(days=1),
            ),
            Case(title="Still open", severity=Severity.LOW, status=CaseStatus.IN_PROGRESS),
        ]
    )
    session.add(Ioc(ioc_type=IocType.IP, value="203.0.113.45", source="test"))
    await session.flush()
    await store_events(session, make_event("one"), make_event("two"))


@pytest.mark.usefixtures("rules")
async def test_week_dashboard(db_session: AsyncSession) -> None:
    await seed(db_session)

    board = await build_dashboard(db_session, DashboardRange.WEEK, now=NOW)

    assert board.bucket_seconds == 6 * 3600
    assert board.start == NOW - timedelta(days=7)
    assert board.totals == {
        "alerts": 4,
        "open_alerts": 3,
        "new_alerts": 3,
        "unassigned_open_alerts": 3,
        "open_cases": 1,
        "events": 2,
    }
    series = board.alerts_over_time
    assert len(series) == 29
    assert series[-1]["bucket"] == datetime(2026, 10, 14, 12, tzinfo=UTC)
    assert sum(bucket["medium"] for bucket in series) == 2
    assert sum(bucket["critical"] for bucket in series) == 1
    assert [(row["severity"], row["count"], row["open"]) for row in board.alerts_by_severity] == [
        (Severity.CRITICAL, 1, 1),
        (Severity.HIGH, 1, 0),
        (Severity.MEDIUM, 2, 1),
        (Severity.LOW, 0, 0),
        (Severity.INFORMATIONAL, 0, 0),
    ]
    ips = board.top_source_ips
    assert [(ip.value, ip.alerts, ip.events, ip.known_bad) for ip in ips] == [
        ("203.0.113.45", 2, 22, True),
        ("198.51.100.23", 1, 4, False),
    ]
    assert [(user.value, user.alerts) for user in board.top_users] == [("root", 2), ("carol", 1)]
    assert [(rule.rule_id, rule.alerts) for rule in board.top_rules] == [
        ("ssh-brute-force", 2),
        ("sysmon-lsass-memory-access", 1),
        ("web-sql-injection", 1),
    ]
    assert board.top_rules[0].title == "SSH brute force"

    ingestion = board.ingestion
    assert (ingestion["events_ingested"], ingestion["jobs"]) == (4000, 2)
    assert ingestion["events_per_second"] == pytest.approx(4000 / 6)
    assert sum(bucket["events"] for bucket in ingestion["series"]) == 4000

    assert board.case_resolution.resolved == 2
    assert board.case_resolution.mean_seconds == pytest.approx(4 * 3600)
    assert board.case_resolution.median_seconds == pytest.approx(4 * 3600)
    assert board.alert_resolution.resolved == 2
    assert board.alert_resolution.mean_seconds == pytest.approx(3 * 3600)


@pytest.mark.usefixtures("rules")
async def test_shorter_and_longer_periods(db_session: AsyncSession) -> None:
    await seed(db_session)

    day = await build_dashboard(db_session, DashboardRange.DAY, now=NOW)
    assert day.bucket_seconds == 3600
    assert len(day.alerts_over_time) == 25
    assert day.totals["alerts"] == 1
    assert day.ingestion["events_ingested"] == 1000
    # Only the case resolved 22 hours ago falls in the last day.
    assert day.case_resolution.resolved == 1
    assert day.case_resolution.mean_seconds == pytest.approx(2 * 3600)
    assert day.alert_resolution.mean_seconds is None

    everything = await build_dashboard(db_session, DashboardRange.ALL, now=NOW)
    assert everything.start is None
    assert everything.bucket_seconds == 3600 * 24  # 40 days of data fit in daily bars
    assert everything.totals["alerts"] == 5
    assert everything.ingestion["events_ingested"] == 4500
    assert everything.alerts_over_time[0]["bucket"] <= NOW - timedelta(days=40)


async def test_empty_dashboard(db_session: AsyncSession) -> None:
    board = await build_dashboard(db_session, DashboardRange.ALL, now=NOW)

    assert board.totals["alerts"] == 0
    assert board.top_source_ips == []
    assert board.ingestion["events_per_second"] is None
    assert len(board.alerts_over_time) == 31  # thirty days of empty daily bars


async def test_dashboard_api(client: AsyncClient) -> None:
    response = await client.get("/api/dashboard", params={"range": "30d"})

    assert response.status_code == 200
    body = response.json()
    assert body["range"] == "30d"
    assert body["bucket_seconds"] == 86400
    assert set(body["totals"]) >= {"alerts", "open_alerts", "open_cases", "events"}
    assert body["alerts_by_severity"][0]["severity"] == "critical"
    assert (await client.get("/api/dashboard")).json()["range"] == "7d"
    assert (await client.get("/api/dashboard", params={"range": "1y"})).status_code == 422
