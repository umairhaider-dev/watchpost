from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.conftest import RecordingQueue
from watchpost.core.config import Settings
from watchpost.db.models import DetectionTrigger, IngestionJob, IngestOrigin
from watchpost.detection.runner import create_run, execute_run
from watchpost.detection.store import sync_builtin_rules
from watchpost.ingestion.jobs import run_ingestion_job

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
async def builtin_rules(db_session: AsyncSession) -> None:
    await sync_builtin_rules(db_session, ROOT / "backend" / "rules")


async def ingested_auth_log(
    db_session: AsyncSession, session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> IngestionJob:
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    path = settings.upload_dir / "auth.log"
    shutil.copy(ROOT / "samples" / "auth.log", path)
    job = IngestionJob(
        origin=IngestOrigin.UPLOAD,
        filename="auth.log",
        stored_path=str(path),
        parser="auto",
        file_size=path.stat().st_size,
    )
    db_session.add(job)
    await db_session.flush()
    await run_ingestion_job(session_factory, settings, job.id)
    return job


async def test_start_manual_run(client: AsyncClient, queue: RecordingQueue) -> None:
    response = await client.post(
        "/api/detection/runs",
        json={
            "start": "2026-10-01T00:00:00Z",
            "end": "2026-10-31T00:00:00Z",
            "rule_ids": ["ssh-brute-force"],
        },
    )

    body = response.json()
    assert response.status_code == 202
    assert body["trigger"] == "manual"
    assert body["status"] == "queued"
    assert body["rule_ids"] == ["ssh-brute-force"]
    assert queue.detection_runs == [body["id"]]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"start": "2026-10-31T00:00:00Z", "end": "2026-10-01T00:00:00Z"}, "before end"),
        ({"rule_ids": ["no-such-rule"]}, "unknown rule"),
        ({"start": "2026-10-01T00:00:00"}, "timezone"),
        ({"rule_ids": []}, "at least 1"),
    ],
)
async def test_invalid_run_requests(
    client: AsyncClient, payload: dict[str, object], message: str
) -> None:
    response = await client.post("/api/detection/runs", json=payload)

    assert response.status_code == 422
    assert message in str(response.json()["detail"])


async def test_queue_outage_fails_the_run(client: AsyncClient, queue: RecordingQueue) -> None:
    queue.fail = True

    response = await client.post("/api/detection/runs", json={})

    assert response.status_code == 503
    [run] = (await client.get("/api/detection/runs")).json()
    assert run["status"] == "failed"
    assert "queue" in run["error"]


async def test_run_results_and_job_summary(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    job = await ingested_auth_log(db_session, session_factory, app_settings)
    run = await create_run(db_session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job.id)
    job_id, run_id = job.id, run.id
    await execute_run(session_factory, run_id)
    db_session.expire_all()  # the API shares this session; drop its cached rows

    detail = (await client.get(f"/api/detection/runs/{run_id}")).json()
    job_detail = (await client.get(f"/api/ingest/jobs/{job_id}")).json()
    job_list = (await client.get("/api/ingest/jobs")).json()

    assert detail["status"] == "completed"
    assert detail["events_scanned"] == 46
    assert detail["alerts_created"] == 7
    assert job_detail["detection"] == {
        "id": run_id,
        "status": "completed",
        "hits": detail["hits"],
        "alerts_created": 7,
        "alerts_updated": 0,
    }
    assert job_list["items"][0]["detection"]["alerts_created"] == 7
    assert (await client.get("/api/detection/runs/999999")).status_code == 404


async def test_alert_list_and_detail(
    client: AsyncClient,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    job = await ingested_auth_log(db_session, session_factory, app_settings)
    run = await create_run(db_session, trigger=DetectionTrigger.INGESTION, ingest_job_id=job.id)
    await execute_run(session_factory, run.id)
    db_session.expire_all()  # the API shares this session; drop its cached rows

    page = (await client.get("/api/alerts")).json()
    high = (await client.get("/api/alerts", params={"severity": ["high", "critical"]})).json()
    by_rule = (await client.get("/api/alerts", params={"rule_id": "ssh-brute-force"})).json()
    closed = (await client.get("/api/alerts", params={"status": "closed"})).json()

    assert page["total"] == 7
    assert {alert["severity"] for alert in high["items"]} == {"high"}
    [brute_force] = by_rule["items"]
    assert closed["total"] == 0

    detail = (await client.get(f"/api/alerts/{brute_force['id']}")).json()
    assert detail["rule"]["title"] == "SSH brute force"
    assert len(detail["evidence"]) == 10
    timestamps = [event["timestamp"] for event in detail["evidence"]]
    assert timestamps == sorted(timestamps)
    assert detail["enrichment"] == {}
    assert (await client.get("/api/alerts/999999")).status_code == 404
