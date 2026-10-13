from __future__ import annotations

import gzip
from pathlib import Path

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.conftest import RecordingQueue
from watchpost.core.config import Settings
from watchpost.db.models import IngestStatus
from watchpost.ingestion.jobs import run_ingestion_job

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


def sample_bytes(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


async def upload(
    client: AsyncClient,
    content: bytes,
    filename: str = "auth.log",
    **form: str,
) -> tuple[int, dict[str, object]]:
    response = await client.post(
        "/api/ingest/uploads",
        files={"file": (filename, content, "application/octet-stream")},
        data=form,
    )
    return response.status_code, response.json()


async def test_ingest_info_lists_parsers(client: AsyncClient, app_settings: Settings) -> None:
    response = await client.get("/api/ingest/info")

    body = response.json()
    assert response.status_code == 200
    assert [parser["name"] for parser in body["parsers"]] == [
        "linux_auth",
        "web_access",
        "windows",
        "json",
    ]
    assert body["max_upload_bytes"] == app_settings.max_upload_bytes
    assert body["watch_enabled"] is True


async def test_upload_stores_file_and_queues_job(
    client: AsyncClient, queue: RecordingQueue, app_settings: Settings
) -> None:
    status, body = await upload(client, sample_bytes("auth.log"), host_name="web-01")

    assert status == 202
    assert body["status"] == "queued"
    assert body["origin"] == "upload"
    assert body["filename"] == "auth.log"
    assert body["parser"] == "auto"
    assert body["host_name"] == "web-01"
    assert body["file_size"] == len(sample_bytes("auth.log"))
    assert queue.job_ids == [body["id"]]
    stored = list(app_settings.upload_dir.iterdir())
    assert len(stored) == 1
    assert stored[0].name.endswith(".upload")  # never the client's filename


async def test_upload_then_process_end_to_end(
    client: AsyncClient,
    queue: RecordingQueue,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    _, body = await upload(client, gzip.compress(sample_bytes("access.log")), "access.log.gz")

    await run_ingestion_job(session_factory, app_settings, queue.job_ids[0])
    detail = (await client.get(f"/api/ingest/jobs/{body['id']}")).json()
    events = (await client.get("/api/events", params={"log_source": "web_access"})).json()

    assert detail["status"] == "completed"
    assert detail["detected_parser"] == "web_access"
    assert detail["events_inserted"] == 32
    assert detail["malformed_samples"] == []
    assert len(events["items"]) == 32


async def test_upload_with_explicit_parser(client: AsyncClient) -> None:
    status, body = await upload(
        client, sample_bytes("sysmon.json"), "sysmon.json", parser="windows"
    )

    assert status == 202
    assert body["parser"] == "windows"


async def test_unknown_parser_is_rejected(client: AsyncClient, queue: RecordingQueue) -> None:
    status, body = await upload(client, b"text\n", parser="syslog")

    assert status == 422
    assert "unknown parser" in str(body["detail"])
    assert queue.job_ids == []


async def test_invalid_host_name_is_rejected(client: AsyncClient) -> None:
    status, _ = await upload(client, b"text\n", host_name="bad host; rm -rf")

    assert status == 422


async def test_binary_upload_is_rejected(client: AsyncClient, app_settings: Settings) -> None:
    status, body = await upload(client, b"MZ\x90\x00" + bytes(64), "evil.exe")

    assert status == 415
    assert "binary" in str(body["detail"])
    assert not app_settings.upload_dir.exists() or not any(app_settings.upload_dir.iterdir())


async def test_evtx_upload_explains_what_to_do(client: AsyncClient) -> None:
    status, body = await upload(client, b"ElfFile\x00" + bytes(64), "Security.evtx")

    assert status == 415
    assert "export the events to JSON" in str(body["detail"])


async def test_empty_upload_is_rejected(client: AsyncClient) -> None:
    status, body = await upload(client, b"", "empty.log")

    assert status == 415
    assert "empty" in str(body["detail"])


async def test_oversized_upload_is_rejected(client: AsyncClient, app_settings: Settings) -> None:
    app_settings.max_upload_bytes = 2048

    status, body = await upload(client, b"x\n" * 2000)

    assert status == 413
    assert "limit" in str(body["detail"])


async def test_queue_outage_marks_job_failed(
    client: AsyncClient, queue: RecordingQueue, db_session: AsyncSession, app_settings: Settings
) -> None:
    queue.fail = True

    status, _ = await upload(client, sample_bytes("auth.log"))

    assert status == 503
    jobs = (await client.get("/api/ingest/jobs")).json()
    assert jobs["items"][0]["status"] == "failed"
    assert "queue" in jobs["items"][0]["error"]
    assert not any(app_settings.upload_dir.iterdir())


async def test_job_list_is_newest_first_and_filterable(client: AsyncClient) -> None:
    for _ in range(3):
        await upload(client, sample_bytes("auth.log"))

    newest_ids = [job["id"] for job in (await client.get("/api/ingest/jobs")).json()["items"]]
    page = (await client.get("/api/ingest/jobs", params={"limit": 2, "offset": 1})).json()
    queued = (await client.get("/api/ingest/jobs", params={"status": "queued"})).json()
    failed = (await client.get("/api/ingest/jobs", params={"status": "failed"})).json()

    assert newest_ids == sorted(newest_ids, reverse=True)
    assert page["total"] == 3
    assert [job["id"] for job in page["items"]] == newest_ids[1:3]
    assert queued["total"] == 3
    assert failed["total"] == 0


async def test_job_detail_and_404(client: AsyncClient) -> None:
    _, body = await upload(client, sample_bytes("auth.log"))

    detail = await client.get(f"/api/ingest/jobs/{body['id']}")
    missing = await client.get("/api/ingest/jobs/999999")

    assert detail.status_code == 200
    assert detail.json()["malformed_samples"] == []
    assert missing.status_code == 404


async def test_invalid_status_filter(client: AsyncClient) -> None:
    response = await client.get("/api/ingest/jobs", params={"status": "exploded"})

    assert response.status_code == 422


async def test_job_status_values_match_enum(client: AsyncClient) -> None:
    _, body = await upload(client, sample_bytes("auth.log"))

    assert body["status"] in {status.value for status in IngestStatus}
