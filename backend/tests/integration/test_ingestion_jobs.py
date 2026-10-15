from __future__ import annotations

import gzip
import io
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import Event, IngestionJob, IngestOrigin, IngestStatus
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.ingestion.parsers import ParseContext, get_parser
from watchpost.ingestion.pipeline import ParseStats, insert_events, parse_events, take_rows

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


async def make_job(
    session: AsyncSession,
    path: Path,
    *,
    parser: str = "auto",
    origin: IngestOrigin = IngestOrigin.UPLOAD,
    host_name: str | None = None,
) -> IngestionJob:
    job = IngestionJob(
        origin=origin,
        filename=path.name,
        stored_path=str(path),
        parser=parser,
        host_name=host_name,
        file_size=path.stat().st_size if path.exists() else 0,
    )
    session.add(job)
    await session.flush()
    return job


def copy_sample(name: str, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    shutil.copy(SAMPLES / name, target)
    return target


async def count_events(session: AsyncSession, **filters: object) -> int:
    query = select(func.count()).select_from(Event)
    for column, value in filters.items():
        query = query.where(getattr(Event, column) == value)
    return (await session.scalar(query)) or 0


async def reload(session: AsyncSession, job: IngestionJob) -> IngestionJob:
    await session.refresh(job)
    return job


@pytest.mark.parametrize(
    ("sample", "parser", "events", "log_source"),
    [
        ("auth.log", "linux_auth", 46, "linux_auth"),
        ("access.log", "web_access", 44, "web_access"),
        ("windows_security.jsonl", "windows", 22, "windows_security"),
        ("sysmon.json", "windows", 8, "sysmon"),
        ("app_events.jsonl", "json", 10, "json"),
    ],
)
async def test_samples_ingest_cleanly(
    sample: str,
    parser: str,
    events: int,
    log_source: str,
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample(sample, app_settings.upload_dir)
    size = path.stat().st_size
    job = await make_job(db_session, path)

    status = await run_ingestion_job(session_factory, app_settings, job.id)

    job = await reload(db_session, job)
    assert status is IngestStatus.COMPLETED
    assert job.status is IngestStatus.COMPLETED
    assert job.detected_parser == parser
    assert job.records_read == events
    assert job.events_inserted == events
    assert job.events_duplicate == job.records_malformed == job.records_skipped == 0
    assert job.bytes_processed == size
    assert job.started_at is not None and job.finished_at is not None
    assert await count_events(db_session, log_source=log_source) == events
    assert await count_events(db_session, ingest_job_id=job.id) == events


async def test_reingesting_the_same_file_only_counts_duplicates(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    keep = app_settings.model_copy(update={"keep_uploads": True})
    path = copy_sample("auth.log", keep.upload_dir)
    first = await make_job(db_session, path, parser="linux_auth")
    await run_ingestion_job(session_factory, keep, first.id)

    second = await make_job(db_session, path, parser="linux_auth")
    await run_ingestion_job(session_factory, keep, second.id)

    second = await reload(db_session, second)
    assert second.events_inserted == 0
    assert second.events_duplicate == 46
    assert await count_events(db_session) == 46
    # Duplicates keep pointing at the job that stored them first.
    assert await count_events(db_session, ingest_job_id=first.id) == 46


async def test_malformed_lines_are_counted_and_reported(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("malformed_lines.log", app_settings.upload_dir)
    job = await make_job(db_session, path)

    await run_ingestion_job(session_factory, app_settings, job.id)

    job = await reload(db_session, job)
    assert job.status is IngestStatus.COMPLETED
    assert (job.records_read, job.events_inserted, job.records_malformed) == (7, 4, 3)
    assert [sample["line"] for sample in job.malformed_samples] == [2, 4, 6]
    assert job.malformed_samples[0]["reason"].startswith("not a syslog line")


async def test_large_file_is_inserted_in_batches(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    app_settings.upload_dir.mkdir(parents=True)
    path = app_settings.upload_dir / "big.log.gz"
    lines = (
        f"Oct 12 09:{n // 60 % 60:02d}:{n % 60:02d} web-01 sshd[{n}]: "
        f"Failed password for root from 203.0.113.{n % 250} port {1024 + n} ssh2\n"
        for n in range(1050)
    )
    path.write_bytes(gzip.compress("".join(lines).encode()))
    size = path.stat().st_size
    job = await make_job(db_session, path, parser="linux_auth")

    await run_ingestion_job(session_factory, app_settings, job.id)  # batch size is 100

    job = await reload(db_session, job)
    assert job.events_inserted == 1050
    assert job.bytes_processed == size  # compressed bytes read from disk


async def test_default_host_is_applied(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("access.log", app_settings.upload_dir)
    job = await make_job(db_session, path, host_name="shop-web-01")

    await run_ingestion_job(session_factory, app_settings, job.id)

    assert await count_events(db_session, host_name="shop-web-01") == 44


async def test_upload_is_deleted_after_processing(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("auth.log", app_settings.upload_dir)
    job = await make_job(db_session, path)

    await run_ingestion_job(session_factory, app_settings, job.id)

    assert not path.exists()


async def test_watched_file_is_never_deleted(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("auth.log", app_settings.watch_dir)
    job = await make_job(db_session, path, origin=IngestOrigin.WATCH_FOLDER)

    await run_ingestion_job(session_factory, app_settings, job.id)

    assert path.exists()
    assert (await reload(db_session, job)).events_inserted == 46


async def test_unrecognised_format_fails_the_job(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    app_settings.upload_dir.mkdir(parents=True)
    path = app_settings.upload_dir / "notes.txt"
    path.write_text("shopping list\nmilk\n")
    job = await make_job(db_session, path)

    status = await run_ingestion_job(session_factory, app_settings, job.id)

    job = await reload(db_session, job)
    assert status is IngestStatus.FAILED
    assert job.status is IngestStatus.FAILED
    assert job.error is not None and "choose a parser" in job.error
    assert job.finished_at is not None


async def test_missing_file_fails_the_job(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    job = await make_job(db_session, app_settings.upload_dir / "gone.log", parser="linux_auth")

    assert await run_ingestion_job(session_factory, app_settings, job.id) is IngestStatus.FAILED
    assert (await reload(db_session, job)).error is not None


async def test_unknown_parser_name_fails_the_job(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("auth.log", app_settings.upload_dir)
    job = await make_job(db_session, path, parser="syslog")

    await run_ingestion_job(session_factory, app_settings, job.id)

    assert (await reload(db_session, job)).error == "unknown parser 'syslog'"


async def test_unexpected_errors_are_recorded(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = copy_sample("auth.log", app_settings.upload_dir)
    job = await make_job(db_session, path, parser="linux_auth")

    def explode(*_: object) -> list[object]:
        msg = "boom"
        raise RuntimeError(msg)

    monkeypatch.setattr("watchpost.ingestion.jobs.take_rows", explode)

    assert await run_ingestion_job(session_factory, app_settings, job.id) is IngestStatus.FAILED
    assert "internal error" in str((await reload(db_session, job)).error)


async def test_finished_or_missing_jobs_are_skipped(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
) -> None:
    path = copy_sample("auth.log", app_settings.upload_dir)
    job = await make_job(db_session, path)
    job.status = IngestStatus.COMPLETED
    await db_session.flush()

    assert await run_ingestion_job(session_factory, app_settings, job.id) is None
    assert await run_ingestion_job(session_factory, app_settings, 999_999) is None
    assert path.exists()


async def test_batch_insert_skips_repeats_and_keeps_raw_records(db_session: AsyncSession) -> None:
    lines = (SAMPLES / "auth.log").read_bytes().splitlines(keepends=True)[:6]
    parser = get_parser("linux_auth")(
        ParseContext(reference_time=datetime(2026, 10, 12, tzinfo=UTC), default_host=None)
    )
    rows = take_rows(parse_events(io.BytesIO(b"".join(lines)), parser, ParseStats()), 100)
    rows[1]["ioc_matched"] = True
    # The same event twice in one batch is stored once.
    first = await insert_events(db_session, [*rows, dict(rows[0])])
    second = await insert_events(db_session, rows[:3])

    assert (len(first), len(second)) == (6, 0)
    assert {event_hash for _, event_hash in first} == {row["event_hash"] for row in rows}
    stored = await db_session.scalar(select(Event).where(Event.id == first[1][0]))
    assert stored is not None
    assert stored.ioc_matched is True
    assert isinstance(stored.raw_event, dict)
    assert stored.raw_event == rows[1]["raw_event"]
    # The staging table is emptied after every batch.
    assert await db_session.scalar(text("SELECT count(*) FROM event_stage")) == 0
