from __future__ import annotations

import shutil
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.integration.conftest import RecordingQueue
from watchpost.core.config import Settings
from watchpost.db.models import IngestionJob, IngestOrigin
from watchpost.ingestion.watcher import list_ready_files, scan_watch_folder

SAMPLES = Path(__file__).resolve().parents[3] / "samples"


def drop(watch_dir: Path, sample: str, relative: str | None = None) -> Path:
    target = watch_dir / (relative or sample)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(SAMPLES / sample, target)
    return target


async def scan(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings, queue: RecordingQueue
) -> list[int]:
    """Scan as if a minute has passed, so freshly copied files count as settled."""
    later = datetime.now(UTC) + timedelta(minutes=1)
    return await scan_watch_folder(session_factory, settings, queue, now=later)


async def jobs(session: AsyncSession) -> list[IngestionJob]:
    return list(await session.scalars(select(IngestionJob).order_by(IngestionJob.id)))


async def test_new_files_become_queued_jobs(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    queue: RecordingQueue,
) -> None:
    drop(app_settings.watch_dir, "auth.log")
    drop(app_settings.watch_dir, "access.log", "web_access/frontend.log")

    created = await scan(session_factory, app_settings, queue)

    found = await jobs(db_session)
    assert created == queue.job_ids == [job.id for job in found]
    by_name = {job.filename: job for job in found}
    assert by_name["auth.log"].parser == "auto"
    assert by_name["web_access/frontend.log"].parser == "web_access"
    assert all(job.origin is IngestOrigin.WATCH_FOLDER for job in found)


async def test_rescanning_does_not_duplicate_jobs(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    queue: RecordingQueue,
) -> None:
    drop(app_settings.watch_dir, "auth.log")

    await scan(session_factory, app_settings, queue)
    second = await scan(session_factory, app_settings, queue)

    assert second == []
    assert len(await jobs(db_session)) == 1


async def test_changed_file_is_picked_up_again(
    db_session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    queue: RecordingQueue,
) -> None:
    path = drop(app_settings.watch_dir, "auth.log")
    await scan(session_factory, app_settings, queue)

    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            "Oct 12 12:00:00 web-01 sshd[9]: Accepted password for x from 10.0.0.9 port 1 ssh2\n"
        )
    again = await scan(session_factory, app_settings, queue)

    assert len(again) == 1
    assert len(await jobs(db_session)) == 2


async def test_files_still_being_written_are_skipped(
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    queue: RecordingQueue,
) -> None:
    drop(app_settings.watch_dir, "auth.log")
    patient = app_settings.model_copy(update={"watch_settle_seconds": 300})

    assert await scan(session_factory, patient, queue) == []


def test_hidden_temporary_and_empty_files_are_ignored(tmp_path: Path) -> None:
    for name in (".hidden.log", "~lock.log", "upload.part", "copy.tmp", "empty.log"):
        (tmp_path / name).write_text("" if name == "empty.log" else "data\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("data\n")
    (tmp_path / "real.log").write_text("data\n")

    ready = list_ready_files(tmp_path, settle_seconds=0, now=time.time() + 60)

    assert [watched.relative for watched in ready] == ["real.log"]


def test_fingerprint_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    path.write_text("one\n")
    [before] = list_ready_files(tmp_path, 0, time.time() + 60)
    path.write_text("one\ntwo\n")
    [after] = list_ready_files(tmp_path, 0, time.time() + 60)

    assert before.fingerprint != after.fingerprint


async def test_missing_watch_folder_is_a_no_op(
    session_factory: async_sessionmaker[AsyncSession],
    app_settings: Settings,
    queue: RecordingQueue,
) -> None:
    assert not app_settings.watch_dir.exists()

    assert await scan(session_factory, app_settings, queue) == []
