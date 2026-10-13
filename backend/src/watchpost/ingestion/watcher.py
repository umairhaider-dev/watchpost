"""Picking up log files dropped into the watched folder.

Every scan lists the folder (recursively), ignores files that are hidden,
temporary or still being written, and creates one ingestion job per *new
version* of a file. A version is identified by path, size and modification
time, stored as ``watch_fingerprint`` with a unique constraint, so two
overlapping scans can never queue the same file twice.

The watcher never modifies the folder, so it can be mounted read-only. When
a file grows (an appended log), the new version is ingested in full and the
event hash skips the lines that were already stored.

A file inside a subfolder named after a parser (``watch/web_access/x.log``)
is parsed with that parser; anything else is auto-detected.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import IngestionJob, IngestOrigin, IngestStatus
from watchpost.ingestion.parsers import AUTO, PARSERS
from watchpost.worker.queue import JobQueue

logger = logging.getLogger(__name__)

IGNORED_SUFFIXES = (".tmp", ".part", ".partial", ".swp", ".crdownload", ".lock")


@dataclass(frozen=True, slots=True)
class WatchedFile:
    """A file ready to be ingested."""

    path: Path
    relative: str
    size: int
    mtime_ns: int
    parser: str

    @property
    def fingerprint(self) -> str:
        key = f"{self.relative}|{self.size}|{self.mtime_ns}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()


def list_ready_files(root: Path, settle_seconds: float, now: float) -> list[WatchedFile]:
    """Files under ``root`` that look complete and are not hidden or temporary."""
    ready: list[WatchedFile] = []
    for directory, subdirs, filenames in os.walk(root):
        subdirs[:] = sorted(name for name in subdirs if not name.startswith("."))
        for filename in sorted(filenames):
            if filename.startswith((".", "~")) or filename.lower().endswith(IGNORED_SUFFIXES):
                continue
            path = Path(directory) / filename
            try:
                stat = path.stat()
            except OSError:
                continue  # deleted or unreadable between listing and stat
            if stat.st_size == 0 or now - stat.st_mtime < settle_seconds:
                continue
            relative = path.relative_to(root).as_posix()
            top_folder = relative.split("/", 1)[0] if "/" in relative else ""
            ready.append(
                WatchedFile(
                    path=path,
                    relative=relative,
                    size=stat.st_size,
                    mtime_ns=stat.st_mtime_ns,
                    parser=top_folder if top_folder in PARSERS else AUTO,
                )
            )
    return ready


async def scan_watch_folder(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    queue: JobQueue,
    *,
    now: datetime | None = None,
) -> list[int]:
    """Create and enqueue jobs for new files. Returns the new job IDs."""
    root = settings.watch_dir
    if not root.is_dir():
        logger.debug("Watch folder %s does not exist; nothing to scan", root)
        return []
    timestamp = (now or datetime.now(UTC)).timestamp()
    files = await asyncio.to_thread(
        list_ready_files, root, settings.watch_settle_seconds, timestamp
    )

    created: list[int] = []
    async with session_factory() as session:
        for watched in files:
            job_id = await session.scalar(
                pg_insert(IngestionJob)
                .values(
                    origin=IngestOrigin.WATCH_FOLDER,
                    status=IngestStatus.QUEUED,
                    filename=watched.relative[-255:],
                    stored_path=str(watched.path.resolve()),
                    parser=watched.parser,
                    file_size=watched.size,
                    watch_fingerprint=watched.fingerprint,
                )
                .on_conflict_do_nothing(index_elements=[IngestionJob.watch_fingerprint])
                .returning(IngestionJob.id)
            )
            if job_id is not None:
                created.append(job_id)
                logger.info("Watch folder: queued %s as job %d", watched.relative, job_id)
        await session.commit()

    for job_id in created:
        await queue.enqueue_ingestion(job_id)
    return created
