"""Saving uploaded files where the worker can read them."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import anyio

from watchpost.ingestion.errors import UploadTooLargeError
from watchpost.ingestion.readers import check_text_content

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024
HEAD_SIZE = 8 * 1024
_UNSAFE_FILENAME_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class AsyncReadable(Protocol):
    """What an upload source must provide (FastAPI's ``UploadFile`` fits)."""

    async def read(self, size: int = -1) -> bytes: ...


@dataclass(frozen=True, slots=True)
class StoredFile:
    path: Path
    size: int
    sha256: str


def display_filename(name: str | None) -> str:
    """A safe, human-readable name for an uploaded file.

    Only used for display: files are always stored under a random name, so
    a client-supplied path like ``../../etc/passwd`` never touches the disk.
    """
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_FILENAME_CHARS.sub("", base).strip()
    return base[:255] or "upload.log"


async def save_upload(source: AsyncReadable, directory: Path, max_bytes: int) -> StoredFile:
    """Stream ``source`` into ``directory``, enforcing the size limit.

    The first bytes are checked before anything is written so binary files
    are rejected early.

    Raises:
        UnsupportedFileError: if the content is not a text log (or gzip of one).
        UploadTooLargeError: if the upload exceeds ``max_bytes``.
    """
    head = await source.read(HEAD_SIZE)
    check_text_content(head)

    await anyio.Path(directory).mkdir(parents=True, exist_ok=True)
    path = directory / f"{uuid.uuid4().hex}.upload"
    digest = hashlib.sha256()
    size = 0
    try:
        async with await anyio.open_file(path, "wb") as target:
            chunk = head
            while chunk:
                size += len(chunk)
                if size > max_bytes:
                    msg = f"the file is larger than the {max_bytes // (1024 * 1024)} MiB limit"
                    raise UploadTooLargeError(msg)
                digest.update(chunk)
                await target.write(chunk)
                chunk = await source.read(CHUNK_SIZE)
    except BaseException:
        await anyio.Path(path).unlink(missing_ok=True)
        raise
    logger.info("Stored upload %s (%d bytes)", path.name, size)
    return StoredFile(path=path, size=size, sha256=digest.hexdigest())
