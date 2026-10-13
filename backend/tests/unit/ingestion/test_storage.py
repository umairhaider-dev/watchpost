from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from watchpost.ingestion.errors import UnsupportedFileError, UploadTooLargeError
from watchpost.ingestion.storage import display_filename, save_upload


class FakeUpload:
    """Async reader over bytes, read in the sizes the caller asks for."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    async def read(self, size: int = -1) -> bytes:
        end = len(self._data) if size < 0 else self._pos + size
        chunk = self._data[self._pos : end]
        self._pos += len(chunk)
        return chunk


async def test_save_upload_streams_to_disk(tmp_path: Path) -> None:
    data = b"Oct 12 09:00:00 web-01 sshd[1]: hello\n" * 100_000  # ~3.7 MB, several chunks

    stored = await save_upload(FakeUpload(data), tmp_path / "uploads", max_bytes=10 * 1024 * 1024)

    assert stored.path.parent == tmp_path / "uploads"
    assert stored.path.read_bytes() == data
    assert stored.size == len(data)
    assert stored.sha256 == hashlib.sha256(data).hexdigest()


async def test_gzip_upload_is_accepted(tmp_path: Path) -> None:
    data = gzip.compress(b"line\n" * 10)

    stored = await save_upload(FakeUpload(data), tmp_path, max_bytes=1024 * 1024)

    assert stored.path.read_bytes() == data


async def test_oversized_upload_is_rejected_and_removed(tmp_path: Path) -> None:
    with pytest.raises(UploadTooLargeError, match="1 MiB limit"):
        await save_upload(FakeUpload(b"x\n" * 1024 * 1024), tmp_path, max_bytes=1024 * 1024)

    assert list(tmp_path.iterdir()) == []


async def test_binary_upload_is_rejected_before_writing(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedFileError):
        await save_upload(
            FakeUpload(b"MZ\x90\x00" + bytes(100)), tmp_path / "uploads", max_bytes=1024
        )

    assert not (tmp_path / "uploads").exists()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("auth.log", "auth.log"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\Desktop\\security.json", "security.json"),
        ("bad\x00name\n.log", "badname.log"),
        ("", "upload.log"),
        (None, "upload.log"),
        ("a" * 300 + ".log", "a" * 255),
    ],
)
def test_display_filename(name: str | None, expected: str) -> None:
    assert display_filename(name) == expected
