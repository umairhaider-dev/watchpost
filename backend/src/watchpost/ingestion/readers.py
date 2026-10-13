"""Streaming readers that turn a log file into lines or JSON records.

Nothing here loads a whole file into memory: lines are read one at a time
(with a cap so a corrupt file without newlines cannot exhaust memory) and JSON
documents are decoded incrementally from fixed-size chunks.

Files are opened through :class:`LogFile`, which transparently handles gzip
compression, UTF-8 byte-order marks and UTF-16 text (the default encoding
of Windows PowerShell's ``Out-File``).
"""

from __future__ import annotations

import codecs
import gzip
import io
import json
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, BinaryIO, Literal, Protocol, Self, cast

from watchpost.ingestion.errors import UnsupportedFileError

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

GZIP_MAGIC = b"\x1f\x8b"
EVTX_MAGIC = b"ElfFile\x00"
ZIP_MAGIC = b"PK\x03\x04"
UTF16_BOMS = {codecs.BOM_UTF16_LE: "utf-16-le", codecs.BOM_UTF16_BE: "utf-16-be"}

MAX_LINE_BYTES = 1024 * 1024
MAX_JSON_RECORD_CHARS = 10 * 1024 * 1024
SNIFF_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024
# Share of unprintable characters above which a file is treated as binary.
_BINARY_THRESHOLD = 0.10
_ALLOWED_CONTROL = frozenset("\t\n\r\f\x1b")
_BOM = chr(0xFEFF)
_REPLACEMENT_CHAR = chr(0xFFFD)  # what errors='replace' inserts
_JSON_SEPARATORS = " \t\r\n,[]" + _BOM
_LEADING_WHITESPACE = " \t\r\n" + _BOM


class ByteStream(Protocol):
    """Minimal readable byte stream used by the readers."""

    def read(self, size: int = -1, /) -> bytes: ...

    def readline(self, size: int = -1, /) -> bytes: ...


# --------------------------------------------------------------------------
# Content checks
# --------------------------------------------------------------------------


def check_text_content(head: bytes) -> None:
    """Reject content that is clearly not a text log.

    ``head`` is the first few kilobytes of the file. Gzip data is
    decompressed before checking so ``.gz`` uploads are validated too.

    Raises:
        UnsupportedFileError: with a message explaining what to do instead.
    """
    if not head:
        msg = "the file is empty"
        raise UnsupportedFileError(msg)
    if head.startswith(GZIP_MAGIC):
        try:
            head = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(head, SNIFF_BYTES)
        except zlib.error as exc:
            msg = "the file looks like gzip but could not be decompressed"
            raise UnsupportedFileError(msg) from exc
        if not head:
            msg = "the compressed file is empty"
            raise UnsupportedFileError(msg)
    if head.startswith(EVTX_MAGIC):
        msg = (
            "binary .evtx files are not supported; export the events to JSON first "
            "(see the README for a PowerShell one-liner)"
        )
        raise UnsupportedFileError(msg)
    if head.startswith(ZIP_MAGIC):
        msg = "zip archives are not supported; upload the log file itself or a .gz"
        raise UnsupportedFileError(msg)
    for bom, encoding in UTF16_BOMS.items():
        if head.startswith(bom):
            _check_printable(head[len(bom) :].decode(encoding, errors="replace"))
            return
    if b"\x00" in head:
        msg = "the file looks binary (it contains NUL bytes), not like a text log"
        raise UnsupportedFileError(msg)
    _check_printable(head.decode("utf-8", errors="replace"))


def _check_printable(text: str) -> None:
    if not text:
        return
    bad = sum(
        1
        for char in text
        if char == _REPLACEMENT_CHAR or (ord(char) < 32 and char not in _ALLOWED_CONTROL)
    )
    if bad / len(text) > _BINARY_THRESHOLD:
        msg = "the file does not look like UTF-8 or UTF-16 text"
        raise UnsupportedFileError(msg)


# --------------------------------------------------------------------------
# Opening files
# --------------------------------------------------------------------------


class _TranscodingReader(io.RawIOBase):
    """Re-encodes a UTF-16 byte stream as UTF-8 on the fly."""

    def __init__(self, source: ByteStream, encoding: str) -> None:
        super().__init__()
        self._source = source
        self._decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        self._pending = b""
        self._eof = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: WriteableBuffer, /) -> int:
        view = memoryview(buffer).cast("B")
        while not self._pending and not self._eof:
            chunk = self._source.read(_READ_CHUNK)
            self._eof = not chunk
            self._pending = self._decoder.decode(chunk, final=self._eof).encode("utf-8")
        size = min(len(view), len(self._pending))
        view[:size] = self._pending[:size]
        self._pending = self._pending[size:]
        return size


class LogFile:
    """An open log file exposing a decompressed, UTF-8 byte stream.

    ``position()`` reports how far into the file *on disk* reading has got,
    which is what progress reporting needs for compressed files.
    """

    def __init__(self, raw: BinaryIO) -> None:
        self._raw = raw
        buffered: io.BufferedReader[Any] = (
            raw if isinstance(raw, io.BufferedReader) else io.BufferedReader(cast(Any, raw))
        )
        stream: io.BufferedReader[Any] | gzip.GzipFile = buffered
        if buffered.peek(2)[:2] == GZIP_MAGIC:
            stream = gzip.GzipFile(fileobj=buffered, mode="rb")
        bom = stream.peek(2)[:2]
        if bom in UTF16_BOMS:
            stream.read(2)
            stream = io.BufferedReader(_TranscodingReader(stream, UTF16_BOMS[bom]))
        self.stream: io.BufferedReader[Any] | gzip.GzipFile = stream

    @classmethod
    def open(cls, path: Path) -> LogFile:
        return cls(path.open("rb"))

    def position(self) -> int:
        return self._raw.tell()

    def close(self) -> None:
        self.stream.close()
        self._raw.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


# --------------------------------------------------------------------------
# Lines
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RawLine:
    """One non-blank line of a text log."""

    number: int
    text: str
    truncated: bool = False


def iter_lines(stream: ByteStream, max_line_bytes: int = MAX_LINE_BYTES) -> Iterator[RawLine]:
    """Yield non-blank lines with their 1-based line numbers.

    Lines longer than ``max_line_bytes`` are cut and flagged as truncated so
    the caller can report them instead of buffering unbounded data. Invalid
    UTF-8 is replaced rather than failing the whole file.
    """
    number = 0
    while True:
        chunk = stream.readline(max_line_bytes + 1)
        if not chunk:
            return
        number += 1
        truncated = len(chunk) > max_line_bytes and not chunk.endswith(b"\n")
        if truncated:
            _discard_rest_of_line(stream, max_line_bytes)
            chunk = chunk[:max_line_bytes]
        text = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
        if number == 1:
            text = text.removeprefix(_BOM)
        if text.strip():
            yield RawLine(number, text, truncated)


def _discard_rest_of_line(stream: ByteStream, chunk_size: int) -> None:
    while True:
        rest = stream.readline(chunk_size)
        if not rest or rest.endswith(b"\n"):
            return


# --------------------------------------------------------------------------
# JSON records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class JsonRecord:
    """One JSON object from a file, or the reason it could not be read.

    ``number`` is the line number for JSON-lines files and the record index
    for JSON documents (arrays or pretty-printed objects).
    """

    number: int
    text: str
    value: dict[str, Any] | None = None
    error: str | None = None


JsonLayout = Literal["lines", "document"]


def detect_json_layout(head: bytes) -> JsonLayout:
    """Decide between one-object-per-line and a multi-line JSON document."""
    text = head.decode("utf-8", errors="replace").lstrip(_LEADING_WHITESPACE)
    if text.startswith("["):
        return "document"
    if text.startswith("{") and text.split("\n", 1)[0].strip() == "{":
        return "document"
    return "lines"


def iter_json_records(
    stream: ByteStream,
    layout: JsonLayout,
    max_record_chars: int = MAX_JSON_RECORD_CHARS,
) -> Iterator[JsonRecord]:
    """Yield JSON objects from either layout, reporting bad records instead of failing."""
    if layout == "lines":
        yield from _iter_json_lines(stream)
    else:
        yield from _iter_json_document(stream, max_record_chars)


def _iter_json_lines(stream: ByteStream) -> Iterator[JsonRecord]:
    for line in iter_lines(stream):
        if line.truncated:
            yield JsonRecord(line.number, line.text, error="line is too long")
            continue
        try:
            value = json.loads(line.text)
        except json.JSONDecodeError as exc:
            yield JsonRecord(line.number, line.text, error=f"invalid JSON: {exc.msg}")
            continue
        if isinstance(value, dict):
            yield JsonRecord(line.number, line.text, value=value)
        else:
            yield JsonRecord(line.number, line.text, error="expected a JSON object")


@dataclass(slots=True)
class _DocumentBuffer:
    stream: ByteStream
    decoder: codecs.IncrementalDecoder = field(
        default_factory=lambda: codecs.getincrementaldecoder("utf-8")(errors="replace")
    )
    text: str = ""
    pos: int = 0
    eof: bool = False

    def fill(self) -> None:
        """Drop consumed text and append the next chunk from the stream."""
        chunk = self.stream.read(_READ_CHUNK)
        self.eof = not chunk
        self.text = self.text[self.pos :] + self.decoder.decode(chunk, final=self.eof)
        self.pos = 0

    def skip_separators(self) -> bool:
        """Advance past whitespace, commas and brackets. False at end of input."""
        while True:
            while self.pos < len(self.text) and self.text[self.pos] in _JSON_SEPARATORS:
                self.pos += 1
            if self.pos < len(self.text):
                return True
            if self.eof:
                return False
            self.fill()


def _iter_json_document(stream: ByteStream, max_record_chars: int) -> Iterator[JsonRecord]:
    """Decode consecutive JSON values from a top-level array or concatenated objects.

    A structural error inside a document makes the rest of it unreadable, so
    it is reported once and iteration stops.
    """
    decoder = json.JSONDecoder()
    buffer = _DocumentBuffer(stream)
    index = 0
    while buffer.skip_separators():
        try:
            value, end = decoder.raw_decode(buffer.text, buffer.pos)
        except json.JSONDecodeError as exc:
            # Probably a record split across chunks: read more and retry.
            if not buffer.eof and len(buffer.text) - buffer.pos <= max_record_chars:
                buffer.fill()
                continue
            index += 1
            excerpt = buffer.text[buffer.pos : buffer.pos + 200]
            yield JsonRecord(
                index, excerpt, error=f"invalid JSON ({exc.msg}); rest of the file skipped"
            )
            return
        index += 1
        text = buffer.text[buffer.pos : end]
        buffer.pos = end
        if isinstance(value, dict):
            yield JsonRecord(index, text, value=value)
        else:
            yield JsonRecord(index, text[:200], error="expected a JSON object")


# --------------------------------------------------------------------------
# Format sniffing
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Sample:
    """The start of a file, used to guess its format."""

    lines: list[str]
    records: list[dict[str, Any]]


def read_sample(path: Path, max_bytes: int = SNIFF_BYTES, max_items: int = 50) -> Sample:
    """Read up to ``max_items`` lines and JSON records from the start of ``path``."""
    with LogFile.open(path) as log_file:
        head = log_file.stream.read(max_bytes)
    return sample_from_bytes(head, complete=len(head) < max_bytes, max_items=max_items)


def sample_from_bytes(head: bytes, *, complete: bool, max_items: int = 50) -> Sample:
    """Build a :class:`Sample` from raw bytes; ``complete`` is False if ``head`` was cut."""
    text = head.decode("utf-8", errors="replace").removeprefix(_BOM)
    all_lines = text.splitlines()
    if not complete and all_lines:
        all_lines = all_lines[:-1]  # the last line is probably cut off
    lines = [line for line in all_lines if line.strip()][:max_items]

    records: list[dict[str, Any]] = []
    layout = detect_json_layout(head)
    for record in iter_json_records(io.BytesIO(head), layout):
        if record.value is not None:
            records.append(record.value)
        if len(records) >= max_items:
            break
    return Sample(lines=lines, records=records)
