from __future__ import annotations

import codecs
import gzip
import io
import json
from pathlib import Path

import pytest

from watchpost.ingestion.errors import UnsupportedFileError
from watchpost.ingestion.readers import (
    EVTX_MAGIC,
    LogFile,
    check_text_content,
    detect_json_layout,
    iter_json_records,
    iter_lines,
    read_sample,
    sample_from_bytes,
)


def lines_of(data: bytes, max_line_bytes: int = 1024) -> list[tuple[int, str, bool]]:
    return [
        (line.number, line.text, line.truncated)
        for line in iter_lines(io.BytesIO(data), max_line_bytes)
    ]


# ---------------------------------------------------------------- content checks


@pytest.mark.parametrize(
    "head",
    [
        b"Oct 12 09:02:11 web-01 sshd[1]: hello\n",
        b'{"a": 1}\n',
        codecs.BOM_UTF8 + b"text\n",
        codecs.BOM_UTF16_LE + "text\n".encode("utf-16-le"),
        gzip.compress(b"plain text log\n"),
        "café log line\n".encode(),
    ],
)
def test_text_content_is_accepted(head: bytes) -> None:
    check_text_content(head)


@pytest.mark.parametrize(
    ("head", "message"),
    [
        (b"", "empty"),
        (EVTX_MAGIC + b"\x00" * 50, "evtx"),
        (b"PK\x03\x04rest", "zip"),
        (b"MZ\x90\x00\x03\x00\x00\x00", "NUL"),
        (bytes(range(1, 32)) * 4, "UTF-8 or UTF-16"),
        (gzip.compress(b""), "compressed file is empty"),
        (b"\x1f\x8bnot really gzip", "could not be decompressed"),
    ],
)
def test_binary_content_is_rejected(head: bytes, message: str) -> None:
    with pytest.raises(UnsupportedFileError, match=message):
        check_text_content(head)


# ---------------------------------------------------------------- lines


def test_iter_lines_skips_blank_lines_but_keeps_numbering() -> None:
    assert lines_of(b"first\n\n   \nsecond\r\nthird") == [
        (1, "first", False),
        (4, "second", False),
        (5, "third", False),
    ]


def test_iter_lines_strips_utf8_bom() -> None:
    assert lines_of(codecs.BOM_UTF8 + b"first\n") == [(1, "first", False)]


def test_iter_lines_replaces_invalid_utf8() -> None:
    [(_, text, _)] = lines_of(b"user \xff\xfe name\n")
    assert text.startswith("user ")
    assert "name" in text


def test_overlong_line_is_truncated_and_rest_discarded() -> None:
    data = b"short\n" + b"x" * 50 + b"\nafter\n"

    assert lines_of(data, max_line_bytes=10) == [
        (1, "short", False),
        (2, "x" * 10, True),
        (3, "after", False),
    ]


# ---------------------------------------------------------------- opening files


def test_log_file_reads_gzip_transparently(tmp_path: Path) -> None:
    path = tmp_path / "auth.log.gz"
    path.write_bytes(gzip.compress(b"line one\nline two\n"))

    with LogFile.open(path) as log_file:
        texts = [line.text for line in iter_lines(log_file.stream)]
        assert log_file.position() > 0

    assert texts == ["line one", "line two"]


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_log_file_transcodes_utf16(tmp_path: Path, encoding: str) -> None:
    bom = codecs.BOM_UTF16_LE if encoding.endswith("le") else codecs.BOM_UTF16_BE
    path = tmp_path / "export.json"
    path.write_bytes(bom + '{"EventID": 4625, "User": "Jörg"}\r\n'.encode(encoding))

    with LogFile.open(path) as log_file:
        lines = [line.text for line in iter_lines(log_file.stream)]

    assert json.loads(lines[0]) == {"EventID": 4625, "User": "Jörg"}


def test_log_file_accepts_unbuffered_streams() -> None:
    with LogFile(io.BytesIO(b"hello\n")) as log_file:
        assert log_file.stream.read() == b"hello\n"


# ---------------------------------------------------------------- JSON records


@pytest.mark.parametrize(
    ("head", "layout"),
    [
        (b'{"a": 1}\n{"a": 2}\n', "lines"),
        (b'[\n  {"a": 1}\n]', "document"),
        (b'  \n[{"a": 1}]', "document"),
        (b'{\n  "a": 1\n}\n', "document"),
        (b"not json at all", "lines"),
    ],
)
def test_detect_json_layout(head: bytes, layout: str) -> None:
    assert detect_json_layout(head) == layout


def records_of(data: bytes) -> list[tuple[int, object, str | None]]:
    layout = detect_json_layout(data)
    return [(r.number, r.value, r.error) for r in iter_json_records(io.BytesIO(data), layout)]


def test_json_lines_report_bad_lines_and_continue() -> None:
    data = b'{"a": 1}\nnot json\n[1, 2]\n\n{"a": 2}\n'

    assert records_of(data) == [
        (1, {"a": 1}, None),
        (2, None, "invalid JSON: Expecting value"),
        (3, None, "expected a JSON object"),
        (5, {"a": 2}, None),
    ]


def test_json_array_document_is_streamed() -> None:
    data = json.dumps([{"n": n} for n in range(3)], indent=2).encode()

    assert [value for _, value, _ in records_of(data)] == [{"n": 0}, {"n": 1}, {"n": 2}]


def test_concatenated_pretty_objects() -> None:
    data = b'{\n  "n": 1\n}\n{\n  "n": 2\n}\n'

    assert [value for _, value, _ in records_of(data)] == [{"n": 1}, {"n": 2}]


def test_records_spanning_read_chunks_are_reassembled() -> None:
    big = [{"n": n, "padding": "x" * 50_000} for n in range(4)]
    data = json.dumps(big).encode()

    values = [value for _, value, _ in records_of(data)]

    assert [v["n"] for v in values if isinstance(v, dict)] == [0, 1, 2, 3]


def test_document_with_broken_record_stops_with_one_error() -> None:
    data = b'[{"n": 1}, {"n": 2,, }, {"n": 3}]'

    results = records_of(data)

    assert results[0] == (1, {"n": 1}, None)
    assert results[1][1] is None
    assert "rest of the file skipped" in str(results[1][2])
    assert len(results) == 2


def test_document_with_non_object_values() -> None:
    assert records_of(b'[{"n": 1}, 42]')[1] == (2, None, "expected a JSON object")


def test_json_line_too_long_is_reported() -> None:
    data = b'{"a": "' + b"x" * 100 + b'"}\n'
    records = list(iter_json_records(io.BytesIO(data), "lines"))
    assert records[0].value is not None  # default limit is generous

    long_line = b'{"a": "' + b"x" * (1024 * 1024 + 10) + b'"}\n{"b": 1}\n'
    records = list(iter_json_records(io.BytesIO(long_line), "lines"))
    assert records[0].error == "line is too long"
    assert records[1].value == {"b": 1}


# ---------------------------------------------------------------- samples


def test_sample_drops_cut_off_last_line() -> None:
    sample = sample_from_bytes(b"one\ntwo\nthr", complete=False)

    assert sample.lines == ["one", "two"]


def test_sample_collects_json_records() -> None:
    sample = sample_from_bytes(b'{"a": 1}\n{"a": 2}\n', complete=True)

    assert sample.records == [{"a": 1}, {"a": 2}]
    assert len(sample.lines) == 2


def test_read_sample_from_file(tmp_path: Path) -> None:
    path = tmp_path / "x.log"
    path.write_bytes(b"\n".join(f"line {n}".encode() for n in range(100)))

    sample = read_sample(path, max_items=10)

    assert sample.lines == [f"line {n}" for n in range(10)]
    assert sample.records == []
