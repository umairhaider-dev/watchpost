from __future__ import annotations

import io
from pathlib import Path

import pytest

from watchpost.db.models import LogSource
from watchpost.ingestion.errors import FormatDetectionError, ParseError
from watchpost.ingestion.parsers import (
    PARSERS,
    GenericJsonParser,
    LinuxAuthParser,
    ParseContext,
    WebAccessParser,
    WindowsEventParser,
    detect_parser,
    get_parser,
    is_valid_parser_choice,
)
from watchpost.ingestion.parsers.base import build_event
from watchpost.ingestion.pipeline import MAX_MALFORMED_SAMPLES, ParseStats, parse_events, take_rows
from watchpost.ingestion.readers import LogFile, read_sample

SAMPLES = Path(__file__).resolve().parents[4] / "samples"


@pytest.mark.parametrize(
    ("filename", "parser"),
    [
        ("auth.log", LinuxAuthParser),
        ("access.log", WebAccessParser),
        ("windows_security.jsonl", WindowsEventParser),
        ("sysmon.json", WindowsEventParser),
        ("app_events.jsonl", GenericJsonParser),
        ("malformed_lines.log", LinuxAuthParser),
    ],
)
def test_samples_are_detected(filename: str, parser: type) -> None:
    assert detect_parser(read_sample(SAMPLES / filename)) is parser


def test_unrecognised_content_fails_detection(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("shopping list\nmilk\neggs\n")

    with pytest.raises(FormatDetectionError, match="choose a parser"):
        detect_parser(read_sample(path))


def test_registry_lookups() -> None:
    assert set(PARSERS) == {"linux_auth", "web_access", "windows", "json"}
    assert get_parser("json") is GenericJsonParser
    assert is_valid_parser_choice("auto")
    assert is_valid_parser_choice("web_access")
    assert not is_valid_parser_choice("syslog")
    with pytest.raises(KeyError):
        get_parser("nope")


def test_build_event_truncates_to_column_size(context: ParseContext) -> None:
    event = build_event(
        timestamp=context.reference_time,
        log_source=LogSource.JSON,
        raw_line="x",
        raw_event={},
        fields={"user.name": "u" * 1000, "message": "m" * 5000},
    )

    assert event.user.name is not None and len(event.user.name) == 255
    assert event.message is not None and len(event.message) == 5000  # TEXT column: no limit


def test_build_event_reports_invalid_values(context: ParseContext) -> None:
    with pytest.raises(ParseError, match=r"source\.port"):
        build_event(
            timestamp=context.reference_time,
            log_source=LogSource.JSON,
            raw_line="x",
            raw_event={},
            fields={"source.port": 99999},
        )


def test_parse_events_counts_add_up(context: ParseContext) -> None:
    stats = ParseStats()
    with LogFile.open(SAMPLES / "malformed_lines.log") as log_file:
        events = list(parse_events(log_file.stream, LinuxAuthParser(context), stats))

    assert len(events) == stats.events_parsed == 4
    assert stats.records_read == 7
    assert stats.malformed == 3
    assert stats.records_read == stats.events_parsed + stats.malformed + stats.skipped
    assert [sample.line for sample in stats.samples] == [2, 4, 6]
    assert stats.samples_as_json()[0]["excerpt"] == "this line is not syslog at all"


def test_parse_events_json_document(context: ParseContext) -> None:
    stats = ParseStats()
    with LogFile.open(SAMPLES / "sysmon.json") as log_file:
        events = list(parse_events(log_file.stream, WindowsEventParser(context), stats))

    assert len(events) == 7
    assert stats.malformed == 0


def test_parse_events_json_reports_bad_records(context: ParseContext) -> None:
    data = b'{"timestamp": "2026-10-12T09:00:00Z"}\n{broken\n{"no_time": 1}\n'
    stats = ParseStats()

    events = list(
        parse_events(io.BufferedReader(io.BytesIO(data)), GenericJsonParser(context), stats)
    )

    assert len(events) == 1
    assert stats.malformed == 2
    assert stats.samples[0].reason.startswith("invalid JSON")
    assert "timestamp" in stats.samples[1].reason


def test_malformed_samples_are_capped() -> None:
    stats = ParseStats()
    for number in range(MAX_MALFORMED_SAMPLES + 50):
        stats.add_malformed(number, "bad", "x" * 1000)

    assert stats.malformed == MAX_MALFORMED_SAMPLES + 50
    assert len(stats.samples) == MAX_MALFORMED_SAMPLES
    assert len(stats.samples[0].excerpt) == 300


def test_take_rows_batches(context: ParseContext) -> None:
    stats = ParseStats()
    with LogFile.open(SAMPLES / "auth.log") as log_file:
        events = parse_events(log_file.stream, LinuxAuthParser(context), stats)
        first = take_rows(events, 20)
        second = take_rows(events, 20)
        third = take_rows(events, 20)
        rest = take_rows(events, 20)

    assert [len(batch) for batch in (first, second, third, rest)] == [20, 20, 5, 0]
    assert {"event_hash", "raw_event", "timestamp"} <= set(first[0])
    assert first[0]["ingest_job_id"] is None


def test_take_rows_tags_the_ingestion_job(context: ParseContext) -> None:
    with LogFile.open(SAMPLES / "auth.log") as log_file:
        events = parse_events(log_file.stream, LinuxAuthParser(context), ParseStats())
        rows = take_rows(events, 5, ingest_job_id=42)

    assert {row["ingest_job_id"] for row in rows} == {42}
