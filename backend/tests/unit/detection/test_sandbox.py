from __future__ import annotations

from pathlib import Path

import pytest

from watchpost.detection.compiler import compile_rule_text
from watchpost.detection.sandbox import try_rule_on_sample
from watchpost.ingestion.errors import FormatDetectionError

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
SAMPLES = Path(__file__).resolve().parents[4] / "samples"


def builtin(path: str) -> object:
    return compile_rule_text((RULES_DIR / path).read_text(encoding="utf-8"))


def test_hits_point_back_at_sample_lines() -> None:
    rule = compile_rule_text((RULES_DIR / "linux" / "ssh-brute-force.yml").read_text())
    sample = (SAMPLES / "auth.log").read_text()

    result = try_rule_on_sample(rule, sample)

    assert result.parser == "linux_auth"
    assert result.events_parsed == 46
    [hit] = result.hits
    assert hit.event_count == 10
    lines = sample.splitlines()
    assert all("Failed password" in lines[number - 1] for number in hit.event_ids)
    assert set(hit.event_ids) <= set(result.rows)


def test_malformed_lines_are_reported_with_explicit_parser() -> None:
    rule = compile_rule_text((RULES_DIR / "linux" / "user-created.yml").read_text())

    result = try_rule_on_sample(rule, (SAMPLES / "malformed_lines.log").read_text(), "linux_auth")

    assert result.malformed_count == 3
    assert [sample.line for sample in result.malformed] == [2, 4, 6]
    assert result.hits == []


def test_json_documents_use_record_numbers() -> None:
    rule = compile_rule_text((RULES_DIR / "sysmon" / "lsass-memory-access.yml").read_text())

    result = try_rule_on_sample(rule, (SAMPLES / "sysmon.json").read_text())

    assert result.parser == "windows"
    [hit] = result.hits
    assert hit.event_ids == [5]  # fifth record in the array


def test_large_samples_are_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("watchpost.detection.sandbox.MAX_SAMPLE_RECORDS", 5)
    rule = compile_rule_text((RULES_DIR / "linux" / "ssh-brute-force.yml").read_text())

    result = try_rule_on_sample(rule, (SAMPLES / "auth.log").read_text())

    assert result.truncated
    assert result.events_parsed == 5


def test_unknown_format_is_an_error() -> None:
    rule = compile_rule_text((RULES_DIR / "linux" / "ssh-brute-force.yml").read_text())

    with pytest.raises(FormatDetectionError):
        try_rule_on_sample(rule, "just some notes\nnothing like a log\n")
