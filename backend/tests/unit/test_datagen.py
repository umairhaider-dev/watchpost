from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from watchpost import cli
from watchpost.datagen import GeneratorConfig, GeneratorError, Manifest, generate
from watchpost.datagen.formats import access_line, syslog_line
from watchpost.datagen.scenarios import indicator_feed
from watchpost.datagen.timeline import LogWriter, Timeline
from watchpost.datagen.world import WINDOWS_USERS, is_allowed_address
from watchpost.ingestion.parsers import ParseContext, get_parser
from watchpost.ingestion.pipeline import ParseStats, parse_events
from watchpost.ingestion.readers import LogFile
from watchpost.intel.feeds import parse_feed

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
END = datetime(2026, 10, 14, tzinfo=UTC)
# An IPv4 address that is not part of a version number or a longer token.
IPV4 = re.compile(r"(?<![\w./:-])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Manifest]:
    directory = tmp_path_factory.mktemp("generated")
    return directory, generate(GeneratorConfig(events=6_000, days=2, end=END, seed=11), directory)


def builtin_rule_ids() -> set[str]:
    return {yaml.safe_load(path.read_text())["id"] for path in RULES_DIR.rglob("*.yml")}


def parse_file(path: Path, parser_name: str) -> tuple[ParseStats, list[datetime]]:
    parser = get_parser(parser_name)(ParseContext(reference_time=END, default_host=None))
    stats = ParseStats()
    with LogFile.open(path) as log_file:
        timestamps = [event.timestamp for event in parse_events(log_file.stream, parser, stats)]
    return stats, timestamps


def test_writes_the_exact_number_of_events_and_every_line_parses(
    generated: tuple[Path, Manifest],
) -> None:
    directory, manifest = generated

    assert manifest.events == 6_000
    assert [item.name for item in manifest.files] == [
        "auth.log",
        "access.log",
        "windows_security.jsonl",
        "sysmon.jsonl",
    ]
    for item in manifest.files:
        stats, timestamps = parse_file(directory / item.name, item.parser)
        assert (stats.events_parsed, stats.malformed, stats.skipped) == (item.events, 0, 0)
        assert timestamps == sorted(timestamps), f"{item.name} is not in time order"
        assert manifest.start <= timestamps[0] and timestamps[-1] <= manifest.end


def test_uses_only_private_and_documentation_addresses(generated: tuple[Path, Manifest]) -> None:
    directory, manifest = generated

    found: set[str] = set()
    for item in manifest.files:
        found.update(IPV4.findall((directory / item.name).read_text(encoding="utf-8")))

    assert len(found) > 50
    assert [address for address in found if not is_allowed_address(address)] == []


def test_attacks_cover_every_builtin_rule(generated: tuple[Path, Manifest]) -> None:
    directory, manifest = generated
    saved = json.loads((directory / "scenarios.json").read_text(encoding="utf-8"))

    expected = {rule for scenario in manifest.scenarios for rule in scenario.rules}
    assert expected == builtin_rule_ids()
    assert [scenario["id"] for scenario in saved["scenarios"]] == [
        scenario.id for scenario in manifest.scenarios
    ]
    assert saved["events"] == 6_000
    for scenario in manifest.scenarios:
        assert manifest.start.timestamp() < scenario.start <= scenario.end
        assert scenario.end < manifest.end.timestamp()


def test_attack_lines_are_in_the_logs(generated: tuple[Path, Manifest]) -> None:
    directory, _ = generated
    auth = (directory / "auth.log").read_text(encoding="utf-8")
    web = (directory / "access.log").read_text(encoding="utf-8")
    sysmon = (directory / "sysmon.jsonl").read_text(encoding="utf-8")

    assert "Accepted password for backup from 203.0.113.45" in auth
    assert "COMMAND=/usr/bin/cat /etc/shadow" in auth
    assert "sqlmap/1.8.4" in web
    assert '"GrantedAccess":"0x1010"' in sysmon


def test_feed_lists_the_attack_infrastructure(generated: tuple[Path, Manifest]) -> None:
    directory, _ = generated
    feed = parse_feed((directory / "iocs.csv").read_bytes(), "iocs.csv")

    assert feed.problem_count == 0
    assert {entry.value for entry in feed.entries} >= {
        "203.0.113.45",
        "198.51.100.23",
        "update-check.example.net",
    }
    assert indicator_feed().startswith("value,type,description,confidence,tags\n")


def test_same_seed_same_logs(tmp_path: Path) -> None:
    config = GeneratorConfig(events=3_000, days=1, end=END, seed=5)
    generate(config, tmp_path / "a")
    generate(config, tmp_path / "b")
    generate(GeneratorConfig(events=3_000, days=1, end=END, seed=6), tmp_path / "c")

    for name in ("auth.log", "access.log", "sysmon.jsonl", "scenarios.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()
    assert (tmp_path / "a" / "access.log").read_bytes() != (
        tmp_path / "c" / "access.log"
    ).read_bytes()


def test_people_log_in_from_one_address_each() -> None:
    addresses = [user.address for user in WINDOWS_USERS]
    assert len(set(addresses)) == len(addresses)


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (GeneratorConfig(events=1_000), "at least 2,000"),
        (GeneratorConfig(days=0), "between 1 and 90"),
        (GeneratorConfig(days=91), "between 1 and 90"),
        (GeneratorConfig(events=2_000, days=90, end=END), "too few"),
    ],
)
def test_rejects_impossible_requests(tmp_path: Path, config: GeneratorConfig, message: str) -> None:
    with pytest.raises(GeneratorError, match=message):
        generate(config, tmp_path)


def test_defaults_to_ending_this_hour(tmp_path: Path) -> None:
    manifest = generate(GeneratorConfig(events=2_000, days=1), tmp_path)

    now = datetime.now(UTC)
    assert manifest.end <= now
    assert (now - manifest.end).total_seconds() < 3600
    assert (manifest.end.minute, manifest.end.second) == (0, 0)


def test_timeline_releases_lines_in_order_and_writer_drops_repeats(tmp_path: Path) -> None:
    timeline = Timeline()
    for timestamp, line in ((5.0, "c"), (1.0, "a"), (3.0, "b"), (9.0, "d")):
        timeline.add(timestamp, line)

    assert [line for _, line, _ in timeline.due(5.0)] == ["a", "b", "c"]
    assert len(timeline) == 1

    with (tmp_path / "out.log").open("w", encoding="utf-8") as handle:
        writer = LogWriter(handle)
        assert writer.write(10.2, "same") and not writer.write(10.7, "same")
        assert writer.write(11.0, "same")
    assert (writer.count, writer.last_timestamp) == (2, 11.0)


def test_formats_use_utc_and_fixed_month_names() -> None:
    moment = datetime(2026, 3, 9, 7, 5, 4, 250000, tzinfo=UTC).timestamp()

    assert syslog_line(moment, "web-01", "sudo", None, "x") == (
        "2026-03-09T07:05:04.250000+00:00 web-01 sudo: x"
    )
    assert access_line(moment, "10.0.0.1", None, "GET / HTTP/1.1", 200, 5, None, "ua") == (
        '10.0.0.1 - - [09/Mar/2026:07:05:04 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"'
    )


def test_cli_generates_logs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The CLI configures its own logging to stderr.
    args = ["generate-logs", "--output", str(tmp_path), "--events", "2500", "--days", "1"]

    assert cli.main([*args, "--seed", "3", "--end", "2026-10-14T06:00:00"]) == 0
    assert (tmp_path / "scenarios.json").exists()
    assert "Planted ssh-brute-force" in capsys.readouterr().err

    assert cli.main([*args, "--events", "10"]) == 1
    assert "Could not generate logs" in capsys.readouterr().err


def test_cli_rejects_a_bad_end_time(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["generate-logs", "--end", "yesterday"])

    assert "not an ISO 8601 time" in capsys.readouterr().err
