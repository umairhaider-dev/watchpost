from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import yaml

from watchpost.detection.compiler import CompiledRule, compile_rule_text
from watchpost.detection.engine import (
    MAX_EVIDENCE_PER_HIT,
    Hit,
    evaluate,
    evaluate_match,
    evaluate_new_value,
    evaluate_sequence,
    evaluate_threshold,
    row_with_id,
)

START = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
FAILED = {"event_action": "ssh_login", "event_outcome": "failure"}
SUCCESS = {"event_action": "ssh_login", "event_outcome": "success"}


def row(event_id: int, seconds: float, **columns: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": event_id,
        "timestamp": START + timedelta(seconds=seconds),
        "log_source": "linux_auth",
        "host_name": "web-01",
        "source_ip": "203.0.113.45",
        "user_name": "root",
        "raw_event": {},
    }
    base.update(columns)
    return base


def rule(rule_type: str = "match", **extra: Any) -> CompiledRule:
    data: dict[str, Any] = {
        "id": f"test-{rule_type.replace('_', '-')}",
        "title": f"Test {rule_type}",
        "description": "Test rule.",
        "severity": "high",
        "type": rule_type,
        "logsource": {"source": "linux_auth"},
    }
    if rule_type != "sequence":
        data["detection"] = {
            "selection": {"event.action": "ssh_login", "event.outcome": "failure"},
            "condition": "selection",
        }
    data.update(extra)
    return compile_rule_text(yaml.safe_dump(data))


def failures(
    count: int, *, every: float = 10, start_id: int = 1, offset: float = 0, **cols: Any
) -> list[dict[str, Any]]:
    return [row(start_id + n, offset + n * every, **FAILED, **cols) for n in range(count)]


# ------------------------------------------------------------- match


def test_match_groups_hits_by_entity() -> None:
    compiled = rule(group_by=["source.ip"])
    rows = [
        *failures(3),
        *failures(2, start_id=10, source_ip="198.51.100.7"),
        row(20, 5, **SUCCESS),
        row(21, 5, log_source="web_access", **FAILED),
    ]

    hits = {hit.group_label: hit for hit in evaluate_match(compiled, rows)}

    assert set(hits) == {"203.0.113.45", "198.51.100.7"}
    first = hits["203.0.113.45"]
    assert first.event_ids == [1, 2, 3]
    assert first.event_count == 3
    assert first.first_seen == START
    assert first.last_seen == START + timedelta(seconds=20)
    assert first.group == (("source.ip", "203.0.113.45"),)
    assert first.group_key == "test-match|source.ip=203.0.113.45"


def test_match_defaults_to_grouping_by_host_and_tracks_latest_entities() -> None:
    rows = [row(1, 0, **FAILED, user_name="alice"), row(2, 30, **FAILED, user_name="bob")]

    [hit] = evaluate_match(rule(), rows)

    assert hit.group == (("host.name", "web-01"),)
    assert hit.user_name == "bob"
    assert hit.host_name == "web-01"
    assert hit.source_ip == "203.0.113.45"


def test_duplicate_rows_are_counted_once() -> None:
    [hit] = evaluate_match(rule(), [row(1, 0, **FAILED), row(1, 0, **FAILED)])

    assert hit.event_count == 1


def test_evidence_is_capped_but_count_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("watchpost.detection.engine.MAX_EVIDENCE_PER_HIT", 5)

    [hit] = evaluate_match(rule(), failures(8, every=1))

    assert len(hit.event_ids) == 5
    assert hit.event_count == 8
    assert MAX_EVIDENCE_PER_HIT == 10_000


def test_missing_group_values_and_long_keys() -> None:
    long_name = "h" * 600
    [hit] = evaluate_match(rule(), [row(1, 0, **FAILED, host_name=long_name)])
    [anonymous] = evaluate_match(rule(), [row(1, 0, **FAILED, host_name=None)])

    assert hit.group_key.startswith("test-match|sha256=")
    assert len(hit.group_key) < 100
    assert anonymous.group_key == "test-match|host.name=-"
    assert anonymous.group_label == ""


# ------------------------------------------------------------- threshold


THRESHOLD = {"group_by": ["source.ip"], "threshold": {"count": 5, "timeframe": "1m"}}


def test_threshold_fires_when_enough_events_fall_in_the_window() -> None:
    [hit] = evaluate_threshold(rule("threshold", **THRESHOLD), failures(5, every=10))

    assert hit.event_count == 5
    assert hit.group_label == "203.0.113.45"


def test_threshold_does_not_fire_below_count_or_outside_window() -> None:
    compiled = rule("threshold", **THRESHOLD)

    assert evaluate_threshold(compiled, failures(4, every=10)) == []
    assert evaluate_threshold(compiled, failures(5, every=20)) == []  # spans 80 s > 1 m


def test_threshold_counts_per_group() -> None:
    rows = failures(3) + failures(3, start_id=10, source_ip="198.51.100.7")

    assert evaluate_threshold(rule("threshold", **THRESHOLD), rows) == []


def test_long_burst_becomes_one_hit_and_separate_bursts_two() -> None:
    compiled = rule("threshold", **THRESHOLD)
    burst = failures(60, every=5)  # five minutes of constant attempts
    later = failures(5, every=5, start_id=500, offset=3600)

    hits = evaluate_threshold(compiled, burst + later)

    assert [hit.event_count for hit in hits] == [60, 5]


def test_events_outside_qualifying_windows_are_not_evidence() -> None:
    compiled = rule("threshold", **THRESHOLD)
    stray = [row(100, -600, **FAILED)]  # ten minutes earlier, on its own

    [hit] = evaluate_threshold(compiled, stray + failures(5))

    assert 100 not in hit.event_ids


def test_threshold_distinct_counts_values() -> None:
    compiled = rule(
        "threshold",
        group_by=["source.ip"],
        threshold={"count": 3, "timeframe": "5m", "distinct": "user.name"},
    )
    same_user = failures(10, every=5)
    spray = [row(n, n * 5, **FAILED, user_name=f"user{n}") for n in range(1, 4)]
    unknown = [row(n, n * 5, **FAILED, user_name=None) for n in range(10, 15)]

    assert evaluate_threshold(compiled, same_user) == []
    assert evaluate_threshold(compiled, unknown) == []
    [hit] = evaluate_threshold(compiled, spray)
    assert hit.event_count == 3


def test_threshold_distinct_window_forgets_old_values() -> None:
    compiled = rule(
        "threshold",
        group_by=["source.ip"],
        threshold={"count": 3, "timeframe": "1m", "distinct": "user.name"},
    )
    rows = [
        row(1, 0, **FAILED, user_name="a"),
        row(2, 10, **FAILED, user_name="b"),
        row(3, 200, **FAILED, user_name="c"),  # a and b have left the window
        row(4, 210, **FAILED, user_name="c"),
    ]

    assert evaluate_threshold(compiled, rows) == []


def test_threshold_scope_drops_bursts_made_only_of_old_events() -> None:
    compiled = rule("threshold", **THRESHOLD)
    old_burst = failures(5, every=5)
    new_burst = failures(5, every=5, start_id=100, offset=3600)

    hits = evaluate_threshold(compiled, old_burst + new_burst, in_scope=lambda r: r["id"] >= 100)

    assert len(hits) == 1
    assert hits[0].event_ids[0] == 100


def test_threshold_rejects_rules_of_other_types() -> None:
    with pytest.raises(ValueError, match="no threshold"):
        evaluate_threshold(rule(), [])


# ------------------------------------------------------------- sequence


def sequence_rule(fail_count: int = 3, maxspan: str = "10m") -> CompiledRule:
    return rule(
        "sequence",
        group_by=["source.ip"],
        sequence={
            "maxspan": maxspan,
            "steps": [
                {
                    "name": "failures",
                    "count": fail_count,
                    "detection": {"s": {"event.outcome": "failure"}, "condition": "s"},
                },
                {
                    "name": "success",
                    "detection": {"s": {"event.outcome": "success"}, "condition": "s"},
                },
            ],
        },
    )


def test_sequence_fires_for_failures_then_success() -> None:
    rows = [*failures(3, every=10), row(10, 60, **SUCCESS)]

    [hit] = evaluate_sequence(sequence_rule(), rows)

    assert hit.event_ids == [1, 2, 3, 10]
    assert hit.group_label == "203.0.113.45"


@pytest.mark.parametrize(
    "rows",
    [
        [*failures(2, every=10), row(10, 60, **SUCCESS)],  # not enough failures
        [row(10, 0, **SUCCESS), *failures(3, every=10, offset=10)],  # wrong order
        [*failures(3, every=10), row(10, 3600, **SUCCESS)],  # too far apart
        [*failures(3), row(10, 60, **SUCCESS, source_ip="198.51.100.7")],  # other entity
        [*failures(3), row(10, 60, **SUCCESS, log_source="web_access")],  # wrong source
    ],
)
def test_sequence_does_not_fire(rows: list[dict[str, Any]]) -> None:
    assert evaluate_sequence(sequence_rule(), rows) == []


def test_sequence_skips_events_without_an_entity() -> None:
    rows = [*failures(3, source_ip=None), row(10, 60, **SUCCESS, source_ip=None)]

    assert evaluate_sequence(sequence_rule(), rows) == []


def test_repeated_successes_merge_into_one_hit() -> None:
    rows = [*failures(3, every=10), row(10, 60, **SUCCESS), row(11, 90, **SUCCESS)]

    [hit] = evaluate_sequence(sequence_rule(), rows)

    assert hit.event_ids == [1, 2, 3, 10]  # greedy match ends at the first success


def test_sequence_scope() -> None:
    rows = [*failures(3, every=10), row(10, 60, **SUCCESS)]

    assert evaluate_sequence(sequence_rule(), rows, in_scope=lambda r: r["id"] > 100) == []


def test_sequence_rejects_rules_of_other_types() -> None:
    with pytest.raises(ValueError, match="no sequence"):
        evaluate_sequence(rule(), [])


# ------------------------------------------------------------- new_value


def new_value_rule(require_history: bool = True) -> CompiledRule:
    return rule(
        "new_value",
        detection={
            "s": {"event.action": "ssh_login", "event.outcome": "success"},
            "condition": "s",
        },
        group_by=["user.name"],
        new_value={"field": "source.ip", "lookback": "7d", "require_history": require_history},
    )


def login(event_id: int, days: float, ip: str, user: str = "alice") -> dict[str, Any]:
    return row(event_id, days * 86400, **SUCCESS, source_ip=ip, user_name=user)


def test_new_source_ip_for_a_user_with_history() -> None:
    rows = [login(1, 0, "10.0.0.5"), login(2, 1, "10.0.0.5"), login(3, 2, "203.0.113.45")]

    [hit] = evaluate_new_value(new_value_rule(), rows, rows)

    assert hit.event_ids == [3]
    assert hit.group == (("user.name", "alice"), ("source.ip", "203.0.113.45"))


def test_known_ip_and_first_ever_login_do_not_fire() -> None:
    rows = [login(1, 0, "10.0.0.5"), login(2, 1, "10.0.0.5"), login(3, 1, "10.0.0.9", "bob")]

    assert evaluate_new_value(new_value_rule(), rows, rows) == []


def test_without_required_history_the_first_login_fires() -> None:
    rows = [login(3, 1, "10.0.0.9", "bob")]

    [hit] = evaluate_new_value(new_value_rule(require_history=False), rows, rows)

    assert hit.user_name == "bob"


def test_history_older_than_lookback_is_forgotten() -> None:
    rows = [login(1, 0, "10.0.0.5"), login(2, 20, "10.0.0.6"), login(3, 21, "10.0.0.5")]

    hits = evaluate_new_value(new_value_rule(), rows, rows)

    # Day 20: 10.0.0.6 has no history within 7 days, so require_history skips it.
    # Day 21: 10.0.0.5 was last seen on day 0, outside the lookback, so it is new.
    assert [hit.event_ids for hit in hits] == [[3]]


def test_failed_logins_do_not_count_as_history() -> None:
    rows = [
        row(1, 0, **FAILED, source_ip="203.0.113.45", user_name="alice"),
        login(2, 1, "10.0.0.5"),
        login(3, 2, "203.0.113.45"),
    ]

    [hit] = evaluate_new_value(new_value_rule(), rows, rows)

    assert hit.event_ids == [3]


def test_new_value_only_reports_targets() -> None:
    history = [login(1, 0, "10.0.0.5"), login(2, 1, "203.0.113.45")]

    assert evaluate_new_value(new_value_rule(), history, []) == []


def test_new_value_rejects_rules_of_other_types() -> None:
    with pytest.raises(ValueError, match="no new_value"):
        evaluate_new_value(rule(), [], [])


# ------------------------------------------------------------- dispatch


@pytest.mark.parametrize(
    ("compiled", "rows", "expected"),
    [
        (rule(), failures(1), 1),
        (rule("threshold", **THRESHOLD), failures(5), 1),
        (sequence_rule(), [*failures(3), row(10, 60, **SUCCESS)], 1),
        (new_value_rule(), [login(1, 0, "10.0.0.5"), login(2, 1, "10.0.0.6")], 1),
    ],
)
def test_evaluate_dispatches_on_type(
    compiled: CompiledRule, rows: list[dict[str, Any]], expected: int
) -> None:
    hits = evaluate(compiled, rows)

    assert len(hits) == expected
    assert all(isinstance(hit, Hit) for hit in hits)


def test_row_with_id() -> None:
    assert row_with_id({"a": 1}, 7) == {"a": 1, "id": 7}
