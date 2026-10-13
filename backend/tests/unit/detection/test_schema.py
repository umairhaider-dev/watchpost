from __future__ import annotations

from datetime import timedelta
from textwrap import dedent
from typing import Any

import pytest
import yaml

from watchpost.db.models import RuleType, Severity
from watchpost.detection.compiler import DEFAULT_GROUP_BY, compile_rule_text
from watchpost.detection.errors import RuleError
from watchpost.detection.schema import load_rule, parse_duration

MATCH_RULE = dedent(
    """
    id: test-match
    title: Test match rule
    description: Finds failed SSH logins.
    severity: medium
    mitre:
      tactics: [TA0006]
      techniques: [T1110.001]
    logsource:
      source: linux_auth
    detection:
      selection:
        event.action: ssh_login
        event.outcome: failure
      condition: selection
    falsepositives:
      - Users mistyping their password
    """
)

SUCCESS = {
    "selection": {"event.action": "ssh_login", "event.outcome": "success"},
    "condition": "selection",
}
FAILURE = {
    "selection": {"event.action": "ssh_login", "event.outcome": "failure"},
    "condition": "selection",
}


def rule_with(**overrides: Any) -> str:
    """MATCH_RULE with top-level keys replaced; ``None`` removes a key."""
    data = yaml.safe_load(MATCH_RULE)
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return yaml.safe_dump(data, sort_keys=False)


def sequence_rule(**overrides: Any) -> str:
    settings: dict[str, Any] = {
        "id": "test-sequence",
        "type": "sequence",
        "group_by": ["source.ip"],
        "detection": None,
        "sequence": {
            "maxspan": "15m",
            "steps": [
                {"name": "failures", "count": 5, "detection": FAILURE},
                {"name": "success", "detection": SUCCESS},
            ],
        },
    }
    settings.update(overrides)
    return rule_with(**settings)


def test_valid_match_rule() -> None:
    rule = load_rule(MATCH_RULE)

    assert rule.id == "test-match"
    assert rule.severity is Severity.MEDIUM
    assert rule.type is RuleType.MATCH
    assert rule.enabled is True
    assert rule.tactics == ["TA0006"]
    assert rule.techniques == ["T1110.001"]
    assert rule.logsource.source == ["linux_auth"]
    assert rule.falsepositives == ["Users mistyping their password"]


def test_sigma_level_and_attack_tags_are_understood() -> None:
    sigma = dedent(
        """
        id: 5f1e8a2c-1111-4c4b-9e0e-3b2d7c9a0001
        title: Imported Sigma rule
        description: A rule as written for Sigma.
        status: experimental
        date: 2024/01/31
        level: high
        tags:
          - attack.credential_access
          - attack.t1003.001
          - attack.T1003
          - attack.not_a_tactic
          - cve.2021-1234
        detection:
          selection:
            TargetImage|endswith: lsass.exe
          condition: selection
        """
    )

    rule = load_rule(sigma)

    assert rule.severity is Severity.HIGH
    assert rule.tactics == ["TA0006"]
    assert rule.techniques == ["T1003.001", "T1003"]


def test_compiled_match_rule_defaults_to_grouping_by_host() -> None:
    compiled = compile_rule_text(MATCH_RULE)

    assert compiled.group_fields == DEFAULT_GROUP_BY
    assert compiled.log_sources == frozenset({"linux_auth"})
    assert compiled.matches(
        {"log_source": "linux_auth", "event_action": "ssh_login", "event_outcome": "failure"}
    )
    assert not compiled.matches(
        {"log_source": "web_access", "event_action": "ssh_login", "event_outcome": "failure"}
    )


def test_rule_without_logsource_accepts_every_source() -> None:
    compiled = compile_rule_text(rule_with(logsource=None))

    assert compiled.log_sources is None
    assert compiled.accepts_source({"log_source": "json"})


def test_threshold_rule() -> None:
    compiled = compile_rule_text(
        rule_with(
            id="test-threshold",
            type="threshold",
            group_by="source.ip",
            threshold={"count": 5, "timeframe": "2m", "distinct": "user.name"},
        )
    )

    spec = compiled.definition.threshold
    assert spec is not None and spec.timeframe == timedelta(minutes=2)
    assert compiled.distinct_resolver is not None
    assert compiled.group_values({"source_ip": "10.0.0.1"}) == ("10.0.0.1",)
    assert compiled.group_values({}) == (None,)


def test_sequence_rule() -> None:
    compiled = compile_rule_text(sequence_rule())

    assert [step.name for step in compiled.steps] == ["failures", "success"]
    assert compiled.steps[0].count == 5
    assert compiled.predicate is None
    with pytest.raises(RuleError, match="no single detection"):
        compiled.matches({})


def test_new_value_rule() -> None:
    compiled = compile_rule_text(
        rule_with(
            id="test-new-value",
            type="new_value",
            group_by=["user.name"],
            new_value={"field": "source.ip", "lookback": "30d"},
        )
    )

    assert compiled.value_resolver is not None
    assert compiled.definition.new_value is not None
    assert compiled.definition.new_value.require_history is True


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": "Bad_ID"}, "id"),
        ({"severity": "extreme"}, "severity"),
        ({"mitre": {"tactics": ["credential-access"]}}, "tactics"),
        ({"mitre": {"techniques": ["T99"]}}, "techniques"),
        ({"logsource": {"source": "syslog"}}, "logsource"),
        ({"type": "threshold"}, "needs a 'threshold' section"),
        ({"threshold": {"count": 5, "timeframe": "1m"}}, "only valid for threshold rules"),
        (
            {"type": "new_value", "new_value": {"field": "source.ip", "lookback": "7d"}},
            "need group_by",
        ),
        ({"unexpected": 1}, "unexpected"),
        ({"type": "threshold", "threshold": {"count": 1, "timeframe": "1m"}}, "count"),
        ({"type": "threshold", "threshold": {"count": 5, "timeframe": "soon"}}, "invalid duration"),
        ({"description": ""}, "description"),
        ({"severity": None}, "severity"),
    ],
)
def test_invalid_rules(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        load_rule(rule_with(**overrides))


@pytest.mark.parametrize(
    ("text", "message"),
    [("id: [unclosed", "invalid YAML"), ("- just\n- a list", "YAML mapping")],
)
def test_unparseable_yaml(text: str, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        load_rule(text)


@pytest.mark.parametrize(
    ("detection", "message"),
    [
        ({"selection": {"event.action": "x"}}, "needs a 'condition'"),
        ({"condition": "selection"}, "at least one selection"),
        ({"selection": {"event.action": "x"}, "condition": "other"}, "unknown selection"),
        ({"selection": {"source.ipp": "x"}, "condition": "selection"}, "unknown field"),
    ],
)
def test_detection_errors_surface_at_compile_time(detection: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        compile_rule_text(rule_with(detection=detection))


def test_sequence_rules_reject_duplicate_steps_and_top_level_detection() -> None:
    duplicate = sequence_rule()
    duplicate = duplicate.replace("name: success", "name: failures")
    with pytest.raises(RuleError, match="unique"):
        load_rule(duplicate)

    with pytest.raises(RuleError, match="per step"):
        load_rule(sequence_rule(detection=FAILURE))

    with pytest.raises(RuleError, match="need group_by"):
        load_rule(sequence_rule(group_by=[]))


def test_sigma_level_is_not_combined_with_severity() -> None:
    text = rule_with(level="low")  # severity: medium is still present

    with pytest.raises(RuleError, match="level"):
        load_rule(text)


def test_oversized_rule_is_rejected() -> None:
    with pytest.raises(RuleError, match="larger than"):
        load_rule("description: " + "x" * 70_000)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("2h", timedelta(hours=2)),
        (" 7d ", timedelta(days=7)),
    ],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected
    assert parse_duration(expected) == expected


@pytest.mark.parametrize("text", ["5", "5 minutes", "0m", "-1h", ""])
def test_parse_duration_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_duration(text)
