from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import ColumnElement

from watchpost.detection.compiler import CompiledRule, compile_rule, compile_rule_text
from watchpost.detection.prefilter import (
    any_rule_filter,
    detection_filter,
    required_selections,
    rule_columns,
    rule_filter,
)
from watchpost.detection.store import load_rule_files

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"


def sql(clause: ColumnElement[bool] | None) -> str | None:
    if clause is None:
        return None
    return str(clause.compile(compile_kwargs={"literal_binds": True})).replace("\n", " ")


def make_rule(detection: dict[str, Any] | None, **extra: Any) -> CompiledRule:
    body: dict[str, Any] = {
        "id": "test-rule",
        "title": "Test rule",
        "description": "For tests.",
        "severity": "low",
        "logsource": {"source": "linux_auth"},
        **extra,
    }
    if detection is not None:
        body["detection"] = detection
    return compile_rule_text(yaml.safe_dump(body))


@pytest.mark.parametrize(
    ("condition", "required"),
    [
        ("login", ["login"]),
        ("login and success", ["login", "success"]),
        ("login AND NOT machine", ["login"]),
        ("not machine and login", ["login"]),
        ("not not login", ["login"]),
        ("login or success", []),
        ("(login and success)", []),
        ("1 of selection_*", []),
        ("all of them", []),
        ("login success", []),
        ("login and", []),
        (["login", "success"], []),
    ],
)
def test_required_selections(condition: object, required: list[str]) -> None:
    assert required_selections(condition) == required


def test_plain_values_become_sql() -> None:
    clause = detection_filter(
        {
            "login": {
                "event.action": ["SSH_LOGIN", "logon"],
                "event.outcome": "success",
                "http.response.status_code": [401, 403],
            },
            "machine": {"user.name|endswith": "$"},
            "condition": "login and not machine",
        }
    )

    assert sql(clause) == (
        "lower(events.event_action) IN ('logon', 'ssh_login') "
        "AND lower(events.event_outcome) IN ('success') "
        "AND events.http_status_code IN (401, 403)"
    )


@pytest.mark.parametrize(
    "selection",
    [
        {"user.name|endswith": "$"},  # modifiers are left to Python
        {"details.url_decoded": "/etc/passwd"},  # the raw record is not a column
        {"TargetImage": "lsass.exe"},
        {"host.name": "web-*"},  # wildcards
        {"user.name": "jürgen"},  # lower-casing outside ASCII may differ
        {"source.ip": "203.0.113.45"},  # address fields are not lower-cased text
        {"threat.matched": True},
        {"http.response.status_code": "404"},  # a string for a number column
        {"event.action": []},
    ],
)
def test_values_that_are_left_to_python(selection: dict[str, Any]) -> None:
    assert detection_filter({"selection": selection, "condition": "selection"}) is None


def test_selections_that_are_not_mappings_add_nothing() -> None:
    keywords = {"words": ["mimikatz"], "condition": "words"}
    either = {"any": [{"event.action": "a"}, {"event.action": "b"}], "condition": "any"}

    assert detection_filter(keywords) is None
    assert detection_filter(either) is None
    assert detection_filter(None) is None


def test_sequences_need_a_filter_for_every_step() -> None:
    sequence: dict[str, Any] = {
        "maxspan": "15m",
        "steps": [
            {
                "name": "failures",
                "count": 5,
                "detection": {"f": {"event.outcome": "failure"}, "condition": "f"},
            },
            {"name": "success", "detection": {"s": {"event.outcome": "success"}, "condition": "s"}},
        ],
    }
    filtered = make_rule(None, type="sequence", group_by=["source.ip"], sequence=sequence)
    sequence["steps"][1]["detection"] = {"s": {"user.name|endswith": "$"}, "condition": "s"}
    unfiltered = make_rule(None, type="sequence", group_by=["source.ip"], sequence=sequence)

    assert sql(rule_filter(filtered)) == (
        "lower(events.event_outcome) IN ('failure') OR lower(events.event_outcome) IN ('success')"
    )
    assert rule_filter(unfiltered) is None


def test_a_group_of_rules_is_only_filtered_when_every_rule_is() -> None:
    action = make_rule({"a": {"event.action": "sudo_command"}, "condition": "a"})
    code = make_rule({"c": {"event.code": "4625"}, "condition": "c"})
    anything = make_rule({"x": {"details.group": "sudo"}, "condition": "x"})

    assert sql(any_rule_filter([action, code])) == (
        "lower(events.event_action) IN ('sudo_command') OR lower(events.event_code) IN ('4625')"
    )
    assert any_rule_filter([action, anything]) is None
    assert any_rule_filter([]) is None


def test_rules_on_columns_only_skip_the_raw_record() -> None:
    columns_only = make_rule(
        {"login": {"event.action": "ssh_login"}, "condition": "login"},
        type="new_value",
        group_by=["user.name"],
        new_value={"field": "source.ip", "lookback": "30d"},
    )
    raw = make_rule({"x": {"details.group": "sudo"}, "condition": "x"})
    keywords = make_rule({"words": ["mimikatz"], "condition": "words"})

    names = [column.name for column in rule_columns(columns_only) or []]
    assert "raw_event" not in names
    assert {"id", "timestamp", "log_source", "event_action", "source_ip", "user_name"} <= set(names)
    assert rule_columns(raw) is None
    assert rule_columns(keywords) is None


def test_builtin_window_and_value_rules_are_narrowed() -> None:
    rules = {
        item.definition.id: compile_rule(item.definition) for item in load_rule_files(RULES_DIR)
    }

    assert sql(rule_filter(rules["ssh-brute-force"])) == (
        "lower(events.event_action) IN ('ssh_login') AND lower(events.event_outcome) IN ('failure')"
    )
    assert sql(rule_filter(rules["web-directory-scanning"])) == "events.http_status_code IN (404)"
    assert sql(rule_filter(rules["windows-logon-brute-force"])) == (
        "lower(events.event_code) IN ('4625')"
    )
    assert rule_filter(rules["ssh-brute-force-then-success"]) is not None
    assert rule_columns(rules["login-from-new-source-ip"]) is not None
