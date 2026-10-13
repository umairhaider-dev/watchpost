from __future__ import annotations

from typing import Any

import pytest

from watchpost.detection.condition import compile_condition, tokenize
from watchpost.detection.errors import RuleError
from watchpost.detection.fields import resolver_for
from watchpost.detection.matchers import compile_field_test, compile_selection

BS = chr(92)

ROW: dict[str, Any] = {
    "log_source": "sysmon",
    "source_ip": "203.0.113.45",
    "user_name": "Administrator",
    "event_code": "10",
    "http_status_code": 404,
    "process_command_line": "powershell.exe -NoP -enc SQBFAFgA",
    "message": "Process accessed LSASS memory",
    "raw_event": {
        "line": "raw text with Mimikatz inside",
        "event_data": {
            "TargetImage": BS.join(["C:", "Windows", "System32", "lsass.exe"]),
            "GrantedAccess": "0x1010",
            "Hashes": ["MD5=AAA", "SHA256=BBB"],
        },
        "details": {"url_decoded": "/x?id=1' or '1'='1", "uid": 0},
        "original": {"service": "billing-api", "nested": {"level": "warn"}},
    },
}


def check(key: str, expected: Any, row: dict[str, Any] | None = None) -> bool:
    return compile_field_test(key, expected)(ROW if row is None else row)


# ------------------------------------------------------------- field resolution


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("source.ip", "203.0.113.45"),
        ("http.response.status_code", 404),
        ("TargetImage", BS.join(["C:", "Windows", "System32", "lsass.exe"])),
        ("event_data.GrantedAccess", "0x1010"),
        ("raw_event.event_data.GrantedAccess", "0x1010"),
        ("url_decoded", "/x?id=1' or '1'='1"),
        ("details.uid", 0),
        ("service", "billing-api"),
        ("original.nested.level", "warn"),
        ("NotThere", None),
        ("details.missing.deeper", None),
    ],
)
def test_field_resolution(name: str, value: Any) -> None:
    assert resolver_for(name)(ROW) == value


def test_typo_in_normalised_namespace_is_rejected() -> None:
    with pytest.raises(RuleError, match=r"unknown field 'source\.ipp'"):
        resolver_for("source.ipp")


def test_resolution_tolerates_missing_raw_event() -> None:
    assert resolver_for("TargetImage")({}) is None
    assert resolver_for("details.uid")({"raw_event": None}) is None


# ------------------------------------------------------------- equality and wildcards


@pytest.mark.parametrize(
    ("key", "expected", "result"),
    [
        ("user.name", "administrator", True),  # case-insensitive
        ("user.name", "admin", False),
        ("user.name", ["root", "ADMINISTRATOR"], True),  # list = any
        ("event.code", 10, True),  # numbers compare as text
        ("user.name", "admin*", True),
        ("user.name", "admin?strator", True),
        ("user.name", "*strator", True),
        ("user.name", "root*", False),
        ("TargetImage", "*" + BS + "lsass.exe", True),
        ("source.ip", None, False),  # null means "missing"
        ("destination.ip", None, True),
    ],
)
def test_plain_values(key: str, expected: Any, result: bool) -> None:
    assert check(key, expected) is result


def test_escaped_wildcards_are_literal() -> None:
    row = {"message": "price is 5* off"}

    assert check("message", "price is 5" + BS + "* off", row)
    assert not check("message", "price is 5" + BS + "* on", row)
    assert check("message", "price is 5*", row)  # unescaped: wildcard


def test_backslash_before_letters_is_literal() -> None:
    assert check("TargetImage|endswith", BS + "lsass.exe")
    assert check("TargetImage|contains", BS + "System32" + BS)


# ------------------------------------------------------------- modifiers


@pytest.mark.parametrize(
    ("key", "expected", "result"),
    [
        ("process.command_line|contains", "-ENC", True),
        ("process.command_line|contains", ["-enc ", "-EncodedCommand"], True),
        ("process.command_line|contains", "bypass", False),
        ("process.command_line|startswith", "PowerShell", True),
        ("process.command_line|endswith", "sqbfafga", True),
        ("process.command_line|contains|all", ["-nop", "-enc"], True),
        ("process.command_line|contains|all", ["-nop", "-w hidden"], False),
        ("process.command_line|contains", "-e*c", True),  # wildcard inside contains
        ("process.command_line|re", r"-enc\s+[A-Za-z0-9+/=]{6,}", True),
        ("process.command_line|re", r"-ENC\s", False),  # re is case-sensitive...
        ("process.command_line|re|i", r"-ENC\s", True),  # ...unless |i
        ("source.ip|cidr", "203.0.113.0/24", True),
        ("source.ip|cidr", ["10.0.0.0/8", "192.168.0.0/16"], False),
        ("http.response.status_code|gte", 400, True),
        ("http.response.status_code|lt", 400, False),
        ("http.response.status_code|gt", "403", True),
        ("Hashes|contains", "sha256=bbb", True),  # list values: any element
        ("user.name|exists", True, True),
        ("destination.ip|exists", False, True),
        ("details.uid|lte", 0, True),
    ],
)
def test_modifiers(key: str, expected: Any, result: bool) -> None:
    assert check(key, expected) is result


@pytest.mark.parametrize(
    ("key", "row"),
    [
        ("source.ip|cidr", {"source_ip": "not-an-ip"}),
        ("source.ip|cidr", {"source_ip": None}),
        ("http.response.status_code|gt", {"http_status_code": "n/a"}),
        ("http.response.status_code|gt", {"http_status_code": True}),
        ("process.command_line|re", {}),
        ("process.command_line|contains", {}),
    ],
)
def test_modifiers_never_match_unusable_values(key: str, row: dict[str, Any]) -> None:
    value = "10.0.0.0/8" if "cidr" in key else ("1" if "gt" in key else "x")

    assert check(key, value, row) is False


@pytest.mark.parametrize(
    ("key", "expected", "message"),
    [
        ("user.name|base64", "x", "unknown modifier"),
        ("user.name|contains|re", "x", "incompatible"),
        ("user.name|i", "x", "only applies to re"),
        ("user.name|re", "(", "invalid regular expression"),
        ("source.ip|cidr", "10.0.0.0/99", "invalid CIDR"),
        ("http.response.status_code|gt", "lots", "not a number"),
        ("user.name|exists", "yes", "exists modifier"),
        ("user.name", [], "empty list"),
        ("user.name|contains", None, "null cannot"),
        ("user.name", {"nested": 1}, "strings, numbers or booleans"),
        ("|contains", "x", "missing field"),
    ],
)
def test_invalid_field_tests(key: str, expected: Any, message: str) -> None:
    with pytest.raises(RuleError, match=message):
        compile_field_test(key, expected)


# ------------------------------------------------------------- selections


def test_mapping_selection_requires_every_field() -> None:
    selection = compile_selection("sel", {"user.name": "administrator", "event.code": "10"})
    wrong = compile_selection("sel", {"user.name": "administrator", "event.code": "11"})

    assert selection(ROW)
    assert not wrong(ROW)


def test_list_of_mappings_is_or() -> None:
    selection = compile_selection("sel", [{"event.code": "4625"}, {"event.code": "10"}])

    assert selection(ROW)


def test_keyword_selection_searches_message_and_raw_line() -> None:
    assert compile_selection("kw", ["LSASS"])(ROW)
    assert compile_selection("kw", ["mimikatz"])(ROW)
    assert not compile_selection("kw", ["cobalt"])(ROW)


@pytest.mark.parametrize("body", [{}, [], "text", [{"a": 1}, "mixed"], [True]])
def test_invalid_selections(body: Any) -> None:
    with pytest.raises(RuleError):
        compile_selection("sel", body)


# ------------------------------------------------------------- conditions


def selections(**values: bool) -> dict[str, Any]:
    return {name: (lambda _row, v=value: v) for name, value in values.items()}


@pytest.mark.parametrize(
    ("condition", "result"),
    [
        ("a", True),
        ("a and b", False),
        ("a or b", True),
        ("a and not b", True),
        ("not a", False),
        ("(a or b) and c", True),
        ("a and (b or not c)", False),
        ("a or b and c", True),  # and binds tighter than or
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("any of them", True),
        ("all of them", False),
        ("a AND NOT b", True),  # keywords are case-insensitive
    ],
)
def test_conditions(condition: str, result: bool) -> None:
    named = selections(a=True, b=False, c=True, sel_one=True, sel_two=False)

    assert compile_condition(condition, named)({}) is result


def test_them_skips_underscore_selections() -> None:
    named = selections(a=True, _helper=False)

    assert compile_condition("all of them", named)({})


def test_condition_list_is_or() -> None:
    assert compile_condition(["a", "b"], selections(a=False, b=True))({})


@pytest.mark.parametrize(
    ("condition", "message"),
    [
        ("", "empty"),
        ([], "empty"),
        ("a and", "ends unexpectedly"),
        ("(a or b", "missing"),
        ("a b", "unexpected 'b'"),
        ("missing", "unknown selection"),
        ("1 of nothing_*", "matches no selection"),
        ("and a", "unexpected 'and'"),
        ("a | b", "unexpected character"),
        (")", "unexpected"),
    ],
)
def test_invalid_conditions(condition: str | list[str], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        compile_condition(condition, selections(a=True, b=True))


def test_tokenize() -> None:
    assert tokenize("(sel_1 or sel-2) and not filter.x") == [
        "(",
        "sel_1",
        "or",
        "sel-2",
        ")",
        "and",
        "not",
        "filter.x",
    ]
