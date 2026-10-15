"""Compiling Sigma detection selections into predicates.

A *selection* is one named entry of a rule's ``detection`` block:

* a mapping ``{field|modifier: value(s)}``: every field must match (AND);
  a list of values matches if any value matches, or all of them with
  the ``all`` modifier;
* a list of mappings: any one of them must match (OR);
* a list of plain strings: keywords searched in the event message.

String comparisons are case-insensitive, as in Sigma. ``*`` and ``?`` are
wildcards unless escaped with a backslash; any other backslash is literal,
so Windows paths such as ``\\lsass.exe`` need no escaping.

Supported modifiers: ``contains``, ``startswith``, ``endswith``, ``re``
(with ``i``, ``m``, ``s`` flags), ``all``, ``cidr``, ``gt``, ``gte``, ``lt``,
``lte`` and ``exists``.
"""

from __future__ import annotations

import ipaddress
import operator
import re
from collections.abc import Callable, Mapping
from typing import Any

from watchpost.detection.errors import RuleError
from watchpost.detection.fields import EventRow, resolver_for

Predicate = Callable[[EventRow], bool]
ValueTest = Callable[[Any], bool]

_STRING_MODIFIERS = frozenset({"contains", "startswith", "endswith"})
_REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_NUMERIC_MODIFIERS: dict[str, Callable[[float, float], bool]] = {
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
}
_VALUE_KINDS = _STRING_MODIFIERS | set(_NUMERIC_MODIFIERS) | {"re", "cidr"}
KNOWN_MODIFIERS = _VALUE_KINDS | set(_REGEX_FLAGS) | {"all", "exists"}
_BACKSLASH = chr(92)


def compile_selection(name: str, body: Any) -> Predicate:
    """Compile one named selection from a ``detection`` block."""
    if isinstance(body, dict):
        return _compile_mapping(name, body)
    if isinstance(body, list) and body:
        if all(isinstance(item, dict) for item in body):
            alternatives = [_compile_mapping(name, item) for item in body]
            return lambda row: any(alternative(row) for alternative in alternatives)
        if all(isinstance(item, str | int) and not isinstance(item, bool) for item in body):
            return _compile_keywords([str(item) for item in body])
    msg = (
        f"selection {name!r} must be a mapping of fields, a list of mappings or a list of keywords"
    )
    raise RuleError(msg)


def _compile_mapping(name: str, mapping: Mapping[Any, Any]) -> Predicate:
    if not mapping:
        msg = f"selection {name!r} is empty"
        raise RuleError(msg)
    tests = [compile_field_test(str(key), value) for key, value in mapping.items()]
    return lambda row: all(test(row) for test in tests)


def compile_field_test(key: str, expected: Any) -> Predicate:
    """Compile ``field|mod1|mod2: value(s)`` into a predicate over an event row."""
    field, *modifiers = key.split("|")
    if not field:
        msg = f"missing field name in {key!r}"
        raise RuleError(msg)
    unknown = [modifier for modifier in modifiers if modifier not in KNOWN_MODIFIERS]
    if unknown:
        msg = f"unknown modifier(s) {', '.join(unknown)} in {key!r}"
        raise RuleError(msg)
    resolve = resolver_for(field)

    if "exists" in modifiers:
        if not isinstance(expected, bool):
            msg = f"{key!r}: the exists modifier takes true or false"
            raise RuleError(msg)
        return lambda row: _present(resolve(row)) is expected

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        msg = f"{key!r} has an empty list of values"
        raise RuleError(msg)
    tests = [_compile_value(key, value, modifiers) for value in values]
    require_all = "all" in modifiers

    def predicate(row: EventRow) -> bool:
        actual = resolve(row)
        candidates = actual if isinstance(actual, list) else [actual]
        if require_all:
            return all(any(test(item) for item in candidates) for test in tests)
        return any(test(item) for test in tests for item in candidates)

    return predicate


def plain_needles(values: list[Any]) -> list[str] | None:
    """Lower-cased literals for plain string values; ``None`` if any value is not one."""
    needles: list[str] = []
    for value in values:
        if value is None or isinstance(value, dict | list):
            return None
        literal, has_wildcards = _unescape(_text(value))
        if has_wildcards:
            return None
        needles.append(literal.lower())
    return needles


def _compile_value(key: str, value: Any, modifiers: list[str]) -> ValueTest:
    kinds = [modifier for modifier in modifiers if modifier in _VALUE_KINDS]
    if len(kinds) > 1:
        msg = f"{key!r} combines incompatible modifiers {', '.join(kinds)}"
        raise RuleError(msg)
    kind = kinds[0] if kinds else None
    flags = [modifier for modifier in modifiers if modifier in _REGEX_FLAGS]
    if flags and kind != "re":
        msg = f"{key!r}: the {', '.join(flags)} modifier only applies to re"
        raise RuleError(msg)

    if value is None:
        if kind is not None:
            msg = f"{key!r}: null cannot be combined with {kind}"
            raise RuleError(msg)
        return lambda actual: not _present(actual)
    if isinstance(value, dict | list):
        msg = f"{key!r}: values must be strings, numbers or booleans"
        raise RuleError(msg)

    if kind == "re":
        return _regex_test(key, str(value), flags)
    if kind == "cidr":
        return _cidr_test(key, str(value))
    if kind in _NUMERIC_MODIFIERS:
        return _numeric_test(key, value, _NUMERIC_MODIFIERS[kind])
    return _string_test(_text(value), kind)


def _regex_test(key: str, pattern: str, flags: list[str]) -> ValueTest:
    combined = 0
    for flag in flags:
        combined |= _REGEX_FLAGS[flag]
    try:
        compiled = re.compile(pattern, combined)
    except re.error as exc:
        msg = f"{key!r}: invalid regular expression: {exc}"
        raise RuleError(msg) from exc
    return lambda actual: actual is not None and compiled.search(_text(actual)) is not None


def _cidr_test(key: str, value: str) -> ValueTest:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        msg = f"{key!r}: invalid CIDR range {value!r}"
        raise RuleError(msg) from exc

    def test(actual: Any) -> bool:
        if actual is None:
            return False
        try:
            return ipaddress.ip_address(str(actual)) in network
        except ValueError:
            return False

    return test


def _numeric_test(key: str, value: Any, compare: Callable[[float, float], bool]) -> ValueTest:
    try:
        limit = float(value)
    except (TypeError, ValueError) as exc:
        msg = f"{key!r}: {value!r} is not a number"
        raise RuleError(msg) from exc

    def test(actual: Any) -> bool:
        if actual is None or isinstance(actual, bool):
            return False
        try:
            return compare(float(actual), limit)
        except (TypeError, ValueError):
            return False

    return test


def _string_test(text: str, kind: str | None) -> ValueTest:
    literal, has_wildcards = _unescape(text)
    if has_wildcards:
        compiled = re.compile(_wildcard_regex(text, kind), re.IGNORECASE | re.DOTALL)
        return lambda actual: actual is not None and compiled.search(_text(actual)) is not None
    needle = literal.lower()
    if kind == "contains":
        return lambda actual: actual is not None and needle in _text(actual).lower()
    if kind == "startswith":
        return lambda actual: actual is not None and _text(actual).lower().startswith(needle)
    if kind == "endswith":
        return lambda actual: actual is not None and _text(actual).lower().endswith(needle)
    return lambda actual: actual is not None and _text(actual).lower() == needle


def _compile_keywords(keywords: list[str]) -> Predicate:
    tests = [_string_test(keyword, "contains") for keyword in keywords]

    def predicate(row: EventRow) -> bool:
        raw = row.get("raw_event")
        line = raw.get("line") if isinstance(raw, dict) else None
        haystacks = [text for text in (row.get("message"), line) if text]
        return any(test(text) for test in tests for text in haystacks)

    return predicate


# --------------------------------------------------------------------------
# Wildcards and escaping
# --------------------------------------------------------------------------


def _unescape(text: str) -> tuple[str, bool]:
    """Resolve Sigma escapes; report whether unescaped wildcards remain."""
    out: list[str] = []
    wildcards = False
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == _BACKSLASH and following in {"*", "?", _BACKSLASH}:
            out.append(following)
            index += 2
            continue
        if char in {"*", "?"}:
            wildcards = True
        out.append(char)
        index += 1
    return "".join(out), wildcards


def _wildcard_regex(text: str, kind: str | None) -> str:
    parts: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == _BACKSLASH and following in {"*", "?", _BACKSLASH}:
            parts.append(re.escape(following))
            index += 2
            continue
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        index += 1
    body = "".join(parts)
    if kind == "contains":
        return body
    if kind == "startswith":
        return f"^{body}"
    if kind == "endswith":
        return f"{body}$"
    return f"^{body}$"


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _present(value: Any) -> bool:
    return value is not None and value not in ("", [])
