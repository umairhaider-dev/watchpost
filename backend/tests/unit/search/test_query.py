from __future__ import annotations

import pytest

from watchpost.search.query import (
    MAX_DEPTH,
    MAX_QUERY_LENGTH,
    MAX_TERMS,
    And,
    Comparison,
    Node,
    Not,
    Or,
    QueryError,
    Term,
    parse_query,
)


def term(
    field: str | None, value: str, *, quoted: bool = False, comparison: Comparison | None = None
) -> Term:
    return Term(field, value, quoted=quoted, comparison=comparison)


def strip(node: Node | None) -> Node | None:
    """The tree without source positions, for readable assertions."""
    if isinstance(node, Term):
        return Term(node.field, node.value, node.quoted, node.comparison)
    if isinstance(node, Not):
        child = strip(node.child)
        assert child is not None
        return Not(child)
    if isinstance(node, And | Or):
        children = tuple(child for child in map(strip, node.children) if child is not None)
        return And(children) if isinstance(node, And) else Or(children)
    return None


def parsed(text: str) -> Node | None:
    return strip(parse_query(text))


def test_empty_queries() -> None:
    assert parse_query("") is None
    assert parse_query("   ") is None


def test_field_and_free_text_terms() -> None:
    assert parsed("user.name:root") == term("user.name", "root")
    assert parsed("Failed") == term(None, "Failed")
    assert parsed('"Failed password"') == term(None, "Failed password", quoted=True)
    assert parsed('user.name:"svc account"') == term("user.name", "svc account", quoted=True)
    assert parsed('message:"say \\"hi\\""') == term("message", 'say "hi"', quoted=True)


def test_values_keep_colons_and_dashes() -> None:
    assert parsed("source.ip:2001:db8::1") == term("source.ip", "2001:db8::1")
    assert parsed("host.name:ws-fin-07") == term("host.name", "ws-fin-07")
    # A word that does not start like a field name is free text.
    assert parsed("12:00:01") == term(None, "12:00:01")


def test_comparisons() -> None:
    assert parsed("http.response.status_code:>=500") == term(
        "http.response.status_code", "500", comparison=">="
    )
    assert parsed("@timestamp:<2026-10-12") == term("@timestamp", "2026-10-12", comparison="<")
    assert parsed('@timestamp:>"2026-10-12 09:00"') == term(
        "@timestamp", "2026-10-12 09:00", quoted=True, comparison=">"
    )


def test_implicit_and_explicit_operators() -> None:
    a, b, c = term("a", "1"), term("b", "2"), term("c", "3")

    assert parsed("a:1 b:2") == And((a, b))
    assert parsed("a:1 AND b:2") == And((a, b))
    assert parsed("a:1 OR b:2 c:3") == Or((a, And((b, c))))
    assert parsed("(a:1 OR b:2) c:3") == And((Or((a, b)), c))
    assert parsed("NOT a:1") == Not(a)
    assert parsed("-a:1 b:2") == And((Not(a), b))
    assert parsed("NOT NOT a:1") == Not(Not(a))
    # Lower-case words are ordinary search terms.
    assert parsed("a:1 or b:2") == And((a, term(None, "or"), b))


def test_term_properties() -> None:
    assert term("host.name", "web-*").has_wildcards
    assert term("host.name", "web-??").has_wildcards
    assert not term("host.name", "web-*", quoted=True).has_wildcards
    assert term("host.name", "*").is_presence
    assert not term("host.name", "*", quoted=True).is_presence


@pytest.mark.parametrize(
    ("text", "message", "position"),
    [
        ('"unterminated', "missing closing quote", 0),
        ("a:1 (b:2", "missing ')'", 4),
        ("a:1)", "unexpected ')'", 3),
        ("a:1 OR", "the query ends too early", 6),
        ("AND a:1", "expected a search term, found AND", 0),
        ("user.name:", "no value after user.name:", 0),
        ("()", "expected a search term, found )", 1),
    ],
)
def test_syntax_errors_point_at_the_problem(text: str, message: str, position: int) -> None:
    with pytest.raises(QueryError) as caught:
        parse_query(text)

    assert caught.value.message == message
    assert caught.value.position == position
    assert f"(at character {position + 1})" in str(caught.value)


def test_size_limits() -> None:
    with pytest.raises(QueryError, match="limited to"):
        parse_query("a" * (MAX_QUERY_LENGTH + 1))
    with pytest.raises(QueryError, match="too many search terms"):
        parse_query(" ".join(["x"] * (MAX_TERMS + 1)))
    with pytest.raises(QueryError, match="too many nested parentheses"):
        parse_query("(" * (MAX_DEPTH + 1) + "x" + ")" * (MAX_DEPTH + 1))
    assert parse_query("(" * MAX_DEPTH + "x" + ")" * MAX_DEPTH) is not None
