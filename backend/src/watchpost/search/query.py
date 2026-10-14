"""Parsing event search queries.

The syntax is a small subset of what Kibana and Splunk users expect::

    user.name:root AND event.outcome:failure
    source.ip:203.0.113.0/24 OR host:"web-01"
    http.response.status_code:>=500 -url.original:*healthz*
    (event.action:ssh_login OR event.action:sudo) NOT user.name:deploy
    "Failed password"

* ``field:value`` matches a field; ``value`` alone searches the event text.
* ``AND`` (or just a space), ``OR`` and ``NOT`` / a leading ``-``, with
  parentheses. Operators are upper case, so ``or`` is an ordinary word.
* Values can be quoted to include spaces or brackets; ``\\"`` escapes a quote.
* ``*`` and ``?`` are wildcards; ``field:*`` means the field is present.
* ``>``, ``>=``, ``<`` and ``<=`` compare numbers and timestamps.

This module only builds the syntax tree; :mod:`watchpost.search.compiler`
checks field names and value types.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

MAX_QUERY_LENGTH = 2000
MAX_TERMS = 64
MAX_DEPTH = 16

Comparison = Literal[">=", "<=", ">", "<"]
TokenKind = Literal["(", ")", "AND", "OR", "NOT", "TERM"]

_FIELD = re.compile(r"[A-Za-z_@][A-Za-z0-9_.@-]*")
_COMPARISONS: tuple[Comparison, ...] = (">=", "<=", ">", "<")
_BRACKETS: dict[str, TokenKind] = {"(": "(", ")": ")"}
_OPERATORS: dict[str, TokenKind] = {"AND": "AND", "OR": "OR", "NOT": "NOT"}


class QueryError(ValueError):
    """The query cannot be parsed; ``position`` is the offending character offset."""

    def __init__(self, message: str, position: int) -> None:
        super().__init__(f"{message} (at character {position + 1})")
        self.message = message
        self.position = position


@dataclass(frozen=True, slots=True)
class Term:
    """One search condition. ``field`` is ``None`` for free text."""

    field: str | None
    value: str
    quoted: bool = False
    comparison: Comparison | None = None
    position: int = 0

    @property
    def has_wildcards(self) -> bool:
        return not self.quoted and ("*" in self.value or "?" in self.value)

    @property
    def is_presence(self) -> bool:
        return not self.quoted and self.value == "*"


@dataclass(frozen=True, slots=True)
class Not:
    child: Node


@dataclass(frozen=True, slots=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Or:
    children: tuple[Node, ...]


Node = Term | Not | And | Or


@dataclass(frozen=True, slots=True)
class _Token:
    kind: TokenKind
    position: int
    term: Term | None = None


def _read_quoted(text: str, start: int) -> tuple[str, int]:
    """The unescaped contents of a quoted string at ``start``, and the index after it."""
    chars: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            chars.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    msg = "missing closing quote"
    raise QueryError(msg, start)


def _read_word(text: str, start: int) -> tuple[str, int]:
    index = start
    while index < len(text) and not text[index].isspace() and text[index] not in '()"':
        index += 1
    return text[start:index], index


def _term(text: str, start: int) -> tuple[Term, int]:
    """Read ``field:value``, ``field:"value"``, ``"phrase"`` or ``word`` at ``start``."""
    if text[start] == '"':
        value, end = _read_quoted(text, start)
        return Term(None, value, quoted=True, position=start), end
    word, end = _read_word(text, start)
    field, colon, rest = word.partition(":")
    if not colon or not _FIELD.fullmatch(field):
        return Term(None, word, position=start), end

    value_start = start + len(field) + 1
    comparison: Comparison | None = None
    for operator in _COMPARISONS:
        if rest.startswith(operator):
            comparison = operator
            value_start += len(operator)
            break
    if value_start < len(text) and text[value_start] == '"' and end == value_start:
        value, end = _read_quoted(text, value_start)
        return Term(field, value, quoted=True, comparison=comparison, position=start), end
    value = text[value_start:end]
    if not value:
        msg = f"no value after {field}:"
        raise QueryError(msg, start)
    return Term(field, value, comparison=comparison, position=start), end


def tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
        elif char in _BRACKETS:
            tokens.append(_Token(_BRACKETS[char], index))
            index += 1
        elif char == "-" and index + 1 < len(text) and not text[index + 1].isspace():
            tokens.append(_Token("NOT", index))
            index += 1
        else:
            word, end = _read_word(text, index)
            if word in _OPERATORS:
                tokens.append(_Token(_OPERATORS[word], index))
                index = end
            else:
                term, index = _term(text, index)
                tokens.append(_Token("TERM", term.position, term))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token], length: int) -> None:
        self.tokens = tokens
        self.index = 0
        self.length = length
        self.terms = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> _Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def parse(self) -> Node:
        node = self.or_expr(0)
        token = self.peek()
        if token is not None:
            msg = "unexpected ')'" if token.kind == ")" else f"unexpected {token.kind}"
            raise QueryError(msg, token.position)
        return node

    def or_expr(self, depth: int) -> Node:
        children = [self.and_expr(depth)]
        while (token := self.peek()) is not None and token.kind == "OR":
            self.take()
            children.append(self.and_expr(depth))
        return children[0] if len(children) == 1 else Or(tuple(children))

    def and_expr(self, depth: int) -> Node:
        children = [self.unary(depth)]
        while (token := self.peek()) is not None and token.kind not in {"OR", ")"}:
            if token.kind == "AND":
                self.take()
            children.append(self.unary(depth))
        return children[0] if len(children) == 1 else And(tuple(children))

    def unary(self, depth: int) -> Node:
        token = self.peek()
        if token is not None and token.kind == "NOT":
            self.take()
            return Not(self.unary(depth))
        return self.primary(depth)

    def primary(self, depth: int) -> Node:
        token = self.peek()
        if token is None:
            msg = "the query ends too early"
            raise QueryError(msg, self.length)
        if token.kind == "(":
            if depth >= MAX_DEPTH:
                msg = f"too many nested parentheses (at most {MAX_DEPTH})"
                raise QueryError(msg, token.position)
            self.take()
            node = self.or_expr(depth + 1)
            closing = self.peek()
            if closing is None or closing.kind != ")":
                msg = "missing ')'"
                raise QueryError(msg, token.position)
            self.take()
            return node
        if token.kind == "TERM" and token.term is not None:
            self.take()
            self.terms += 1
            if self.terms > MAX_TERMS:
                msg = f"too many search terms (at most {MAX_TERMS})"
                raise QueryError(msg, token.position)
            return token.term
        msg = f"expected a search term, found {token.kind}"
        raise QueryError(msg, token.position)


def parse_query(text: str) -> Node | None:
    """The syntax tree of a query; ``None`` for an empty query.

    Raises:
        QueryError: with the position of the problem.
    """
    if len(text) > MAX_QUERY_LENGTH:
        msg = f"queries are limited to {MAX_QUERY_LENGTH} characters"
        raise QueryError(msg, MAX_QUERY_LENGTH)
    tokens = tokenize(text)
    if not tokens:
        return None
    return _Parser(tokens, len(text)).parse()
