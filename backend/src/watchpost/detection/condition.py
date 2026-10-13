"""Parsing Sigma ``condition`` expressions.

Grammar (case-insensitive keywords)::

    expression := term ("or" term)*
    term       := factor ("and" factor)*
    factor     := "not" factor | "(" expression ")" | quantified | NAME
    quantified := ("1" | "any" | "all") "of" (PATTERN | "them")

``PATTERN`` may use ``*`` (``1 of selection_*``). ``them`` means every
selection except those whose name starts with an underscore.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping, Sequence

from watchpost.detection.errors import RuleError
from watchpost.detection.matchers import Predicate

_TOKEN = re.compile(r"\s*(?:(?P<paren>[()])|(?P<word>[A-Za-z0-9_*.\-]+))")
_KEYWORDS = frozenset({"and", "or", "not", "of"})


def tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    text = condition.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None or match.end() == position:
            msg = f"unexpected character {text[position]!r} in condition {condition!r}"
            raise RuleError(msg)
        tokens.append(match["paren"] or match["word"])
        position = match.end()
    return tokens


class _Parser:
    def __init__(self, condition: str, selections: Mapping[str, Predicate]) -> None:
        self.condition = condition
        self.tokens = tokenize(condition)
        self.position = 0
        self.selections = selections

    def parse(self) -> Predicate:
        if not self.tokens:
            msg = "condition is empty"
            raise RuleError(msg)
        predicate = self._expression()
        if self.position != len(self.tokens):
            msg = f"unexpected {self.tokens[self.position]!r} in condition {self.condition!r}"
            raise RuleError(msg)
        return predicate

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            msg = f"condition {self.condition!r} ends unexpectedly"
            raise RuleError(msg)
        self.position += 1
        return token

    def _accept(self, keyword: str) -> bool:
        token = self._peek()
        if token is not None and token.lower() == keyword:
            self.position += 1
            return True
        return False

    def _expression(self) -> Predicate:
        terms = [self._term()]
        while self._accept("or"):
            terms.append(self._term())
        if len(terms) == 1:
            return terms[0]
        return lambda row: any(term(row) for term in terms)

    def _term(self) -> Predicate:
        factors = [self._factor()]
        while self._accept("and"):
            factors.append(self._factor())
        if len(factors) == 1:
            return factors[0]
        return lambda row: all(factor(row) for factor in factors)

    def _factor(self) -> Predicate:
        if self._accept("not"):
            inner = self._factor()
            return lambda row: not inner(row)
        word = self._take()
        if word == "(":
            inner = self._expression()
            if self._peek() != ")":
                msg = f"missing ')' in condition {self.condition!r}"
                raise RuleError(msg)
            self.position += 1
            return inner
        if word.lower() in {"1", "any", "all"} and self._accept("of"):
            return self._quantified(word.lower(), self._take())
        if word == ")" or word.lower() in _KEYWORDS:
            msg = f"unexpected {word!r} in condition {self.condition!r}"
            raise RuleError(msg)
        if word not in self.selections:
            msg = f"condition refers to unknown selection {word!r}"
            raise RuleError(msg)
        return self.selections[word]

    def _quantified(self, quantifier: str, target: str) -> Predicate:
        names = self._expand(target)
        members = [self.selections[name] for name in names]
        if quantifier == "all":
            return lambda row: all(member(row) for member in members)
        return lambda row: any(member(row) for member in members)

    def _expand(self, target: str) -> Sequence[str]:
        if target.lower() == "them":
            names = [name for name in self.selections if not name.startswith("_")]
        else:
            names = [name for name in self.selections if fnmatch.fnmatchcase(name, target)]
        if not names:
            msg = f"{target!r} in condition {self.condition!r} matches no selection"
            raise RuleError(msg)
        return names


def compile_condition(condition: str | list[str], selections: Mapping[str, Predicate]) -> Predicate:
    """Compile a condition (or a list of conditions, OR-ed) over named selections."""
    if isinstance(condition, list):
        if not condition:
            msg = "condition list is empty"
            raise RuleError(msg)
        parts = [_Parser(str(item), selections).parse() for item in condition]
        return lambda row: any(part(row) for part in parts)
    return _Parser(condition, selections).parse()
