"""Turning a parsed search query into a SQL condition on ``events``.

How a value is matched depends on the field (see :mod:`watchpost.events.fields`):

=========  ===================================================================
keyword    exact and case-sensitive (uses the indexes); ``*``/``?`` patterns
           are case-insensitive
text       case-insensitive substring; with ``*``/``?`` the pattern must
           match the whole value
ip         an address, or a network in CIDR form (``10.0.0.0/8``)
integer    exact, or ``>``/``>=``/``<``/``<=``
timestamp  ``>``/``>=``/``<``/``<=`` an ISO time; a bare date means that day (UTC)
boolean    ``true`` or ``false``
=========  ===================================================================

Free text (no field) is a case-insensitive substring search over the
message, command line and URL. ``raw.<path>`` reaches into the original
record (``raw.event_data.TargetImage:*lsass*``) with text matching.

Every value becomes a bound parameter; field names are checked against the
field registry, so nothing from the query is ever spliced into SQL.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import ColumnElement, and_, cast, false, func, not_, or_, true
from sqlalchemy.dialects.postgresql import CIDR, INET

from watchpost.db.models import Event
from watchpost.events import FIELDS_BY_NAME, FieldKind, FieldSpec
from watchpost.search.query import And, Node, Not, QueryError, Term, parse_query

ALIASES: dict[str, str] = {
    "timestamp": "@timestamp",
    "host": "host.name",
    "user": "user.name",
    "action": "event.action",
    "outcome": "event.outcome",
    "category": "event.category",
    "process": "process.name",
    "command_line": "process.command_line",
    "url": "url.original",
    "status": "http.response.status_code",
    "method": "http.request.method",
}
# ``ip:`` matches either end of a connection.
EITHER_IP = "ip"
RAW_PREFIX = "raw."
_RAW_PATH = re.compile(r"[A-Za-z0-9_@-]{1,64}")
_MAX_RAW_DEPTH = 8
_FREE_TEXT_COLUMNS = ("message", "process_command_line", "url_original")
_BOOLEANS = {"true": True, "false": False}

_EVENTS = Event.__table__


def _like_pattern(value: str, *, anchored: bool) -> str:
    """A LIKE pattern from a search value: ``*``/``?`` become ``%``/``_``, the rest is literal."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = escaped.replace("*", "%").replace("?", "_")
    return pattern if anchored else f"%{pattern}%"


def _field_names() -> list[str]:
    return [*FIELDS_BY_NAME, *ALIASES, EITHER_IP]


def _unknown_field(term: Term) -> QueryError:
    suggestion = difflib.get_close_matches(term.field or "", _field_names(), n=1)
    hint = f"; did you mean {suggestion[0]}?" if suggestion else ""
    return QueryError(f"unknown field {term.field!r}{hint}", term.position)


def _text(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    if term.is_presence:
        return column.is_not(None)
    if term.comparison:
        raise QueryError(f"{term.field} is text and cannot be compared", term.position)
    pattern = _like_pattern(term.value, anchored=term.has_wildcards)
    return column.ilike(pattern, escape="\\")


def _keyword(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    if term.is_presence:
        return column.is_not(None)
    if term.comparison:
        raise QueryError(f"{term.field} is a keyword and cannot be compared", term.position)
    if term.has_wildcards:
        return column.ilike(_like_pattern(term.value, anchored=True), escape="\\")
    return column == term.value


def _ip(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    if term.is_presence:
        return column.is_not(None)
    if term.comparison or term.has_wildcards:
        msg = f"{term.field} takes an address or a CIDR network such as 10.0.0.0/8"
        raise QueryError(msg, term.position)
    try:
        if "/" in term.value:
            network = ipaddress.ip_network(term.value, strict=False)
            return cast(column, INET).op("<<=")(cast(str(network), CIDR))
        return column == str(ipaddress.ip_address(term.value))
    except ValueError as exc:
        msg = f"{term.value!r} is not an IP address or network"
        raise QueryError(msg, term.position) from exc


def _compare(column: ColumnElement[Any], term: Term, value: int | datetime) -> ColumnElement[bool]:
    match term.comparison:
        case ">":
            return column > value
        case ">=":
            return column >= value
        case "<":
            return column < value
        case "<=":
            return column <= value
        case _:
            return column == value


def _integer(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    if term.is_presence:
        return column.is_not(None)
    try:
        number = int(term.value)
    except ValueError as exc:
        msg = f"{term.field} takes a whole number, not {term.value!r}"
        raise QueryError(msg, term.position) from exc
    return _compare(column, term, number)


def _day_bounds(column: ColumnElement[Any], term: Term, day: date) -> ColumnElement[bool]:
    """A bare date stands for the whole UTC day: ``> day`` means after it ends."""
    day_start = datetime.combine(day, time(), tzinfo=UTC)
    day_end = day_start + timedelta(days=1)
    if term.comparison == ">":
        return column >= day_end
    if term.comparison == ">=":
        return column >= day_start
    if term.comparison == "<":
        return column < day_start
    if term.comparison == "<=":
        return column < day_end
    return and_(column >= day_start, column < day_end)


def _timestamp(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    if term.is_presence:
        return true()
    text = term.value.strip()
    try:
        if len(text) == len("2026-10-12"):
            return _day_bounds(column, term, date.fromisoformat(text))
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        msg = f"{term.field} takes an ISO date or time such as 2026-10-12T09:00:00Z"
        raise QueryError(msg, term.position) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return _compare(column, term, moment)


def _boolean(column: ColumnElement[Any], term: Term) -> ColumnElement[bool]:
    value = _BOOLEANS.get(term.value.lower())
    if value is None or term.comparison:
        raise QueryError(f"{term.field} is true or false", term.position)
    return column.is_(value)


_MATCHERS = {
    FieldKind.KEYWORD: _keyword,
    FieldKind.TEXT: _text,
    FieldKind.IP: _ip,
    FieldKind.INTEGER: _integer,
    FieldKind.DATETIME: _timestamp,
    FieldKind.BOOLEAN: _boolean,
}


def _raw(term: Term) -> ColumnElement[bool]:
    path = (term.field or "").removeprefix(RAW_PREFIX).split(".")
    if len(path) > _MAX_RAW_DEPTH or not all(_RAW_PATH.fullmatch(part) for part in path):
        msg = f"{term.field!r} is not a valid path into the raw event"
        raise QueryError(msg, term.position)
    if term.is_presence:
        return _EVENTS.c.raw_event[tuple(path)].is_not(None)
    return _text(_EVENTS.c.raw_event[tuple(path)].astext, term)


def _spec(term: Term) -> FieldSpec:
    name = ALIASES.get(term.field or "", term.field or "")
    spec = FIELDS_BY_NAME.get(name)
    if spec is None:
        raise _unknown_field(term)
    return spec


def _term(term: Term) -> ColumnElement[bool]:
    if term.field is None:
        if term.is_presence:
            return true()
        pattern = _like_pattern(term.value, anchored=False)
        return or_(
            *(_EVENTS.c[column].ilike(pattern, escape="\\") for column in _FREE_TEXT_COLUMNS)
        )
    if term.field == EITHER_IP:
        return or_(
            _ip(_EVENTS.c.source_ip, term),
            _ip(_EVENTS.c.destination_ip, term),
        )
    if term.field.startswith(RAW_PREFIX):
        return _raw(term)
    spec = _spec(term)
    return _MATCHERS[spec.kind](_EVENTS.c[spec.column], term)


def _compile(node: Node) -> ColumnElement[bool]:
    if isinstance(node, Term):
        return _term(node)
    if isinstance(node, Not):
        # NULL (a missing field) must count as "does not match", so NOT includes it.
        return not_(func.coalesce(_compile(node.child), false()))
    if isinstance(node, And):
        return and_(*(_compile(child) for child in node.children))
    return or_(*(_compile(child) for child in node.children))


def compile_query(text: str) -> ColumnElement[bool] | None:
    """The SQL condition for a query, or ``None`` when the query is empty.

    Raises:
        QueryError: for syntax errors, unknown fields and values of the wrong type.
    """
    node = parse_query(text)
    return _compile(node) if node is not None else None
