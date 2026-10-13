"""Resolving rule field names against stored events.

Rules see an event as a row: the ``events`` columns plus ``raw_event``.
A field name in a rule is resolved in this order:

1. A normalised field (``source.ip``, ``process.command_line``, ...) reads
   its column directly.
2. A dotted name that is not normalised is a path into ``raw_event``
   (``details.url_decoded``, ``event_data.TargetImage``; a leading
   ``raw_event.`` is optional).
3. A bare name (Sigma style: ``TargetImage``, ``GrantedAccess``) is looked
   up in the Windows event data, then in parser details, then at the top
   level of the original JSON record.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from watchpost.detection.errors import RuleError
from watchpost.events import FIELDS_BY_NAME

EventRow = Mapping[str, Any]
Resolver = Callable[[EventRow], Any]

# ECS namespaces the normalised schema uses. A dotted name starting with one
# of these that is *not* a known field is almost certainly a typo.
_NORMALISED_NAMESPACES = frozenset(
    {"source", "destination", "user", "host", "event", "process", "url", "http", "user_agent"}
)
_BARE_NAME_CONTAINERS = ("event_data", "details")


def resolver_for(name: str) -> Resolver:
    """Return a function that extracts ``name`` from an event row.

    Raises:
        RuleError: for dotted names in a normalised namespace that do not exist.
    """
    spec = FIELDS_BY_NAME.get(name)
    if spec is not None:
        column = spec.column
        return lambda row: row.get(column)

    parts = name.split(".")
    if len(parts) > 1:
        if parts[0] in _NORMALISED_NAMESPACES:
            msg = f"unknown field {name!r}; see GET /api/meta/fields for the normalised names"
            raise RuleError(msg)
        if parts[0] == "raw_event":
            parts = parts[1:]
        path = tuple(parts)
        return lambda row: _dig(row.get("raw_event"), path)

    return lambda row: _bare(row.get("raw_event"), name)


def _dig(node: Any, path: tuple[str, ...]) -> Any:
    for part in path:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _bare(raw: Any, name: str) -> Any:
    if not isinstance(raw, dict):
        return None
    for container in _BARE_NAME_CONTAINERS:
        section = raw.get(container)
        if isinstance(section, dict) and name in section:
            return section[name]
    original = raw.get("original")
    if isinstance(original, dict):
        return original.get(name)
    return None
