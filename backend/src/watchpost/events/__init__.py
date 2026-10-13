"""The normalised event model shared by parsers, detection rules and search."""

from watchpost.events.fields import FIELDS, FIELDS_BY_NAME, FieldKind, FieldSpec
from watchpost.events.hashing import compute_event_hash
from watchpost.events.schema import NormalizedEvent

__all__ = [
    "FIELDS",
    "FIELDS_BY_NAME",
    "FieldKind",
    "FieldSpec",
    "NormalizedEvent",
    "compute_event_hash",
]
