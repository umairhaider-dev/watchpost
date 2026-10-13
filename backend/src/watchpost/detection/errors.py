"""Detection errors."""

from __future__ import annotations


class RuleError(ValueError):
    """A rule is malformed: bad YAML, an unknown modifier, a broken condition, ..."""
