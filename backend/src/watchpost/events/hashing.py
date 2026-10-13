"""Event fingerprinting used for deduplication."""

from __future__ import annotations

import hashlib


def compute_event_hash(log_source: str, raw_line: str | bytes) -> str:
    """Return a SHA-256 hex digest identifying a raw log line.

    The log source is part of the digest so identical text arriving through
    two different parsers is not silently collapsed. Trailing newline
    characters are ignored, so a re-exported file with different line
    endings still deduplicates against the original.
    """
    line = raw_line if isinstance(raw_line, bytes) else raw_line.encode("utf-8")
    digest = hashlib.sha256()
    digest.update(log_source.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(line.rstrip(b"\r\n"))
    return digest.hexdigest()
