from __future__ import annotations

import re

from watchpost.events import compute_event_hash

LINE = "Mar 14 09:26:53 web-01 sshd[4120]: Failed password for alice from 203.0.113.45"


def test_hash_is_sha256_hex() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", compute_event_hash("linux_auth", LINE))


def test_hash_is_deterministic() -> None:
    assert compute_event_hash("linux_auth", LINE) == compute_event_hash("linux_auth", LINE)


def test_hash_ignores_line_endings() -> None:
    base = compute_event_hash("linux_auth", LINE)

    assert compute_event_hash("linux_auth", LINE + "\n") == base
    assert compute_event_hash("linux_auth", LINE + "\r\n") == base


def test_hash_accepts_bytes_and_text_equally() -> None:
    assert compute_event_hash("linux_auth", LINE.encode()) == compute_event_hash("linux_auth", LINE)


def test_hash_depends_on_log_source() -> None:
    assert compute_event_hash("linux_auth", LINE) != compute_event_hash("json", LINE)


def test_hash_depends_on_content() -> None:
    assert compute_event_hash("linux_auth", LINE) != compute_event_hash("linux_auth", LINE + "x")
