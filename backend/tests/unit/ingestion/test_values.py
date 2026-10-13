from __future__ import annotations

from datetime import UTC, datetime

import pytest

from watchpost.ingestion.values import (
    basename,
    clean_int,
    clean_ip,
    clean_port,
    clean_str,
    parse_timestamp,
    split_account,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("  alice ", "alice"),
        ("-", None),
        ("", None),
        ("N/A", None),
        ("null", None),
        (None, None),
        (42, "42"),
        ({"nested": 1}, None),
        (["a"], None),
    ],
)
def test_clean_str(value: object, expected: str | None) -> None:
    assert clean_str(value) == expected


def test_clean_str_truncates() -> None:
    assert clean_str("abcdef", max_length=3) == "abc"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.45", "203.0.113.45"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("::ffff:10.0.0.5", "10.0.0.5"),
        ("2001:DB8:0:0::10", "2001:db8::10"),
        ("0.0.0.0", None),
        ("::", None),
        ("-", None),
        ("server.example.com", None),
        ("999.1.1.1", None),
        (None, None),
    ],
)
def test_clean_ip(value: object, expected: str | None) -> None:
    assert clean_ip(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4412", 4412),
        ("0x1a2c", 6700),
        ("0X10", 16),
        (12, 12),
        (True, None),
        ("-", None),
        ("abc", None),
        ("-5", None),
        (2**40, None),
    ],
)
def test_clean_int(value: object, expected: int | None) -> None:
    assert clean_int(value) == expected


def test_clean_port_range() -> None:
    assert clean_port("443") == 443
    assert clean_port("70000") is None


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("/usr/bin/sudo", "sudo"),
        ("/var/log/", "log"),
        ("lsass.exe", "lsass.exe"),
        (None, None),
        ("", None),
    ],
)
def test_basename(path: str | None, expected: str | None) -> None:
    assert basename(path) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CORP\\jsmith", ("jsmith", "CORP")),
        ("jsmith@corp.example", ("jsmith", "corp.example")),
        ("root", ("root", None)),
        ("-", (None, None)),
    ],
)
def test_split_account(value: str, expected: tuple[str | None, str | None]) -> None:
    assert split_account(value) == expected


EXPECTED = datetime(2026, 10, 12, 9, 41, tzinfo=UTC)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-12T09:41:00Z",
        "2026-10-12T09:41:00.0000000Z",
        "2026-10-12T11:41:00+02:00",
        "2026-10-12T09:41:00+0000",
        "2026-10-12 09:41:00",
        "/Date(1791798060000)/",
        "1791798060",
        "1791798060000",
        1791798060,
        1791798060000,
        1791798060000000,
        1791798060.0,
        datetime(2026, 10, 12, 9, 41),  # noqa: DTZ001 - naive input is the point
    ],
)
def test_parse_timestamp_formats(value: object) -> None:
    assert parse_timestamp(value) == EXPECTED


@pytest.mark.parametrize("value", ["", "yesterday", None, True, "99999999999999999999", {}])
def test_parse_timestamp_rejects_garbage(value: object) -> None:
    with pytest.raises(ValueError, match=r"timestamp|Invalid|epoch|unsupported|out of range"):
        parse_timestamp(value)
