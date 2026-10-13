from __future__ import annotations

from ipaddress import IPv4Interface

import pytest
from sqlalchemy.dialects import postgresql

from watchpost.db.models import AlertStatus, Severity
from watchpost.db.types import IPAddress

DIALECT = postgresql.dialect()  # type: ignore[no-untyped-call]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.1", "10.0.0.1"),
        (" 192.168.1.20 ", "192.168.1.20"),
        ("2001:0DB8::0001", "2001:db8::1"),
        (None, None),
    ],
)
def test_ip_address_bind_normalises(value: str | None, expected: str | None) -> None:
    assert IPAddress().process_bind_param(value, DIALECT) == expected


def test_ip_address_bind_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        IPAddress().process_bind_param("not-an-ip", DIALECT)


def test_ip_address_result_drops_prefix_length() -> None:
    assert IPAddress().process_result_value(IPv4Interface("10.1.2.3/32"), DIALECT) == "10.1.2.3"
    assert IPAddress().process_result_value(None, DIALECT) is None


def test_severity_rank_orders_levels() -> None:
    ordered = sorted(Severity, key=lambda level: level.rank)

    assert ordered == [
        Severity.INFORMATIONAL,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_only_new_and_investigating_alerts_are_open() -> None:
    assert {status for status in AlertStatus if status.is_open} == {
        AlertStatus.NEW,
        AlertStatus.INVESTIGATING,
    }
