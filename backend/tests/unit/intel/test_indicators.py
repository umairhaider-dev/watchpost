from __future__ import annotations

import pytest

from watchpost.db.models import IocType
from watchpost.intel.indicators import (
    IndicatorError,
    normalize_domain,
    normalize_indicator,
    parent_domains,
    parse_declared_type,
    refang,
)

MD5 = "D41D8CD98F00B204E9800998ECF8427E"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.45", (IocType.IP, "203.0.113.45")),
        ("  198.51.100.7\t", (IocType.IP, "198.51.100.7")),
        ("203.0.113[.]45", (IocType.IP, "203.0.113.45")),
        ("2001:DB8::0:1", (IocType.IP, "2001:db8::1")),
        ("[2001:db8::5]", (IocType.IP, "2001:db8::5")),
        ("::ffff:10.0.0.5", (IocType.IP, "10.0.0.5")),
        ("Evil.Example.", (IocType.DOMAIN, "evil.example")),
        ("update-check[.]example[.]net", (IocType.DOMAIN, "update-check.example.net")),
        ("*.cdn.example.org", (IocType.DOMAIN, "cdn.example.org")),
        ("hxxps://Login.Example.COM/reset?x=1", (IocType.DOMAIN, "login.example.com")),
        ("http://203.0.113.9:8080/payload", (IocType.IP, "203.0.113.9")),
        ("bücher.example", (IocType.DOMAIN, "xn--bcher-kva.example")),
        (MD5, (IocType.MD5, MD5.lower())),
        (SHA1, (IocType.SHA1, SHA1)),
        (SHA256.upper(), (IocType.SHA256, SHA256)),
        ('"203.0.113.45"', (IocType.IP, "203.0.113.45")),
    ],
)
def test_normalize_indicator(raw: str, expected: tuple[IocType, str]) -> None:
    assert normalize_indicator(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("203.0.113.0/24", "CIDR"),
        ("abc123", "not an IP address"),
        ("d41d8cd98f00b204e9800998ecf842", "not an MD5, SHA-1 or SHA-256"),
        ("deadbeef", "not an IP address"),
        ("localhost", "not an IP address"),
        ("-bad-.example", "not an IP address"),
        ("http:///nohost", "URL without a host"),
        ("0.0.0.0", "not an IP address"),
        ("1234", "not an IP address"),
    ],
)
def test_rejects_non_indicators(raw: str, message: str) -> None:
    with pytest.raises(IndicatorError, match=message):
        normalize_indicator(raw)


def test_declared_type_must_match() -> None:
    assert normalize_indicator("evil.example", IocType.DOMAIN) == (IocType.DOMAIN, "evil.example")
    with pytest.raises(IndicatorError, match="looks like a ip, not a domain"):
        normalize_indicator("203.0.113.45", IocType.DOMAIN)
    with pytest.raises(IndicatorError, match="expected a file hash"):
        normalize_indicator("evil.example", any_hash=True)
    assert normalize_indicator(SHA1, any_hash=True) == (IocType.SHA1, SHA1)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("IPv4", (True, IocType.IP)),
        ("ip-dst", (True, IocType.IP)),
        ("FQDN", (True, IocType.DOMAIN)),
        ("url", (True, IocType.DOMAIN)),
        ("SHA256", (True, IocType.SHA256)),
        ("hash", (True, None)),
        ("", (True, None)),
        (None, (True, None)),
        ("email", (False, None)),
    ],
)
def test_parse_declared_type(value: str | None, expected: tuple[bool, IocType | None]) -> None:
    assert parse_declared_type(value) == expected


def test_refang() -> None:
    assert refang("hxxp://evil[.]example[:]8080") == "http://evil.example:8080"
    assert refang("bad(.)example{.}com") == "bad.example.com"


@pytest.mark.parametrize(
    "value", ["example", "10.0.0.1", "", "a..b.example", "x" * 64 + ".example"]
)
def test_normalize_domain_rejects(value: str) -> None:
    assert normalize_domain(value) is None


def test_parent_domains() -> None:
    assert parent_domains("a.b.evil.example") == [
        "a.b.evil.example",
        "b.evil.example",
        "evil.example",
    ]
    assert parent_domains("evil.example") == ["evil.example"]
