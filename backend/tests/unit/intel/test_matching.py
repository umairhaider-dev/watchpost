from __future__ import annotations

from typing import Any

from watchpost.db.models import IocType
from watchpost.intel.matching import IndicatorIndex, Observed, extract_indicators

SHA256 = "3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"
MD5 = "0b5e0c3d9a8f7e6d5c4b3a2918172635"


def row(**columns: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"event_hash": "h", "raw_event": {}}
    base.update(columns)
    return base


def index() -> IndicatorIndex:
    built = IndicatorIndex()
    built.add(1, IocType.IP, "203.0.113.45")
    built.add(2, IocType.DOMAIN, "evil.example")
    built.add(3, IocType.SHA256, SHA256)
    built.add(4, IocType.MD5, MD5)
    return built


def test_ips_from_source_and_destination() -> None:
    observed = extract_indicators(row(source_ip="203.0.113.45", destination_ip="10.0.0.8"))

    assert observed == [
        Observed(IocType.IP, "203.0.113.45", "source.ip"),
        Observed(IocType.IP, "10.0.0.8", "destination.ip"),
    ]


def test_absolute_url_host() -> None:
    assert extract_indicators(row(url_original="https://Login.Evil.Example/reset")) == [
        Observed(IocType.DOMAIN, "login.evil.example", "url.original")
    ]
    assert extract_indicators(row(url_original="http://203.0.113.9:8080/x")) == [
        Observed(IocType.IP, "203.0.113.9", "url.original")
    ]
    assert extract_indicators(row(url_original="/index.php?id=1")) == []


def test_sysmon_dns_destination_and_hashes() -> None:
    raw = {
        "event_data": {
            "QueryName": "update-check.example.net",
            "DestinationHostname": "203.0.113.99",
            "Hashes": f"SHA256={SHA256.upper()},MD5={MD5},IMPHASH=abc",
        },
        "original": {"domain": "ignored-for-windows.example"},
    }

    observed = extract_indicators(row(raw_event=raw))

    assert Observed(IocType.DOMAIN, "update-check.example.net", "QueryName") in observed
    assert Observed(IocType.IP, "203.0.113.99", "DestinationHostname") in observed
    assert Observed(IocType.SHA256, SHA256, "Hashes") in observed
    assert Observed(IocType.MD5, MD5, "Hashes") in observed
    assert all(item.value != "ignored-for-windows.example" for item in observed)


def test_generic_json_fields() -> None:
    raw = {
        "original": {
            "dns": {"question": {"name": "Evil.Example."}},
            "file": {"hash": {"sha256": SHA256}},
            "md5": "not-a-hash",
        }
    }

    assert extract_indicators(row(raw_event=raw)) == [
        Observed(IocType.DOMAIN, "evil.example", "dns.question.name"),
        Observed(IocType.SHA256, SHA256, "file.hash.sha256"),
    ]


def test_rows_without_raw_event_details() -> None:
    assert extract_indicators(row(raw_event=None)) == []
    assert extract_indicators(row(raw_event={"line": "text"})) == []


def test_index_matches_ips_hashes_and_parent_domains() -> None:
    built = index()
    raw = {"event_data": {"QueryName": "cdn.evil.example", "Hashes": f"MD5={MD5}"}}

    matches = built.match(row(source_ip="203.0.113.45", raw_event=raw))

    assert matches == [(1, "source.ip"), (2, "QueryName"), (4, "Hashes")]
    assert built.match(row(raw_event={"event_data": {"QueryName": "notevil.example"}})) == []
    assert built.size == 4


def test_duplicate_matches_are_reported_once() -> None:
    built = index()
    raw = {"event_data": {"Hashes": f"SHA256={SHA256}", "Hash": SHA256}}

    assert built.match(row(raw_event=raw)) == [(3, "Hashes"), (3, "Hash")]
    assert built.match(row(source_ip="203.0.113.45", destination_ip="203.0.113.45")) == [
        (1, "source.ip"),
        (1, "destination.ip"),
    ]


def test_annotate_flags_rows_and_keys_matches_by_hash() -> None:
    rows = [
        row(event_hash="a", source_ip="203.0.113.45", ioc_matched=False),
        row(event_hash="b", source_ip="10.0.0.1", ioc_matched=False),
    ]

    found = index().annotate(rows)

    assert found == {"a": [(1, "source.ip")]}
    assert [r["ioc_matched"] for r in rows] == [True, False]


def test_empty_index_does_nothing() -> None:
    rows = [row(source_ip="203.0.113.45", ioc_matched=False)]

    assert IndicatorIndex().empty
    assert IndicatorIndex().annotate(rows) == {}
    assert rows[0]["ioc_matched"] is False
