from __future__ import annotations

from datetime import UTC, datetime
from textwrap import dedent

import pytest

from watchpost.db.models import IocType
from watchpost.intel.feeds import MAX_PROBLEMS_KEPT, FeedFormatError, parse_feed

SHA256 = "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3"


def test_txt_feed_with_comments_and_defanged_values() -> None:
    data = dedent(
        """\
        # Weekly blocklist
        ; another comment style
        // and another

        203.0.113.45      # SSH brute force source
        evil[.]example
        hxxps://update-check.example.net/payload.ps1
        not-an-indicator!
        203.0.113.45
        """
    ).encode()

    feed = parse_feed(data, "blocklist.txt")

    assert [(entry.ioc_type, entry.value) for entry in feed.entries] == [
        (IocType.IP, "203.0.113.45"),
        (IocType.DOMAIN, "evil.example"),
        (IocType.DOMAIN, "update-check.example.net"),
    ]
    assert feed.duplicates == 1
    assert feed.problem_count == 1
    assert feed.problems[0].line == 8
    assert feed.problems[0].excerpt == "not-an-indicator!"


def test_csv_feed_with_metadata_columns() -> None:
    data = dedent(
        f"""\
        Indicator,Type,Description,Confidence,Tags,Expires,Extra
        203.0.113.45,ipv4,SSH brute force,90,ssh; brute-force,2027-01-01T00:00:00Z,ignored
        update-check.example.net,domain,C2 domain,high,c2|powershell,,
        {SHA256},sha256,LSASS dumper,,malware,,
        """
    ).encode()

    feed = parse_feed(data, "feed.csv")

    assert feed.problem_count == 0
    ip, domain, sha = feed.entries
    assert ip.ioc_type is IocType.IP
    assert ip.description == "SSH brute force"
    assert ip.confidence == 90
    assert ip.tags == ("brute-force", "ssh")
    assert ip.expires_at == datetime(2027, 1, 1, tzinfo=UTC)
    assert domain.confidence == 90  # "high"
    assert domain.tags == ("c2", "powershell")
    assert sha.ioc_type is IocType.SHA256
    assert sha.confidence is None


def test_csv_is_recognised_without_csv_extension() -> None:
    feed = parse_feed(b"value,description\n198.51.100.23,web scanner\n", "export.txt")

    assert feed.entries[0].description == "web scanner"


def test_csv_with_a_typed_column() -> None:
    feed = parse_feed(f"hash,comment\n{SHA256},dropper\nevil.example,oops\n".encode(), "hashes.csv")

    assert [entry.value for entry in feed.entries] == [SHA256]
    assert "expected a file hash" in feed.problems[0].reason


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ("203.0.113.45,domain,,", "looks like an IP address, not a domain"),
        ("203.0.113.45,email,,", "unknown indicator type"),
        ("203.0.113.45,ip,very sure,", "not a number from 0 to 100"),
        ("203.0.113.45,ip,150,", "not a number from 0 to 100"),
        ("203.0.113.45,ip,50,next tuesday", "invalid expiry date"),
        (",ip,,", "missing indicator value"),
    ],
)
def test_csv_row_problems(row: str, reason: str) -> None:
    feed = parse_feed(f"value,type,confidence,expires\n{row}\n".encode(), "feed.csv")

    assert feed.entries == []
    assert reason in feed.problems[0].reason
    assert feed.problems[0].line == 2


def test_csv_without_indicator_column_is_rejected() -> None:
    with pytest.raises(FeedFormatError, match="no indicator column"):
        parse_feed(b"name,score\nfoo,1\n", "feed.csv")


def test_utf8_bom_and_problem_cap() -> None:
    lines = "\n".join(f"bad-{n}!" for n in range(MAX_PROBLEMS_KEPT + 20))
    feed = parse_feed(b"\xef\xbb\xbf" + lines.encode(), "list.txt")

    assert feed.problem_count == MAX_PROBLEMS_KEPT + 20
    assert len(feed.problems) == MAX_PROBLEMS_KEPT


def test_entry_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("watchpost.intel.feeds.MAX_FEED_ENTRIES", 2)

    feed = parse_feed(b"203.0.113.1\n203.0.113.2\n203.0.113.3\n", "list.txt")

    assert feed.truncated
    assert len(feed.entries) == 2
