from __future__ import annotations

from datetime import UTC, datetime

import pytest

from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers import ParseContext, WebAccessParser
from watchpost.ingestion.readers import Sample

UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"
COMBINED = (
    '198.51.100.23 - - [12/Oct/2026:09:21:10 +0000] "GET /products?id=1%27%20OR%20%271%27%3D%271 '
    f'HTTP/1.1" 500 512 "https://shop.example.com/" "{UA}"'
)


def parse(line: str, context: ParseContext) -> NormalizedEvent:
    return WebAccessParser(context).parse_line(line)


def test_combined_format(context: ParseContext) -> None:
    event = parse(COMBINED, context)
    flat = event.flatten()

    assert event.timestamp == datetime(2026, 10, 12, 9, 21, 10, tzinfo=UTC)
    assert flat["source.ip"] == "198.51.100.23"
    assert flat["http.request.method"] == "GET"
    assert flat["url.original"] == "/products?id=1%27%20OR%20%271%27%3D%271"
    assert flat["http.response.status_code"] == 500
    assert flat["user_agent.original"] == UA
    assert flat["event.category"] == "web"
    assert flat["event.action"] == "http_request"
    assert flat["event.outcome"] == "failure"
    assert event.raw_event["details"] == {
        "bytes": 512,
        "referrer": "https://shop.example.com/",
        "protocol": "HTTP/1.1",
        "url_decoded": "/products?id=1' OR '1'='1",
    }


def test_common_log_format_with_authenticated_user(context: ParseContext) -> None:
    event = parse(
        '192.168.1.34 - alice [12/Oct/2026:09:11:53 +0000] "GET /account HTTP/1.0" 200 6311',
        context,
    )
    flat = event.flatten()

    assert flat["user.name"] == "alice"
    assert flat["event.outcome"] == "success"
    assert "user_agent.original" not in flat


def test_timezone_offset_is_applied(context: ParseContext) -> None:
    event = parse(
        '10.0.0.1 - - [12/Oct/2026:11:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"', context
    )

    assert event.timestamp == datetime(2026, 10, 12, 9, 0, tzinfo=UTC)


def test_vhost_combined_sets_host(context: ParseContext) -> None:
    event = parse(
        'shop.example.com:443 192.168.1.20 - - [12/Oct/2026:09:10:01 +0000] "GET / HTTP/2.0" '
        '200 5120 "-" "curl/8.5.0"',
        context,
    )

    assert event.host.name == "shop.example.com"
    assert event.flatten()["source.ip"] == "192.168.1.20"


def test_default_host_from_context() -> None:
    context = ParseContext(reference_time=datetime(2026, 10, 13, tzinfo=UTC), default_host="web-01")

    assert parse(COMBINED, context).host.name == "web-01"


def test_ipv6_client(context: ParseContext) -> None:
    event = parse(
        '2001:db8::42 - - [12/Oct/2026:09:12:00 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "probe"',
        context,
    )

    assert event.flatten()["source.ip"] == "2001:db8::42"


def test_hostname_client_is_kept_in_details(context: ParseContext) -> None:
    event = parse(
        'crawler.example - - [12/Oct/2026:09:12:00 +0000] "GET / HTTP/1.1" 200 2 "-" "bot"', context
    )

    assert "source.ip" not in event.flatten()
    assert event.raw_event["details"]["client"] == "crawler.example"


def test_non_http_request_line_is_kept(context: ParseContext) -> None:
    event = parse(
        r'203.0.113.61 - - [12/Oct/2026:09:25:44 +0000] "\x16\x03\x01\x02\x00" 400 157 "-" "-"',
        context,
    )
    flat = event.flatten()

    assert "http.request.method" not in flat
    assert flat["http.response.status_code"] == 400
    assert event.raw_event["details"]["request"] == r"\x16\x03\x01\x02\x00"


def test_dash_request_and_size(context: ParseContext) -> None:
    event = parse('203.0.113.61 - - [12/Oct/2026:09:25:45 +0000] "-" 408 - "-" "-"', context)

    assert event.flatten()["http.response.status_code"] == 408
    assert "bytes" not in event.raw_event["details"]


def test_escaped_quotes_in_user_agent(context: ParseContext) -> None:
    event = parse(
        '10.0.0.9 - - [12/Oct/2026:09:12:00 +0000] "GET / HTTP/1.1" 200 2 "-" "evil \\"agent\\" v1"',
        context,
    )

    assert event.flatten()["user_agent.original"] == 'evil "agent" v1'


def test_trailing_fields_are_ignored(context: ParseContext) -> None:
    event = parse(COMBINED + " 0.023 upstream=10.0.0.5:8080", context)

    assert event.flatten()["http.response.status_code"] == 500


@pytest.mark.parametrize(
    "line",
    [
        "Oct 12 09:02:13 web-01 sshd[1]: not an access log",
        '198.51.100.23 - - [12/Oct/2026:09:21:10 +0000] "GET / HTTP/1.1"',
        '198.51.100.23 - - [99/Oct/2026:09:21:10 +0000] "GET / HTTP/1.1" 200 1',
        '198.51.100.23 - - [12/Foo/2026:09:21:10 +0000] "GET / HTTP/1.1" 200 1',
        '198.51.100.23 - - [12/Oct/2026 09:21:10] "GET / HTTP/1.1" 200 1',
        '{"json": true}',
    ],
)
def test_malformed_lines_raise(line: str, context: ParseContext) -> None:
    with pytest.raises(ParseError):
        parse(line, context)


def test_sniff() -> None:
    assert WebAccessParser.sniff(Sample(lines=[COMBINED] * 3, records=[])) == pytest.approx(0.9)
    assert WebAccessParser.sniff(Sample(lines=["nope"], records=[])) == 0
    assert WebAccessParser.sniff(Sample(lines=[], records=[])) == 0
