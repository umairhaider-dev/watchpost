"""Parser for Apache and Nginx access logs.

Supports the Common Log Format, the Combined format (the default for both
servers) and Apache's ``vhost_combined`` (virtual host prefix). Extra fields
that some setups append after the user agent, such as request time, are
ignored.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar
from urllib.parse import unquote_plus

from watchpost.db.models import EventCategory, EventOutcome, LogSource
from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers.base import LineParser, build_event
from watchpost.ingestion.readers import Sample
from watchpost.ingestion.values import clean_int, clean_ip, clean_str

_QUOTED = r'"(?P<{name}>(?:[^"\\]|\\.)*)"'
_ACCESS = re.compile(
    r"^(?:(?P<vhost>\S+)\s+)?(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<auth_user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    + _QUOTED.format(name="request")
    + r"\s+(?P<status>\d{3}|-)\s+(?P<size>\d+|-)"
    + r"(?:\s+"
    + _QUOTED.format(name="referrer")
    + r"\s+"
    + _QUOTED.format(name="agent")
    + r")?"
    + r"(?P<extra>.*)$"
)
_REQUEST = re.compile(
    r"^(?P<method>[A-Z]{1,16}) (?P<target>\S+)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?$"
)
_TIME = re.compile(
    r"^(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<sign>[+-])(?P<tzh>\d{2})(?P<tzm>\d{2})$"
)
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_HTTP_ERROR_THRESHOLD = 400


def _unescape(value: str | None) -> str | None:
    """Undo the backslash escaping Apache and Nginx apply inside quoted fields."""
    if value is None:
        return None
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _parse_time(text: str) -> datetime:
    match = _TIME.match(text)
    if match is None or match["month"] not in _MONTHS:
        msg = f"invalid access log timestamp {text!r}"
        raise ParseError(msg)
    offset = timedelta(hours=int(match["tzh"]), minutes=int(match["tzm"]))
    zone = timezone(offset if match["sign"] == "+" else -offset)
    try:
        return datetime(
            int(match["year"]),
            _MONTHS[match["month"]],
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            tzinfo=zone,
        )
    except ValueError as exc:
        msg = f"invalid access log timestamp {text!r}"
        raise ParseError(msg) from exc


class WebAccessParser(LineParser):
    """Apache / Nginx access logs (common, combined, vhost_combined)."""

    name: ClassVar[str] = "web_access"
    label: ClassVar[str] = "Apache / Nginx access log"
    description: ClassVar[str] = (
        "Web server access logs in Common, Combined or vhost_combined format."
    )

    def parse_line(self, line: str) -> NormalizedEvent:
        match = _ACCESS.match(line)
        if match is None:
            msg = "not an access log line (expected Common or Combined Log Format)"
            raise ParseError(msg)
        timestamp = _parse_time(match["time"])
        request = _unescape(match["request"]) or ""
        status = clean_int(match["status"], minimum=100, maximum=599)

        method = target = protocol = None
        if request_match := _REQUEST.match(request):
            method, target, protocol = (
                request_match["method"],
                request_match["target"],
                request_match["protocol"],
            )

        outcome = None
        if status is not None:
            outcome = (
                EventOutcome.FAILURE if status >= _HTTP_ERROR_THRESHOLD else EventOutcome.SUCCESS
            )

        vhost = clean_str(match["vhost"])
        host = vhost.rsplit(":", 1)[0] if vhost else self.context.default_host
        client = match["client"]
        fields: dict[str, Any] = {
            "host.name": host,
            "source.ip": clean_ip(client),
            "user.name": clean_str(match["auth_user"]),
            "event.category": EventCategory.WEB,
            "event.action": "http_request",
            "event.outcome": outcome,
            "url.original": target,
            "http.request.method": method,
            "http.response.status_code": status,
            "user_agent.original": clean_str(_unescape(match["agent"])),
            "message": f"{request} -> {match['status']}" if request else None,
        }

        details: dict[str, Any] = {
            "bytes": clean_int(match["size"]),
            "referrer": clean_str(_unescape(match["referrer"])),
            "protocol": protocol,
        }
        if target is not None:
            # Decoded once so rules can match "union select" as well as "union%20select".
            details["url_decoded"] = unquote_plus(target)
        else:
            details["request"] = request
        if fields["source.ip"] is None:
            details["client"] = client
        raw_event: dict[str, Any] = {
            "line": line,
            "details": {key: value for key, value in details.items() if value is not None},
        }
        return build_event(
            timestamp=timestamp,
            log_source=LogSource.WEB_ACCESS,
            raw_line=line,
            raw_event=raw_event,
            fields=fields,
        )

    @classmethod
    def sniff(cls, sample: Sample) -> float:
        if not sample.lines:
            return 0.0
        hits = sum(1 for line in sample.lines if _ACCESS.match(line))
        return 0.9 * hits / len(sample.lines)
