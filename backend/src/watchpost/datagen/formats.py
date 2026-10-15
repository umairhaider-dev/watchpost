"""Formatting one log line in each output format.

Timestamps are POSIX seconds (floats) and always written in UTC. Month names
are spelled out here rather than taken from ``strftime`` so the output does
not depend on the machine's locale.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


def syslog_line(timestamp: float, host: str, program: str, pid: int | None, message: str) -> str:
    """A syslog line with the RFC 3339 header current rsyslog versions write."""
    stamp = _utc(timestamp).isoformat(timespec="microseconds")
    tag = program if pid is None else f"{program}[{pid}]"
    return f"{stamp} {host} {tag}: {message}"


def access_line(
    timestamp: float,
    client: str,
    user: str | None,
    request: str,
    status: int,
    size: int,
    referer: str | None,
    agent: str,
) -> str:
    """A line in the NGINX/Apache combined log format."""
    moment = _utc(timestamp)
    stamp = (
        f"{moment.day:02d}/{_MONTHS[moment.month - 1]}/{moment.year}:"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} +0000"
    )
    return (
        f'{client} - {user or "-"} [{stamp}] "{request}" {status} {size} '
        f'"{referer or "-"}" "{agent}"'
    )


def _windows_time(timestamp: float) -> str:
    # Windows writes seven fractional digits; the last one is always zero here.
    return _utc(timestamp).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def _json(record: dict[str, Any]) -> str:
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


def windows_event(
    timestamp: float,
    event_id: int,
    computer: str,
    data: dict[str, Any],
    *,
    provider: str = SECURITY_PROVIDER,
    success: bool = True,
) -> str:
    """A Security log record as Winlogbeat-style flat JSON."""
    return _json(
        {
            "EventID": event_id,
            "TimeCreated": _windows_time(timestamp),
            "Computer": computer,
            "Channel": "Security",
            "Provider": provider,
            "EventData": data,
            "Keywords": "Audit Success" if success else "Audit Failure",
        }
    )


def sysmon_event(timestamp: float, event_id: int, computer: str, data: dict[str, Any]) -> str:
    """A Sysmon record in the same flat JSON shape."""
    moment = _utc(timestamp)
    utc_time = moment.strftime("%Y-%m-%d %H:%M:%S.") + f"{moment.microsecond // 1000:03d}"
    return _json(
        {
            "EventID": event_id,
            "TimeCreated": _windows_time(timestamp),
            "Computer": computer,
            "Channel": SYSMON_CHANNEL,
            "Provider": SYSMON_PROVIDER,
            "EventData": {"RuleName": "-", "UtcTime": utc_time, **data},
        }
    )
