"""Parser for Linux authentication logs (``/var/log/auth.log``, ``/var/log/secure``).

Understands the classic BSD syslog header (``Mar 14 09:26:53 host prog[pid]:``)
and the RFC 3339 header newer rsyslog versions write
(``2026-03-14T09:26:53.123456+00:00 host prog[pid]:``).

Messages from sshd, sudo, su, PAM and the account management tools
(useradd, usermod, gpasswd, ...) are mapped to specific actions. Any other
well-formed syslog line is still kept as a generic event, because context
matters during an investigation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from watchpost.db.models import EventCategory, EventOutcome, LogSource
from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers.base import LineParser, build_event
from watchpost.ingestion.readers import Sample
from watchpost.ingestion.values import clean_int, clean_ip, clean_port, clean_str, parse_timestamp

_SYSLOG = re.compile(
    r"^(?:(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>\S+)\s+(?P<program>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)
_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

# --- sshd -------------------------------------------------------------------
_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?\s*$"
)
_SSH_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    r"(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_CLOSED = re.compile(
    r"^Connection (?:closed|reset) by (?:(?:authenticating|invalid) user (?P<user>\S+) )?"
    r"(?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_DISCONNECT = re.compile(
    r"^(?:Received disconnect from|Disconnected from)"
    r"(?: (?:authenticating |invalid )?user (?P<user>\S+))? (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_NO_IDENT = re.compile(
    r"^Did not receive identification string from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_SSH_NEGOTIATE = re.compile(r"^Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+)")

# --- PAM (any program) ---------------------------------------------------------
_PAM_AUTH_FAILURE = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):auth\): authentication failure;(?P<kv>.*)$"
)
_PAM_SESSION = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):session\): session (?P<state>opened|closed) "
    r"for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?"
)
_PAM_PASSWORD_CHANGED = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):chauthtok\): password changed for (?P<user>\S+)"
)
_KEY_VALUE = re.compile(r"(\w+)=(\S*)")

# --- sudo / su -------------------------------------------------------------------
_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<reason>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ;.*?COMMAND=(?P<command>.*)$"
)
_SU_FAILED = re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_SU_SUCCESS = re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_SU_SUCCESS_OLD = re.compile(r"^Successful su for (?P<target>\S+) by (?P<user>\S+)")

# --- account management ------------------------------------------------------------
_ACCOUNT_PROGRAMS = frozenset(
    {"useradd", "usermod", "userdel", "groupadd", "groupdel", "gpasswd", "passwd", "chpasswd"}
)
_NEW_USER = re.compile(
    r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), "
    r"home=(?P<home>[^,]*), shell=(?P<shell>[^,]*)"
)
_NEW_GROUP = re.compile(r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")
_ADD_TO_GROUP = re.compile(
    r"^add '(?P<user>[^']+)' to (?P<shadow>shadow )?group '(?P<group>[^']+)'"
)
_GPASSWD_ADD = re.compile(r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)")
_DELETE_USER = re.compile(r"^delete user '(?P<user>[^']+)'")
_DELETE_GROUP = re.compile(r"^(?:removed group|group) '(?P<group>[^']+)'")
_CHANGE_PASSWORD = re.compile(r"^change user '(?P<user>[^']+)' password")


@dataclass(slots=True)
class _Classified:
    """What a message means, in normalised terms."""

    category: EventCategory | None = None
    action: str | None = None
    outcome: EventOutcome | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


def _remote(match: re.Match[str], user_group: str = "user") -> dict[str, Any]:
    """Common user/IP/port fields; non-IP hosts (UseDNS) are left out of ``source.ip``."""
    return {
        "user.name": clean_str(match[user_group]),
        "source.ip": clean_ip(match["ip"]),
        "source.port": clean_port(match["port"]),
    }


def _endpoint(match: re.Match[str]) -> dict[str, Any]:
    return {"source.ip": clean_ip(match["ip"]), "source.port": clean_port(match["port"])}


_Rule = tuple[re.Pattern[str], Callable[[re.Match[str]], _Classified]]
_AUTH, _NETWORK, _IAM = EventCategory.AUTHENTICATION, EventCategory.NETWORK, EventCategory.IAM
_SUCCESS, _FAILURE = EventOutcome.SUCCESS, EventOutcome.FAILURE

_SSH_RULES: tuple[_Rule, ...] = (
    (
        _SSH_FAILED,
        lambda m: _Classified(
            _AUTH,
            "ssh_login",
            _FAILURE,
            _remote(m),
            {"auth_method": m["method"], "invalid_user": bool(m["invalid"])},
        ),
    ),
    (
        _SSH_ACCEPTED,
        lambda m: _Classified(
            _AUTH, "ssh_login", _SUCCESS, _remote(m), {"auth_method": m["method"]}
        ),
    ),
    (_SSH_INVALID_USER, lambda m: _Classified(_AUTH, "ssh_invalid_user", _FAILURE, _remote(m))),
    (_SSH_MAX_AUTH, lambda m: _Classified(_AUTH, "ssh_max_auth_attempts", _FAILURE, _remote(m))),
    (_SSH_CLOSED, lambda m: _Classified(_NETWORK, "ssh_connection_closed", None, _remote(m))),
    (_SSH_DISCONNECT, lambda m: _Classified(_NETWORK, "ssh_disconnect", None, _remote(m))),
    (
        _SSH_NO_IDENT,
        lambda m: _Classified(_NETWORK, "ssh_no_identification", _FAILURE, _endpoint(m)),
    ),
    (
        _SSH_NEGOTIATE,
        lambda m: _Classified(_NETWORK, "ssh_negotiation_failed", _FAILURE, _endpoint(m)),
    ),
)


def _first_match(rules: tuple[_Rule, ...], message: str) -> _Classified | None:
    for pattern, build in rules:
        if match := pattern.match(message):
            return build(match)
    return None


def _classify_pam(message: str) -> _Classified | None:
    if match := _PAM_AUTH_FAILURE.match(message):
        pairs = dict(_KEY_VALUE.findall(match["kv"]))
        fields = {
            "user.name": clean_str(pairs.get("user")) or clean_str(pairs.get("ruser")),
            "source.ip": clean_ip(pairs.get("rhost")),
        }
        details = {"service": match["service"], "tty": clean_str(pairs.get("tty"))}
        return _Classified(
            EventCategory.AUTHENTICATION, "pam_auth_failure", EventOutcome.FAILURE, fields, details
        )
    if match := _PAM_SESSION.match(message):
        action = "session_opened" if match["state"] == "opened" else "session_closed"
        details = {"service": match["service"], "by": clean_str(match["by"])}
        return _Classified(
            EventCategory.SESSION,
            action,
            EventOutcome.SUCCESS,
            {"user.name": clean_str(match["user"])},
            details,
        )
    if match := _PAM_PASSWORD_CHANGED.match(message):
        return _Classified(
            EventCategory.IAM,
            "password_changed",
            EventOutcome.SUCCESS,
            {"user.name": clean_str(match["user"])},
            {"service": match["service"]},
        )
    return None


def _classify_sudo(message: str) -> _Classified | None:
    match = _SUDO.match(message)
    if match is None:
        return None
    reason = clean_str(match["reason"])
    command = match["command"].strip()
    fields = {
        "user.name": clean_str(match["user"]),
        "process.command_line": command,
        "process.executable": command.split(" ", 1)[0] or None,
    }
    details = {
        "target_user": match["target"],
        "tty": match["tty"],
        "cwd": match["pwd"],
        "reason": reason,
    }
    outcome = EventOutcome.FAILURE if reason else EventOutcome.SUCCESS
    return _Classified(EventCategory.PROCESS, "sudo_command", outcome, fields, details)


def _classify_su(message: str) -> _Classified | None:
    if match := _SU_FAILED.match(message):
        outcome = EventOutcome.FAILURE
    elif (match := _SU_SUCCESS.match(message)) or (match := _SU_SUCCESS_OLD.match(message)):
        outcome = EventOutcome.SUCCESS
    else:
        return None
    return _Classified(
        EventCategory.AUTHENTICATION,
        "su",
        outcome,
        {"user.name": clean_str(match["user"])},
        {"target_user": match["target"]},
    )


_ACCOUNT_RULES: tuple[_Rule, ...] = (
    (
        _NEW_USER,
        lambda m: _Classified(
            _IAM,
            "user_created",
            _SUCCESS,
            {"user.name": m["user"]},
            {"uid": int(m["uid"]), "gid": int(m["gid"]), "home": m["home"], "shell": m["shell"]},
        ),
    ),
    (
        _NEW_GROUP,
        lambda m: _Classified(
            _IAM, "group_created", _SUCCESS, {}, {"group": m["group"], "gid": int(m["gid"])}
        ),
    ),
    (
        _ADD_TO_GROUP,
        lambda m: _Classified(
            _IAM,
            "user_added_to_group",
            _SUCCESS,
            {"user.name": m["user"]},
            {"group": m["group"], "shadow": bool(m["shadow"])},
        ),
    ),
    (
        _GPASSWD_ADD,
        lambda m: _Classified(
            _IAM,
            "user_added_to_group",
            _SUCCESS,
            {"user.name": m["user"]},
            {"group": m["group"], "by": m["by"]},
        ),
    ),
    (_DELETE_USER, lambda m: _Classified(_IAM, "user_deleted", _SUCCESS, {"user.name": m["user"]})),
    (
        _DELETE_GROUP,
        lambda m: _Classified(_IAM, "group_deleted", _SUCCESS, {}, {"group": m["group"]}),
    ),
    (
        _CHANGE_PASSWORD,
        lambda m: _Classified(_IAM, "password_changed", _SUCCESS, {"user.name": m["user"]}),
    ),
)


def _classify(program: str, message: str) -> _Classified:
    classified: _Classified | None = None
    if program.startswith("sshd"):  # OpenSSH 9.8+ also logs as "sshd-session"
        classified = _first_match(_SSH_RULES, message)
    elif program == "sudo":
        classified = _classify_sudo(message)
    elif program in {"su", "su-l"}:
        classified = _classify_su(message)
    elif program in _ACCOUNT_PROGRAMS:
        classified = _first_match(_ACCOUNT_RULES, message)
    return classified or _classify_pam(message) or _Classified()


class LinuxAuthParser(LineParser):
    """auth.log / secure: SSH, sudo, su, PAM and account management."""

    name: ClassVar[str] = "linux_auth"
    label: ClassVar[str] = "Linux auth.log"
    description: ClassVar[str] = (
        "Syslog authentication logs: SSH logins, sudo, su, PAM sessions and "
        "account changes (useradd, usermod, ...)."
    )

    def parse_line(self, line: str) -> NormalizedEvent:
        match = _SYSLOG.match(line)
        if match is None:
            msg = "not a syslog line (expected 'timestamp host program[pid]: message')"
            raise ParseError(msg)
        timestamp = self._timestamp(match)
        program, message = match["program"], match["message"].strip()
        classified = _classify(program, message)

        fields: dict[str, Any] = {
            "host.name": clean_str(match["host"]) or self.context.default_host,
            "process.name": program,
            "process.pid": clean_int(match["pid"]),
            "event.category": classified.category,
            "event.action": classified.action,
            "event.outcome": classified.outcome,
            "message": message,
        }
        fields.update(classified.fields)
        raw_event: dict[str, Any] = {"line": line}
        details = {key: value for key, value in classified.details.items() if value is not None}
        if details:
            raw_event["details"] = details
        return build_event(
            timestamp=timestamp,
            log_source=LogSource.LINUX_AUTH,
            raw_line=line,
            raw_event=raw_event,
            fields=fields,
        )

    def _timestamp(self, match: re.Match[str]) -> datetime:
        if match["iso"]:
            try:
                return parse_timestamp(match["iso"])
            except ValueError as exc:
                msg = f"invalid timestamp {match['iso']!r}"
                raise ParseError(msg) from exc
        return _bsd_timestamp(
            match["month"], match["day"], match["time"], self.context.reference_time
        )

    @classmethod
    def sniff(cls, sample: Sample) -> float:
        if not sample.lines:
            return 0.0
        hits = sum(1 for line in sample.lines if _SYSLOG.match(line))
        return 0.9 * hits / len(sample.lines)


def _bsd_timestamp(month: str, day: str, time: str, reference: datetime) -> datetime:
    """Resolve a year-less syslog timestamp against ``reference``.

    The year is taken from the reference; if that would put the event more
    than a day in the future (December entries read in January), the previous
    year is used instead. Times are assumed to be UTC.
    """
    if month not in _MONTHS:
        msg = f"unknown month {month!r}"
        raise ParseError(msg)
    hour, minute, second = (int(part) for part in time.split(":"))
    reference = reference.astimezone(UTC)
    for year in (reference.year, reference.year - 1):
        try:
            moment = datetime(year, _MONTHS[month], int(day), hour, minute, second, tzinfo=UTC)
        except ValueError:
            continue  # e.g. Feb 29 in a non-leap year
        if moment - reference <= timedelta(days=1):
            return moment
    msg = f"invalid date {month} {day} {time}"
    raise ParseError(msg)
