from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers import LinuxAuthParser, ParseContext
from watchpost.ingestion.readers import Sample

HEADER = "Oct 12 09:02:13 web-01"


def parse(context: ParseContext, line: str) -> NormalizedEvent:
    return LinuxAuthParser(context).parse_line(line)


def summary(event: NormalizedEvent) -> dict[str, Any]:
    flat = event.flatten()
    return {
        key: flat.get(key)
        for key in (
            "event.category",
            "event.action",
            "event.outcome",
            "user.name",
            "source.ip",
            "source.port",
        )
    }


def details(event: NormalizedEvent) -> dict[str, Any]:
    value = event.raw_event.get("details", {})
    assert isinstance(value, dict)
    return value


# ------------------------------------------------------------------ header


def test_header_fields(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sshd[3101]: Failed password for root from 203.0.113.45 port 40112 ssh2",
    )

    assert event.timestamp == datetime(2026, 10, 12, 9, 2, 13, tzinfo=UTC)
    assert event.host.name == "web-01"
    assert event.process.name == "sshd"
    assert event.process.pid == 3101
    assert event.log_source == "linux_auth"
    assert event.message == "Failed password for root from 203.0.113.45 port 40112 ssh2"
    assert event.raw_event["line"].startswith("Oct 12")


def test_rfc3339_header(context: ParseContext) -> None:
    event = parse(
        context,
        "2026-10-12T09:02:13.123456+02:00 web-01 sshd[1]: Accepted publickey for a "
        "from 10.0.0.1 port 22 ssh2",
    )

    assert event.timestamp == datetime(2026, 10, 12, 7, 2, 13, 123456, tzinfo=UTC)


def test_year_rolls_back_for_december_lines_read_in_january() -> None:
    january = ParseContext(reference_time=datetime(2027, 1, 2, tzinfo=UTC))

    event = parse(january, "Dec 31 23:59:59 web-01 sshd[1]: Server listening on :: port 22.")

    assert event.timestamp.year == 2026


def test_single_digit_day_with_padding(context: ParseContext) -> None:
    event = parse(
        context, "Oct  2 01:02:03 web-01 CRON[5]: (root) CMD (run-parts /etc/cron.hourly)"
    )

    assert event.timestamp == datetime(2026, 10, 2, 1, 2, 3, tzinfo=UTC)


@pytest.mark.parametrize(
    "line",
    [
        "this is not syslog",
        "Oct 12 web-01 sshd[1]: missing time",
        "Oct 12 09:02:13",
        "Foo 12 09:02:13 web-01 sshd[1]: unknown month",
        "Oct 32 09:02:13 web-01 sshd[1]: impossible day",
        "Feb 30 09:02:13 web-01 sshd[1]: impossible date",
        "2026-13-45T99:00:00Z web-01 sshd[1]: bad iso date",
        '{"json": "is not syslog"}',
    ],
)
def test_malformed_lines_raise(context: ParseContext, line: str) -> None:
    with pytest.raises(ParseError):
        parse(context, line)


def test_unrecognised_message_is_kept_as_generic_event(context: ParseContext) -> None:
    event = parse(context, f"{HEADER} systemd-logind[612]: New session 41 of user deploy.")

    assert summary(event)["event.action"] is None
    assert event.process.name == "systemd-logind"
    assert "details" not in event.raw_event


# ------------------------------------------------------------------ sshd


def test_failed_password(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} sshd[1]: Failed password for root from 203.0.113.45 port 40112 ssh2"
    )

    assert summary(event) == {
        "event.category": "authentication",
        "event.action": "ssh_login",
        "event.outcome": "failure",
        "user.name": "root",
        "source.ip": "203.0.113.45",
        "source.port": 40112,
    }
    assert details(event) == {"auth_method": "password", "invalid_user": False}


def test_failed_password_for_invalid_user(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sshd[1]: Failed password for invalid user admin from 203.0.113.45 port 1 ssh2",
    )

    assert summary(event)["user.name"] == "admin"
    assert details(event)["invalid_user"] is True


def test_accepted_publickey_on_sshd_session_program(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sshd-session[1]: Accepted publickey for deploy from 10.20.0.15 port 51522 "
        "ssh2: ED25519 SHA256:abc",
    )

    assert summary(event)["event.outcome"] == "success"
    assert summary(event)["user.name"] == "deploy"
    assert details(event) == {"auth_method": "publickey"}


def test_ipv6_source(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} sshd[1]: Accepted password for a from 2001:db8::5 port 22 ssh2"
    )

    assert summary(event)["source.ip"] == "2001:db8::5"


def test_hostname_instead_of_ip_is_not_put_in_source_ip(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} sshd[1]: Failed password for root from scanner.example port 22 ssh2"
    )

    assert summary(event)["source.ip"] is None
    assert summary(event)["user.name"] == "root"


@pytest.mark.parametrize(
    ("message", "action", "outcome", "user"),
    [
        (
            "Invalid user oracle from 203.0.113.45 port 40131",
            "ssh_invalid_user",
            "failure",
            "oracle",
        ),
        (
            "error: maximum authentication attempts exceeded for root from 203.0.113.45 "
            "port 40160 ssh2 [preauth]",
            "ssh_max_auth_attempts",
            "failure",
            "root",
        ),
        (
            "Connection closed by invalid user admin 203.0.113.45 port 40112 [preauth]",
            "ssh_connection_closed",
            None,
            "admin",
        ),
        ("Connection reset by 203.0.113.45 port 40112", "ssh_connection_closed", None, None),
        (
            "Received disconnect from 10.20.0.15 port 51522:11: disconnected by user",
            "ssh_disconnect",
            None,
            None,
        ),
        ("Disconnected from user deploy 10.20.0.15 port 51522", "ssh_disconnect", None, "deploy"),
        (
            "Did not receive identification string from 198.51.100.77 port 61000",
            "ssh_no_identification",
            "failure",
            None,
        ),
        (
            "Unable to negotiate with 198.51.100.77 port 61002: no matching key exchange method",
            "ssh_negotiation_failed",
            "failure",
            None,
        ),
    ],
)
def test_other_ssh_messages(
    context: ParseContext, message: str, action: str, outcome: str | None, user: str | None
) -> None:
    result = summary(parse(context, f"{HEADER} sshd[1]: {message}"))

    assert result["event.action"] == action
    assert result["event.outcome"] == outcome
    assert result["user.name"] == user
    assert result["source.ip"] is not None


def test_ssh_pattern_does_not_match_other_programs(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} myapp[1]: Failed password for root from 203.0.113.45 port 1 ssh2"
    )

    assert summary(event)["event.action"] is None


# ------------------------------------------------------------------ PAM


def test_pam_authentication_failure(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 "
        "euid=0 tty=ssh ruser= rhost=203.0.113.45  user=backup",
    )

    assert summary(event)["event.action"] == "pam_auth_failure"
    assert summary(event)["user.name"] == "backup"
    assert summary(event)["source.ip"] == "203.0.113.45"
    assert details(event) == {"service": "sshd", "tty": "ssh"}


@pytest.mark.parametrize(
    ("message", "action", "user", "by"),
    [
        (
            "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1001)",
            "session_opened",
            "root",
            "deploy",
        ),
        (
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "session_opened",
            "root",
            None,
        ),
        (
            "pam_unix(sshd:session): session closed for user deploy",
            "session_closed",
            "deploy",
            None,
        ),
    ],
)
def test_pam_sessions(
    context: ParseContext, message: str, action: str, user: str, by: str | None
) -> None:
    event = parse(context, f"{HEADER} CRON[1]: {message}")

    assert summary(event)["event.category"] == "session"
    assert summary(event)["event.action"] == action
    assert summary(event)["user.name"] == user
    assert details(event).get("by") == by


def test_pam_password_change(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} passwd[1]: pam_unix(passwd:chauthtok): password changed for svc-update"
    )

    assert summary(event)["event.action"] == "password_changed"
    assert summary(event)["user.name"] == "svc-update"


# ------------------------------------------------------------------ sudo / su


def test_sudo_command(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sudo:   backup : TTY=pts/1 ; PWD=/home/backup ; USER=root ; "
        "COMMAND=/usr/bin/cat /etc/shadow",
    )

    assert summary(event)["event.action"] == "sudo_command"
    assert summary(event)["event.outcome"] == "success"
    assert summary(event)["user.name"] == "backup"
    assert event.process.command_line == "/usr/bin/cat /etc/shadow"
    assert event.process.executable == "/usr/bin/cat"
    assert details(event) == {"target_user": "root", "tty": "pts/1", "cwd": "/home/backup"}


@pytest.mark.parametrize(
    "reason", ["3 incorrect password attempts", "user NOT in sudoers", "command not allowed"]
)
def test_sudo_failures(context: ParseContext, reason: str) -> None:
    event = parse(
        context,
        f"{HEADER} sudo:    dave : {reason} ; TTY=pts/3 ; PWD=/home/dave ; USER=root ; "
        "COMMAND=/bin/bash",
    )

    assert summary(event)["event.outcome"] == "failure"
    assert details(event)["reason"] == reason


def test_sudo_with_env_and_group(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} sudo: alice : TTY=pts/0 ; PWD=/srv ; USER=root ; GROUP=adm ; ENV=A=1 ; "
        "COMMAND=/usr/bin/id",
    )

    assert event.process.command_line == "/usr/bin/id"


def test_sudo_unrelated_message_is_generic(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} sudo: unable to resolve host web-01: Name or service not known"
    )

    assert summary(event)["event.action"] is None


@pytest.mark.parametrize(
    ("message", "outcome", "user", "target"),
    [
        ("FAILED SU (to root) dave on pts/3", "failure", "dave", "root"),
        ("(to root) alice on pts/0", "success", "alice", "root"),
        ("Successful su for root by alice", "success", "alice", "root"),
    ],
)
def test_su(context: ParseContext, message: str, outcome: str, user: str, target: str) -> None:
    event = parse(context, f"{HEADER} su[1]: {message}")

    assert summary(event)["event.action"] == "su"
    assert summary(event)["event.outcome"] == outcome
    assert summary(event)["user.name"] == user
    assert details(event)["target_user"] == target


# ------------------------------------------------------------------ accounts


def test_user_created(context: ParseContext) -> None:
    event = parse(
        context,
        f"{HEADER} useradd[3150]: new user: name=svc-update, UID=1003, GID=1003, "
        "home=/home/svc-update, shell=/bin/bash, from=/dev/pts/1",
    )

    assert summary(event)["event.category"] == "iam"
    assert summary(event)["event.action"] == "user_created"
    assert summary(event)["user.name"] == "svc-update"
    assert details(event) == {
        "uid": 1003,
        "gid": 1003,
        "home": "/home/svc-update",
        "shell": "/bin/bash",
    }


@pytest.mark.parametrize(
    ("program", "message", "action", "user"),
    [
        ("useradd", "new group: name=svc-update, GID=1003", "group_created", None),
        ("usermod", "add 'svc-update' to group 'sudo'", "user_added_to_group", "svc-update"),
        ("usermod", "add 'svc-update' to shadow group 'sudo'", "user_added_to_group", "svc-update"),
        ("gpasswd", "user mallory added by root to group sudo", "user_added_to_group", "mallory"),
        ("userdel", "delete user 'olduser'", "user_deleted", "olduser"),
        ("groupdel", "removed group 'olduser' owned by 'olduser'", "group_deleted", None),
        ("usermod", "change user 'alice' password", "password_changed", "alice"),
    ],
)
def test_account_management(
    context: ParseContext, program: str, message: str, action: str, user: str | None
) -> None:
    event = parse(context, f"{HEADER} {program}[1]: {message}")

    assert summary(event)["event.action"] == action
    assert summary(event)["user.name"] == user


def test_group_membership_details(context: ParseContext) -> None:
    event = parse(context, f"{HEADER} usermod[1]: add 'svc-update' to shadow group 'sudo'")

    assert details(event) == {"group": "sudo", "shadow": True}


def test_account_message_from_unrelated_program_is_generic(context: ParseContext) -> None:
    event = parse(
        context, f"{HEADER} kernel: new user: name=x, UID=1, GID=1, home=/, shell=/bin/sh"
    )

    assert summary(event)["event.action"] is None


# ------------------------------------------------------------------ sniffing


def test_sniff_scores_syslog_high_and_others_zero() -> None:
    syslog = Sample(lines=[f"{HEADER} sshd[1]: hello"] * 5, records=[])
    web = Sample(
        lines=['1.2.3.4 - - [12/Oct/2026:09:10:01 +0000] "GET / HTTP/1.1" 200 1'], records=[]
    )

    assert LinuxAuthParser.sniff(syslog) == pytest.approx(0.9)
    assert LinuxAuthParser.sniff(web) == 0
    assert LinuxAuthParser.sniff(Sample(lines=[], records=[])) == 0
