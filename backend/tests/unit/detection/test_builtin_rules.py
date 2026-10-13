"""Every built-in rule against a matching and a non-matching example.

The examples are real log lines run through the real parsers, so these
tests cover the parser output and the rule logic together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from watchpost.detection.compiler import CompiledRule, compile_rule
from watchpost.detection.engine import Hit, evaluate, row_with_id
from watchpost.detection.mitre import TACTICS, technique_name
from watchpost.detection.store import load_rule_files
from watchpost.ingestion.parsers import JsonParser, LineParser, ParseContext, get_parser

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
RULES: dict[str, CompiledRule] = {
    rule_file.definition.id: compile_rule(rule_file.definition)
    for rule_file in load_rule_files(RULES_DIR)
}
REFERENCE = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
BASE = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
BS = chr(92)

ATTACKER = "203.0.113.45"
OTHER = "198.51.100.7"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def win(*parts: str) -> str:
    return BS.join(parts)


# ------------------------------------------------------------------ log builders


def syslog(second: float, program: str, message: str, day: int = 12) -> str:
    moment = BASE.replace(day=day) + timedelta(seconds=second)
    return f"{moment:%b} {moment.day:2d} {moment:%H:%M:%S} web-01 {program}: {message}"


def ssh_failures(
    count: int, ip: str = ATTACKER, user: str = "root", step: float = 5, start: float = 0
) -> list[str]:
    return [
        syslog(
            start + n * step,
            f"sshd[{3000 + n}]",
            f"Failed password for {user} from {ip} port {40000 + n} ssh2",
        )
        for n in range(count)
    ]


def ssh_accepted(second: float, ip: str, user: str = "root", day: int = 12) -> str:
    return syslog(
        second, "sshd[3999]", f"Accepted password for {user} from {ip} port 41000 ssh2", day=day
    )


def sudo(command: str, user: str = "backup") -> str:
    return syslog(
        0, "sudo", f"  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
    )


def windows(
    event_id: int, data: dict[str, Any], second: float = 0, channel: str = "Security"
) -> str:
    record = {
        "EventID": event_id,
        "TimeCreated": (BASE + timedelta(seconds=second)).isoformat(),
        "Computer": "WS-FIN-07",
        "Channel": channel,
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": data,
    }
    return json.dumps(record)


def sysmon(event_id: int, data: dict[str, Any]) -> str:
    return windows(event_id, data, channel="Microsoft-Windows-Sysmon/Operational")


def process(
    name: str, command_line: str, parent: str = "explorer.exe", user: str = "jsmith"
) -> dict[str, Any]:
    return {
        "SubjectUserName": user,
        "NewProcessName": win("C:", "Windows", "System32", name),
        "NewProcessId": "0x1a2c",
        "CommandLine": command_line,
        "ParentProcessName": win("C:", "Windows", parent),
        "ProcessId": "0x0f10",
    }


def logon_failure(second: float, ip: str) -> str:
    return windows(
        4625, {"TargetUserName": "administrator", "IpAddress": ip, "LogonType": "3"}, second
    )


def access(
    path: str,
    status: int = 200,
    ip: str = ATTACKER,
    ua: str = "Mozilla/5.0 (X11; Linux x86_64)",
    second: float = 0,
) -> str:
    moment = BASE + timedelta(seconds=second)
    return (
        f'{ip} - - [{moment:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'
    )


# ------------------------------------------------------------------ cases


@dataclass(frozen=True)
class Case:
    parser: str
    match: list[str]
    no_match: list[str]
    expected_group: dict[str, str] = field(default_factory=dict)


CASES: dict[str, Case] = {
    "ssh-brute-force": Case(
        "linux_auth",
        match=ssh_failures(10),
        no_match=ssh_failures(9) + ssh_failures(10, ip=OTHER, step=40),  # too few / too slow
        expected_group={"source.ip": ATTACKER},
    ),
    "ssh-password-spraying": Case(
        "linux_auth",
        match=[
            line
            for n, user in enumerate(["root", "admin", "oracle", "test", "ubuntu"])
            for line in ssh_failures(1, user=user, start=n * 20)
        ],
        no_match=ssh_failures(30),  # many attempts, one account: brute force, not spraying
    ),
    "ssh-brute-force-then-success": Case(
        "linux_auth",
        match=[*ssh_failures(5), ssh_accepted(60, ATTACKER)],
        no_match=[*ssh_failures(5), ssh_accepted(60, OTHER), *ssh_failures(2, ip=OTHER)],
        expected_group={"source.ip": ATTACKER},
    ),
    "linux-user-created": Case(
        "linux_auth",
        match=[
            syslog(
                0,
                "useradd[3150]",
                "new user: name=svc-update, UID=1003, GID=1003, home=/home/svc-update, shell=/bin/bash, from=/dev/pts/1",
            )
        ],
        no_match=[syslog(0, "useradd[3150]", "new group: name=svc-update, GID=1003")],
        expected_group={"user.name": "svc-update"},
    ),
    "linux-user-added-to-admin-group": Case(
        "linux_auth",
        match=[syslog(0, "usermod[3155]", "add 'svc-update' to group 'sudo'")],
        no_match=[syslog(0, "usermod[3155]", "add 'svc-update' to group 'video'")],
        expected_group={"user.name": "svc-update"},
    ),
    "linux-shadow-file-access": Case(
        "linux_auth",
        match=[sudo("/usr/bin/cat /etc/shadow")],
        no_match=[
            sudo("/usr/bin/cat /etc/hosts"),
            syslog(0, "sshd[1]", "Failed password for x from 10.0.0.1 port 1 ssh2 /etc/shadow"),
        ],
        expected_group={"user.name": "backup"},
    ),
    "login-from-new-source-ip": Case(
        "linux_auth",
        match=[
            ssh_accepted(0, "10.20.0.30", "backup", day=10),
            ssh_accepted(60, ATTACKER, "backup"),
        ],
        no_match=[
            ssh_accepted(0, "10.20.0.30", "backup", day=10),
            ssh_accepted(60, "10.20.0.30", "backup"),  # known address
            ssh_accepted(90, ATTACKER, "carol"),  # no history for carol yet
        ],
        expected_group={"user.name": "backup", "source.ip": ATTACKER},
    ),
    "windows-logon-brute-force": Case(
        "windows",
        match=[logon_failure(n * 10, "203.0.113.80") for n in range(10)],
        no_match=[logon_failure(n * 10, "-") for n in range(15)]
        + [logon_failure(n, "203.0.113.80") for n in range(9)],
        expected_group={"source.ip": "203.0.113.80"},
    ),
    "windows-encoded-powershell": Case(
        "windows",
        match=[
            windows(
                4688,
                process(
                    "powershell.exe",
                    f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {B64}",
                ),
            )
        ],
        no_match=[
            windows(
                4688,
                process(
                    "powershell.exe",
                    "powershell.exe -ExecutionPolicy Bypass -File C:/scripts/backup.ps1",
                ),
            ),
            windows(4688, process("cmd.exe", f"cmd.exe /c echo -enc {B64}")),
        ],
        expected_group={"user.name": "jsmith"},
    ),
    "windows-audit-log-cleared": Case(
        "windows",
        match=[windows(1102, {"SubjectUserName": "administrator"})],
        no_match=[windows(4624, {"TargetUserName": "administrator"})],
        expected_group={"host.name": "WS-FIN-07"},
    ),
    "windows-scheduled-task-created": Case(
        "windows",
        match=[windows(4698, {"SubjectUserName": "administrator", "TaskName": win("", "Updater")})],
        no_match=[
            windows(4699, {"SubjectUserName": "administrator", "TaskName": win("", "Updater")})
        ],
    ),
    "windows-user-account-created": Case(
        "windows",
        match=[
            windows(4720, {"TargetUserName": "helpdesk-svc", "SubjectUserName": "administrator"})
        ],
        no_match=[windows(4726, {"TargetUserName": "helpdesk-svc"})],
        expected_group={"user.name": "helpdesk-svc"},
    ),
    "windows-user-added-to-admin-group": Case(
        "windows",
        match=[
            windows(
                4732,
                {
                    "MemberSid": "S-1-5-21-1-1612",
                    "MemberName": "-",
                    "TargetUserName": "Administrators",
                },
            )
        ],
        no_match=[
            windows(
                4732,
                {
                    "MemberSid": "S-1-5-21-1-1612",
                    "MemberName": "-",
                    "TargetUserName": "Remote Desktop Users",
                },
            )
        ],
        expected_group={"user.name": "S-1-5-21-1-1612"},
    ),
    "sysmon-lsass-memory-access": Case(
        "windows",
        match=[
            sysmon(
                10,
                {
                    "SourceImage": win("C:", "Temp", "m.exe"),
                    "TargetImage": win("C:", "Windows", "System32", "lsass.exe"),
                    "GrantedAccess": "0x1010",
                },
            )
        ],
        no_match=[
            sysmon(
                10,
                {
                    "SourceImage": win("C:", "ProgramData", "Defender", "MsMpEng.exe"),
                    "TargetImage": win("C:", "Windows", "System32", "lsass.exe"),
                    "GrantedAccess": "0x1010",
                },
            ),
            sysmon(
                10,
                {
                    "SourceImage": win("C:", "Temp", "m.exe"),
                    "TargetImage": win("C:", "Windows", "System32", "lsass.exe"),
                    "GrantedAccess": "0x1000",
                },
            ),
            sysmon(
                10,
                {
                    "SourceImage": win("C:", "Temp", "m.exe"),
                    "TargetImage": win("C:", "Windows", "notepad.exe"),
                    "GrantedAccess": "0x1010",
                },
            ),
        ],
    ),
    "office-app-spawns-shell": Case(
        "windows",
        match=[
            sysmon(
                1,
                {
                    "Image": win("C:", "Windows", "System32", "cmd.exe"),
                    "CommandLine": "cmd.exe /c whoami",
                    "ParentImage": win("C:", "Office16", "WINWORD.EXE"),
                    "User": win("CORP", "jsmith"),
                },
            )
        ],
        no_match=[
            sysmon(
                1,
                {
                    "Image": win("C:", "Windows", "System32", "cmd.exe"),
                    "ParentImage": win("C:", "Windows", "explorer.exe"),
                },
            ),
            sysmon(
                1,
                {
                    "Image": win("C:", "Windows", "splwow64.exe"),
                    "ParentImage": win("C:", "Office16", "WINWORD.EXE"),
                },
            ),
        ],
        expected_group={"user.name": "jsmith"},
    ),
    "sysmon-registry-run-key": Case(
        "windows",
        match=[
            sysmon(
                13,
                {
                    "TargetObject": win(
                        "HKU",
                        "S-1-5-21-1",
                        "Software",
                        "Microsoft",
                        "Windows",
                        "CurrentVersion",
                        "Run",
                        "Updater",
                    ),
                    "Details": win("C:", "Temp", "m.exe"),
                },
            )
        ],
        no_match=[
            sysmon(
                13,
                {
                    "TargetObject": win("HKLM", "SOFTWARE", "Vendor", "Settings", "Theme"),
                    "Details": "dark",
                },
            )
        ],
    ),
    "web-directory-scanning": Case(
        "web_access",
        match=[access(f"/probe-{n}", 404, second=n * 3) for n in range(20)],
        no_match=[access(f"/probe-{n}", 404, second=n * 3) for n in range(19)]
        + [access(f"/page-{n}", 200, second=n) for n in range(30)],
        expected_group={"source.ip": ATTACKER},
    ),
    "web-sql-injection": Case(
        "web_access",
        match=[access("/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 500)],
        no_match=[access("/search?q=union+station+opening+hours"), access("/products?id=42")],
        expected_group={"source.ip": ATTACKER},
    ),
    "web-path-traversal": Case(
        "web_access",
        match=[access("/download?file=..%2F..%2F..%2Fetc%2Fpasswd", 400)],
        no_match=[access("/static/app.js?v=2"), access("/docs/index.html")],
        expected_group={"source.ip": ATTACKER},
    ),
    "web-scanner-user-agent": Case(
        "web_access",
        match=[access("/products?id=1", ua="sqlmap/1.8.4#stable (https://sqlmap.org)")],
        no_match=[
            access("/products?id=1", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0")
        ],
        expected_group={"source.ip": ATTACKER},
    ),
}


def run(rule_id: str, parser_name: str, lines: list[str]) -> list[Hit]:
    parser = get_parser(parser_name)(ParseContext(reference_time=REFERENCE))
    rows = []
    for number, line in enumerate(lines, start=1):
        if isinstance(parser, LineParser):
            event = parser.parse_line(line)
        else:
            assert isinstance(parser, JsonParser)
            event = parser.parse_record(json.loads(line))
        assert event is not None
        rows.append(row_with_id(event.to_row(), number))
    return evaluate(RULES[rule_id], rows)


# ------------------------------------------------------------------ tests


def test_every_rule_has_test_cases() -> None:
    assert set(CASES) == set(RULES)
    assert len(RULES) >= 15


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_matching_logs(rule_id: str) -> None:
    case = CASES[rule_id]

    hits = run(rule_id, case.parser, case.match)

    assert len(hits) == 1, f"{rule_id} should fire exactly once, got {len(hits)}"
    group = dict(hits[0].group)
    for field_name, value in case.expected_group.items():
        assert group.get(field_name) == value


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet_on_similar_benign_logs(rule_id: str) -> None:
    case = CASES[rule_id]

    assert run(rule_id, case.parser, case.no_match) == []


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_is_documented(rule_id: str) -> None:
    definition = RULES[rule_id].definition

    assert len(definition.description.split()) >= 20, "describe the attack and the evidence"
    assert definition.falsepositives, "list known false positives"
    assert definition.references, "link to ATT&CK or other references"
    assert definition.tactics and all(tactic in TACTICS for tactic in definition.tactics)
    assert definition.techniques
    assert all(technique_name(technique) for technique in definition.techniques)
