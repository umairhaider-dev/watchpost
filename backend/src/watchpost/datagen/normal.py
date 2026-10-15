"""Ordinary activity: what the logs look like on a day without an incident.

Each activity schedules one or more lines on a :class:`Timeline`, starting at
``now``. The mix is chosen so that none of the built-in rules fires on it:
logins come from each person's usual address, failed logins are single
typos, and nobody reads password files or adds administrators.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from watchpost.datagen.formats import access_line, syslog_line, sysmon_event, windows_event
from watchpost.datagen.timeline import Timeline
from watchpost.datagen.world import (
    ADMINISTRATOR,
    BACKUP_HOSTS,
    BACKUP_USER,
    CRON_COMMANDS,
    DESKTOP_APPS,
    DOMAIN_CONTROLLER,
    HEALTH_CHECKERS,
    INTERNAL_DOMAINS,
    INTERNET_ADDRESSES,
    LINUX_HOSTS,
    LINUX_USERS,
    NETBIOS_DOMAIN,
    OFFICE_ADDRESSES,
    SERVERS,
    SHOP_URL,
    SUDO_COMMANDS,
    WINDOWS_USERS,
    LinuxUser,
    WindowsUser,
    stable_hex,
    stable_token,
)

# Some activities return when they end; the generator ignores that.
Activity = Callable[[random.Random, float, Timeline], object]


def _pid(rng: random.Random) -> int:
    return rng.randint(1200, 65000)


def _port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


# --------------------------------------------------------------------------
# Linux auth.log
# --------------------------------------------------------------------------


def _sudo(out: Timeline, at: float, host: str, user: LinuxUser, command: str, tty: int) -> None:
    out.add(
        at,
        syslog_line(
            at,
            host,
            "sudo",
            None,
            f"{user.name:>8} : TTY=pts/{tty} ; PWD=/home/{user.name} ; USER=root ; "
            f"COMMAND={command}",
        ),
    )
    out.add(
        at + 0.002,
        syslog_line(
            at + 0.002,
            host,
            "sudo",
            None,
            f"pam_unix(sudo:session): session opened for user root(uid=0) by "
            f"{user.name}(uid={user.uid})",
        ),
    )
    closed = at + 0.5
    out.add(
        closed,
        syslog_line(
            closed, host, "sudo", None, "pam_unix(sudo:session): session closed for user root"
        ),
    )


def ssh_session(
    rng: random.Random,
    now: float,
    out: Timeline,
    *,
    user: LinuxUser | None = None,
    host: str | None = None,
    method: str = "publickey",
    fixed: bool = False,
) -> float:
    """An SSH login, a few sudo commands for admins, and the logout. Returns its end."""
    user = user or rng.choice(LINUX_USERS)
    host = host or rng.choice(LINUX_HOSTS)
    sshd, port, tty = _pid(rng), _port(rng), rng.randint(0, 9)
    accepted = f"Accepted {method} for {user.name} from {user.address} port {port} ssh2"
    if method == "publickey":
        accepted += f": ED25519 SHA256:{stable_token(user.name)}"
    lines = [
        (now, "sshd", sshd, accepted),
        (
            now + 0.004,
            "sshd",
            sshd,
            f"pam_unix(sshd:session): session opened for user {user.name}(uid={user.uid}) "
            "by (uid=0)",
        ),
        (
            now + 0.3,
            "systemd-logind",
            612,
            f"New session {rng.randint(100, 9999)} of user {user.name}.",
        ),
    ]
    for at, program, pid, message in lines:
        out.add(at, syslog_line(at, host, program, pid, message), fixed=fixed)
    at = now + 1
    if user.can_sudo:
        for _ in range(rng.randint(0, 3)):
            at += rng.uniform(20, 600)
            _sudo(out, at, host, user, rng.choice(SUDO_COMMANDS), tty)
    end = at + rng.uniform(30, 2400)
    for offset, message in (
        (0.0, f"Received disconnect from {user.address} port {port}:11: disconnected by user"),
        (0.001, f"Disconnected from user {user.name} {user.address} port {port}"),
        (0.003, f"pam_unix(sshd:session): session closed for user {user.name}"),
    ):
        out.add(end + offset, syslog_line(end + offset, host, "sshd", sshd, message), fixed=fixed)
    return end


# A person mistypes now and then, not every few minutes, however many events are generated.
TYPO_COOLDOWN_SECONDS = 6 * 3600


def mistyped_password(rng: random.Random, now: float, out: Timeline) -> None:
    """One or two wrong passwords, then the right one: a person, not a tool."""
    user = rng.choice(LINUX_USERS)
    host = rng.choice(LINUX_HOSTS)
    key = f"typo:{user.name}"
    if now - out.last_seen.get(key, float("-inf")) < TYPO_COOLDOWN_SECONDS:
        ssh_session(rng, now, out, user=user, host=host)
        return
    out.last_seen[key] = now
    sshd, port = _pid(rng), _port(rng)
    at = now
    for _ in range(rng.randint(1, 2)):
        out.add(
            at,
            syslog_line(
                at,
                host,
                "sshd",
                sshd,
                f"Failed password for {user.name} from {user.address} port {port} ssh2",
            ),
        )
        at += rng.uniform(3, 9)
    ssh_session(rng, at, out, user=user, host=host, method="password")


def cron_job(rng: random.Random, now: float, out: Timeline) -> None:
    host = rng.choice(LINUX_HOSTS)
    pid = _pid(rng)
    out.add(
        now,
        syslog_line(
            now,
            host,
            "CRON",
            pid,
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        ),
    )
    out.add(
        now + 0.001,
        syslog_line(now + 0.001, host, "CRON", pid, f"(root) CMD ({rng.choice(CRON_COMMANDS)})"),
    )
    closed = now + rng.uniform(0.05, 40)
    out.add(
        closed,
        syslog_line(
            closed, host, "CRON", pid, "pam_unix(cron:session): session closed for user root"
        ),
    )


def internet_noise(rng: random.Random, now: float, out: Timeline) -> None:
    """Connections from the internet that never get as far as a password."""
    address, port = rng.choice(INTERNET_ADDRESSES), _port(rng)
    message = rng.choice(
        (
            f"Connection closed by {address} port {port} [preauth]",
            f"Did not receive identification string from {address} port {port}",
            f"Unable to negotiate with {address} port {port}: no matching key exchange method "
            "found. Their offer: diffie-hellman-group1-sha1 [preauth]",
        )
    )
    out.add(now, syslog_line(now, "bastion-01", "sshd", _pid(rng), message))


def nightly_backup(rng: random.Random, now: float, out: Timeline, *, fixed: bool) -> None:
    """The backup account pulling data with its key from the backup server."""
    for host in BACKUP_HOSTS:
        ssh_session(rng, now + rng.uniform(0, 120), out, user=BACKUP_USER, host=host, fixed=fixed)


AUTH_ACTIVITIES: Sequence[tuple[Activity, float]] = (
    (ssh_session, 30),
    (cron_job, 45),
    (mistyped_password, 3),
    (internet_noise, 12),
)


# --------------------------------------------------------------------------
# Web access.log
# --------------------------------------------------------------------------

BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0 Mobile Safari/537.36",
)
APP_AGENT = "ShopApp/4.2 (Android 14; okhttp/4.12)"
CRAWLER_AGENT = "ExampleBot/2.1 (+https://example.org/bot)"
PROBE_AGENT = "kube-probe/1.30"

PRODUCTS = (
    "trail-runner-shoes",
    "merino-wool-socks",
    "waterproof-shell-jacket",
    "canvas-backpack",
    "insulated-bottle",
    "fleece-pullover",
    "hiking-poles",
    "sun-hat",
)
CATEGORIES = ("shoes", "jackets", "bags", "accessories", "outdoor")
SEARCHES = ("red+shoes", "rain+jacket", "backpack+30l", "wool+socks", "gift+card")
ASSETS = (("/static/app.css", 18233), ("/static/app.js", 90412), ("/static/logo.svg", 4211))
MISSING = (
    "/favicon.png",
    "/products/discontinued-boots",
    "/old-catalogue.pdf",
    "/apple-touch-icon.png",
)
CUSTOMERS = ("alice.w", "bo.huang", "carmen.r", "dmitri.v", "esi.a", "felix.m", "gita.p")


def _web_get(
    out: Timeline,
    at: float,
    client: str,
    path: str,
    agent: str,
    *,
    status: int = 200,
    size: int | None = None,
    referer: str | None = None,
    user: str | None = None,
    method: str = "GET",
    rng: random.Random,
) -> None:
    body = size if size is not None else rng.randint(2500, 40000)
    out.add(
        at,
        access_line(at, client, user, f"{method} {path} HTTP/1.1", status, body, referer, agent),
    )


def shop_visit(rng: random.Random, now: float, out: Timeline) -> None:
    """A customer browsing, maybe signing in and buying something."""
    client = rng.choice(OFFICE_ADDRESSES if rng.random() < 0.25 else INTERNET_ADDRESSES)
    agent = rng.choice(BROWSERS)
    at = now
    _web_get(out, at, client, "/", agent, size=5120, rng=rng)
    for path, size in ASSETS:
        at += rng.uniform(0.05, 0.4)
        cached = rng.random() < 0.3
        _web_get(
            out,
            at,
            client,
            path,
            agent,
            status=304 if cached else 200,
            size=0 if cached else size,
            referer=f"{SHOP_URL}/",
            rng=rng,
        )
    previous = f"{SHOP_URL}/"
    for _ in range(rng.randint(1, 7)):
        at += rng.uniform(4, 60)
        roll = rng.random()
        if roll < 0.35:
            path = f"/products?category={rng.choice(CATEGORIES)}"
        elif roll < 0.55:
            path = f"/search?q={rng.choice(SEARCHES)}"
        elif roll < 0.98:
            path = f"/products/{rng.choice(PRODUCTS)}"
        else:
            _web_get(
                out,
                at,
                client,
                rng.choice(MISSING),
                agent,
                status=404,
                size=196,
                referer=previous,
                rng=rng,
            )
            continue
        _web_get(out, at, client, path, agent, referer=previous, rng=rng)
        previous = f"{SHOP_URL}{path}"
    if rng.random() < 0.3:
        customer = rng.choice(CUSTOMERS)
        at += rng.uniform(5, 30)
        _web_get(
            out,
            at,
            client,
            "/login",
            agent,
            method="POST",
            status=302,
            size=0,
            referer=f"{SHOP_URL}/login",
            rng=rng,
        )
        at += rng.uniform(0.2, 1)
        _web_get(
            out, at, client, "/account", agent, user=customer, referer=f"{SHOP_URL}/login", rng=rng
        )
        if rng.random() < 0.5:
            at += rng.uniform(10, 120)
            _web_get(out, at, client, "/cart", agent, user=customer, referer=previous, rng=rng)
            at += rng.uniform(5, 60)
            _web_get(
                out,
                at,
                client,
                "/checkout",
                agent,
                method="POST",
                status=201,
                size=512,
                user=customer,
                referer=f"{SHOP_URL}/cart",
                rng=rng,
            )


def health_check(rng: random.Random, now: float, out: Timeline) -> None:
    _web_get(out, now, rng.choice(HEALTH_CHECKERS), "/healthz", PROBE_AGENT, size=2, rng=rng)


def app_request(rng: random.Random, now: float, out: Timeline) -> None:
    client = rng.choice(INTERNET_ADDRESSES)
    at = now
    for page in range(1, rng.randint(2, 4)):
        _web_get(out, at, client, f"/api/v1/products?page={page}", APP_AGENT, rng=rng)
        at += rng.uniform(0.5, 6)


def crawler(rng: random.Random, now: float, out: Timeline) -> None:
    client = rng.choice(INTERNET_ADDRESSES)
    _web_get(out, now, client, "/robots.txt", CRAWLER_AGENT, size=120, rng=rng)
    _web_get(
        out,
        now + rng.uniform(1, 5),
        client,
        f"/products/{rng.choice(PRODUCTS)}",
        CRAWLER_AGENT,
        rng=rng,
    )


WEB_ACTIVITIES: Sequence[tuple[Activity, float]] = (
    (shop_visit, 55),
    (health_check, 30),
    (app_request, 10),
    (crawler, 5),
)


# --------------------------------------------------------------------------
# Windows Security log
# --------------------------------------------------------------------------


def _logon_id(rng: random.Random) -> str:
    return f"0x{rng.randint(0x100000, 0xFFFFFFF):x}"


def domain_logon(
    rng: random.Random,
    now: float,
    out: Timeline,
    *,
    user: WindowsUser | None = None,
    server: str | None = None,
    fixed: bool = False,
) -> None:
    """A network logon to a server from the user's own workstation, and the logoff."""
    user = user or rng.choice(WINDOWS_USERS)
    server = server or rng.choice(SERVERS)
    logon_id = _logon_id(rng)
    base = {
        "SubjectUserSid": "S-1-0-0",
        "SubjectUserName": "-",
        "TargetUserSid": user.sid,
        "TargetUserName": user.name,
        "TargetDomainName": NETBIOS_DOMAIN,
        "TargetLogonId": logon_id,
        "LogonType": "3",
    }
    out.add(
        now,
        windows_event(
            now,
            4624,
            server,
            {
                **base,
                "LogonProcessName": "Kerberos",
                "AuthenticationPackageName": "Kerberos",
                "WorkstationName": user.workstation,
                "IpAddress": user.address,
                "IpPort": str(_port(rng)),
            },
        ),
        fixed=fixed,
    )
    if user.is_admin:
        out.add(
            now + 0.001,
            windows_event(
                now + 0.001,
                4672,
                server,
                {
                    "SubjectUserSid": user.sid,
                    "SubjectUserName": user.name,
                    "SubjectDomainName": NETBIOS_DOMAIN,
                    "SubjectLogonId": logon_id,
                    "PrivilegeList": "SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege",
                },
            ),
            fixed=fixed,
        )
    off = now + rng.uniform(5, 3600)
    out.add(off, windows_event(off, 4634, server, base), fixed=fixed)


def workstation_unlock(rng: random.Random, now: float, out: Timeline) -> None:
    """An interactive logon at the user's own desk (no network address)."""
    user = rng.choice(WINDOWS_USERS)
    computer = f"{user.workstation}.corp.example.local"
    data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": f"{user.workstation}$",
        "TargetUserSid": user.sid,
        "TargetUserName": user.name,
        "TargetDomainName": NETBIOS_DOMAIN,
        "TargetLogonId": _logon_id(rng),
        "LogonType": rng.choice(("2", "7")),
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
        "WorkstationName": user.workstation,
        "IpAddress": "-",
        "IpPort": "-",
    }
    out.add(now, windows_event(now, 4624, computer, data))


def service_ticket(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    out.add(
        now,
        windows_event(
            now,
            4769,
            DOMAIN_CONTROLLER,
            {
                "TargetUserName": f"{user.name}@CORP.EXAMPLE.LOCAL",
                "TargetDomainName": "CORP.EXAMPLE.LOCAL",
                "ServiceName": rng.choice(("FS01$", "cifs/FS01", "HTTP/intranet")),
                "TicketOptions": "0x40810000",
                "TicketEncryptionType": "0x12",
                "IpAddress": f"::ffff:{user.address}",
                "IpPort": str(_port(rng)),
                "Status": "0x0",
            },
        ),
    )


def _app_command(rng: random.Random, user: WindowsUser) -> tuple[str, str]:
    image, command = rng.choice(DESKTOP_APPS)
    quarter = str(rng.randint(1, 4))
    return image.format(user=user.name), command.format(user=user.name, quarter=quarter)


def process_start(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    image, command = _app_command(rng, user)
    out.add(
        now,
        windows_event(
            now,
            4688,
            f"{user.workstation}.corp.example.local",
            {
                "SubjectUserSid": user.sid,
                "SubjectUserName": user.name,
                "SubjectDomainName": NETBIOS_DOMAIN,
                "NewProcessId": hex(rng.randint(0x400, 0xFFFF)),
                "NewProcessName": image,
                "CommandLine": command,
                "ProcessId": hex(rng.randint(0x400, 0xFFFF)),
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "TokenElevationType": "%%1938",
            },
        ),
    )


def mistyped_logon(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    server = rng.choice(SERVERS)
    out.add(
        now,
        windows_event(
            now,
            4625,
            server,
            {
                "SubjectUserSid": "S-1-0-0",
                "SubjectUserName": "-",
                "TargetUserName": user.name,
                "TargetDomainName": NETBIOS_DOMAIN,
                "LogonType": "3",
                "WorkstationName": user.workstation,
                "IpAddress": user.address,
                "IpPort": str(_port(rng)),
                "AuthenticationPackageName": "NTLM",
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a",
                "FailureReason": "%%2313",
            },
            success=False,
        ),
    )
    domain_logon(rng, now + rng.uniform(4, 15), out, user=user, server=server)


def admin_logon(rng: random.Random, now: float, out: Timeline, *, fixed: bool = False) -> None:
    domain_logon(rng, now, out, user=ADMINISTRATOR, server=DOMAIN_CONTROLLER, fixed=fixed)


WINDOWS_ACTIVITIES: Sequence[tuple[Activity, float]] = (
    (domain_logon, 30),
    (service_ticket, 30),
    (workstation_unlock, 12),
    (process_start, 22),
    (mistyped_logon, 2),
    (admin_logon, 4),
)


# --------------------------------------------------------------------------
# Sysmon
# --------------------------------------------------------------------------


def _sysmon_user(user: WindowsUser) -> str:
    return f"{NETBIOS_DOMAIN}\\{user.name}"


def _computer(user: WindowsUser) -> str:
    return f"{user.workstation}.corp.example.local"


def app_launch(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    image, command = _app_command(rng, user)
    out.add(
        now,
        sysmon_event(
            now,
            1,
            _computer(user),
            {
                "ProcessGuid": f"{{{rng.getrandbits(32):08x}-5c1a-6710-a512-000000000b01}}",
                "ProcessId": rng.randint(1000, 30000),
                "Image": image,
                "CommandLine": command,
                "User": _sysmon_user(user),
                "IntegrityLevel": "Medium",
                "Hashes": f"SHA256={stable_hex(image)}",
                "ParentProcessId": rng.randint(1000, 30000),
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
            },
        ),
    )


def web_connection(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    out.add(
        now,
        sysmon_event(
            now,
            3,
            _computer(user),
            {
                "ProcessId": rng.randint(1000, 30000),
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "User": _sysmon_user(user),
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": user.address,
                "SourcePort": str(_port(rng)),
                "DestinationIp": rng.choice(INTERNET_ADDRESSES),
                "DestinationPort": "443",
            },
        ),
    )


def dns_lookup(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    name = rng.choice(INTERNAL_DOMAINS)
    answer = (
        f"10.0.1.{rng.randint(10, 60)}"
        if name.endswith(".local")
        else rng.choice(INTERNET_ADDRESSES)
    )
    out.add(
        now,
        sysmon_event(
            now,
            22,
            _computer(user),
            {
                "ProcessId": rng.randint(1000, 30000),
                "QueryName": name,
                "QueryStatus": "0",
                "QueryResults": f"::ffff:{answer};",
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "User": _sysmon_user(user),
            },
        ),
    )


def file_download(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    name = rng.choice(("invoice", "statement", "agenda", "slides", "report"))
    out.add(
        now,
        sysmon_event(
            now,
            11,
            _computer(user),
            {
                "ProcessId": rng.randint(1000, 30000),
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "TargetFilename": (
                    f"C:\\Users\\{user.name}\\Downloads\\{name}-{rng.randint(100, 999)}.pdf"
                ),
                "User": _sysmon_user(user),
            },
        ),
    )


def settings_change(rng: random.Random, now: float, out: Timeline) -> None:
    user = rng.choice(WINDOWS_USERS)
    value = rng.choice(("General\\ShownFirstRunOptin", "Toolbars\\Settings", "Roaming\\Identities"))
    out.add(
        now,
        sysmon_event(
            now,
            13,
            _computer(user),
            {
                "EventType": "SetValue",
                "ProcessId": rng.randint(1000, 30000),
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                "TargetObject": (
                    f"HKU\\{user.sid}\\Software\\Microsoft\\Office\\16.0\\Common\\{value}"
                ),
                "Details": "DWORD (0x00000001)",
                "User": _sysmon_user(user),
            },
        ),
    )


DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"


def antivirus_scan(rng: random.Random, now: float, out: Timeline) -> None:
    """Defender opening LSASS: legitimate, and excluded by the LSASS rule."""
    user = rng.choice(WINDOWS_USERS)
    out.add(
        now,
        sysmon_event(
            now,
            10,
            _computer(user),
            {
                "SourceProcessId": rng.randint(2000, 9000),
                "SourceImage": DEFENDER,
                "TargetProcessId": 712,
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceUser": "NT AUTHORITY\\SYSTEM",
                "TargetUser": "NT AUTHORITY\\SYSTEM",
            },
        ),
    )


SYSMON_ACTIVITIES: Sequence[tuple[Activity, float]] = (
    (app_launch, 25),
    (web_connection, 30),
    (dns_lookup, 25),
    (file_download, 8),
    (settings_change, 9),
    (antivirus_scan, 3),
)


def activity_level(timestamp: float) -> float:
    """How busy the organisation is at this hour, relative to a weekday afternoon."""
    moment = datetime.fromtimestamp(timestamp, UTC)
    working_day = moment.weekday() < 5
    if 8 <= moment.hour < 18:
        return 1.0 if working_day else 0.35
    if 6 <= moment.hour < 22:
        return 0.55 if working_day else 0.3
    return 0.2
