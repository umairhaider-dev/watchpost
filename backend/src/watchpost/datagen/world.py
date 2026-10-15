"""The fictional organisation the generated logs describe.

Every address is in a private or documentation range (10.0.0.0/8,
192.168.0.0/16, 203.0.113.0/24 and 198.51.100.0/24) and every account name
is made up. Each person logs in from one address only, so ordinary activity
never looks like a login from somewhere new.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address

ALLOWED_NETWORKS: tuple[IPv4Network, ...] = tuple(
    IPv4Network(network)
    for network in ("10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24", "198.51.100.0/24")
)

DOMAIN = "corp.example.local"
NETBIOS_DOMAIN = "CORP"
SHOP_URL = "https://shop.example.com"


def is_allowed_address(text: str) -> bool:
    """Whether ``text`` is an IPv4 address inside :data:`ALLOWED_NETWORKS`."""
    address = ip_address(text)
    return any(address in network for network in ALLOWED_NETWORKS)


def stable_token(*parts: str, length: int = 43) -> str:
    """A deterministic base64 string, e.g. for SSH key fingerprints."""
    digest = hashlib.sha256("|".join(parts).encode()).digest()
    return base64.b64encode(digest).decode().rstrip("=")[:length]


def stable_hex(*parts: str, length: int = 64) -> str:
    """A deterministic uppercase hex string, e.g. for file hashes."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest().upper()[:length]


# --------------------------------------------------------------------------
# Linux servers
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LinuxUser:
    name: str
    uid: int
    address: str
    can_sudo: bool


LINUX_HOSTS = ("web-01", "web-02", "db-01", "bastion-01")
BACKUP_HOSTS = ("web-01", "db-01")

BACKUP_USER = LinuxUser("backup", 1002, "10.20.0.30", can_sudo=False)
LINUX_USERS: tuple[LinuxUser, ...] = (
    LinuxUser("deploy", 1001, "10.20.0.15", can_sudo=True),
    LinuxUser("ansible", 1003, "10.20.0.40", can_sudo=True),
    LinuxUser("r.okafor", 1101, "10.20.4.11", can_sudo=True),
    LinuxUser("m.lindqvist", 1102, "10.20.4.12", can_sudo=True),
    LinuxUser("t.haddad", 1103, "10.20.4.13", can_sudo=True),
    LinuxUser("s.ivanova", 1104, "10.20.4.14", can_sudo=False),
    LinuxUser("k.mensah", 1105, "10.20.4.15", can_sudo=False),
)

SUDO_COMMANDS = (
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status postgresql",
    "/usr/bin/apt-get update",
    "/usr/bin/journalctl -u nginx --since today",
    "/usr/bin/tail -n 200 /var/log/nginx/error.log",
    "/usr/bin/docker ps",
    "/usr/sbin/nginx -t",
    "/usr/bin/du -sh /var/lib/postgresql",
)

CRON_COMMANDS = (
    "/usr/local/bin/rotate-logs",
    "/usr/lib/sysstat/debian-sa1 1 1",
    "test -x /usr/sbin/anacron || run-parts --report /etc/cron.hourly",
    "/usr/local/bin/refresh-certificates --quiet",
)


# --------------------------------------------------------------------------
# Windows domain
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowsUser:
    name: str
    workstation: str
    address: str
    is_admin: bool = False

    @property
    def sid(self) -> str:
        rid = 1100 + int(stable_hex(self.name, length=4), 16) % 8000
        return f"S-1-5-21-1004336348-1177238915-682003330-{rid}"


DOMAIN_CONTROLLER = f"DC01.{DOMAIN}"
FILE_SERVER = f"FS01.{DOMAIN}"
SERVERS = (DOMAIN_CONTROLLER, FILE_SERVER)

ADMINISTRATOR = WindowsUser("administrator", "ADM-JUMP-01", "10.0.5.10", is_admin=True)

_PEOPLE = (
    ("a.petrova", "FIN"),
    ("b.nakamura", "FIN"),
    ("c.oyelaran", "FIN"),
    ("d.fontaine", "FIN"),
    ("e.vasquez", "FIN"),
    ("f.kowalczyk", "FIN"),
    ("g.adeyemi", "FIN"),
    ("h.lindgren", "ENG"),
    ("i.moreau", "ENG"),
    ("j.tanaka", "ENG"),
    ("k.obi", "ENG"),
    ("l.novak", "ENG"),
    ("m.castillo", "HR"),
    ("n.haugen", "HR"),
    ("o.mbeki", "SAL"),
    ("p.rossi", "SAL"),
    ("q.duarte", "SAL"),
    ("r.yilmaz", "OPS"),
)


def _windows_users() -> tuple[WindowsUser, ...]:
    users: list[WindowsUser] = []
    numbers: dict[str, int] = {}
    for index, (name, department) in enumerate(_PEOPLE):
        numbers[department] = numbers.get(department, 0) + 1
        workstation = f"WS-{department}-{numbers[department]:02d}"
        users.append(
            WindowsUser(name, workstation, f"10.0.5.{21 + index}", is_admin=department == "OPS")
        )
    return tuple(users)


WINDOWS_USERS = _windows_users()
# The finance user whose workstation the phishing scenario compromises.
PHISHING_VICTIM = next(user for user in WINDOWS_USERS if user.workstation == "WS-FIN-07")

DESKTOP_APPS = (
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"'),
    (
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        '"OUTLOOK.EXE" /recycle',
    ),
    (
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
        '"EXCEL.EXE" "C:\\Users\\{user}\\Documents\\budget-q{quarter}.xlsx"',
    ),
    (
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        '"WINWORD.EXE" /n "C:\\Users\\{user}\\Documents\\notes-{quarter}.docx"',
    ),
    ("C:\\Windows\\System32\\notepad.exe", '"notepad.exe"'),
    ("C:\\Program Files\\Microsoft VS Code\\Code.exe", '"Code.exe"'),
    ("C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\ms-teams.exe", '"ms-teams.exe"'),
    ("C:\\Windows\\System32\\mstsc.exe", '"mstsc.exe" /v:FS01'),
)

INTERNAL_DOMAINS = (
    f"intranet.{DOMAIN}",
    f"fs01.{DOMAIN}",
    "mail.example.org",
    "cdn.example.com",
    "docs.example.com",
    "updates.example.org",
    "calendar.example.org",
)


# --------------------------------------------------------------------------
# Attack infrastructure (all in documentation ranges)
# --------------------------------------------------------------------------

SSH_ATTACKER = "203.0.113.45"
WEB_SCANNER = "198.51.100.23"
LOGON_ATTACKER = "203.0.113.80"
C2_ADDRESS = "203.0.113.99"
C2_DOMAIN = "update-check.example.net"
MALWARE_SHA256 = "3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"
ATTACKER_ADDRESSES = frozenset({SSH_ATTACKER, WEB_SCANNER, LOGON_ATTACKER, C2_ADDRESS})
# Kept out of ordinary traffic too: samples/iocs.csv lists it as an old scanner.
_RESERVED = ATTACKER_ADDRESSES | {"198.51.100.200"}

# Customers and the wider internet.
INTERNET_ADDRESSES: tuple[str, ...] = tuple(
    address
    for prefix in ("203.0.113", "198.51.100")
    for address in (f"{prefix}.{host}" for host in range(1, 255))
    if address not in _RESERVED
)
OFFICE_ADDRESSES: tuple[str, ...] = tuple(f"192.168.1.{host}" for host in range(20, 120))
HEALTH_CHECKERS = ("10.0.8.4", "10.0.8.5")
