"""Recognising and normalising indicators of compromise.

Feeds and analysts write indicators in many ways: defanged
(``203.0.113[.]45``, ``hxxps://evil[.]example/x``), as full URLs, with
upper-case hashes or trailing dots on domains. Every value is reduced to one
canonical form so lookups are plain equality checks:

* IPs: canonical text (``2001:db8::1``; IPv4-mapped IPv6 becomes IPv4)
* domains: lower-case, IDNA-encoded, no trailing dot, no ``*.`` prefix
* hashes: lower-case hex, typed by length (MD5, SHA-1, SHA-256)
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from watchpost.db.models import IocType
from watchpost.ingestion.values import clean_ip


class IndicatorError(ValueError):
    """A value is not a usable indicator."""


HASH_TYPES = frozenset({IocType.MD5, IocType.SHA1, IocType.SHA256})
_HASH_BY_LENGTH = {32: IocType.MD5, 40: IocType.SHA1, 64: IocType.SHA256}
_HEX = re.compile(r"^[0-9a-f]+$")
_MIN_HASH_ATTEMPT = 24
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*\.(?!-)[a-z0-9-]{{2,63}}$")
_DEFANG = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("hxxp", "http"),
    ("hXXp", "http"),
    ("fxp", "ftp"),
)

# Names feeds use for indicator types, mapped to ours. "hash" means any of
# the hash types, decided by length.
TYPE_SYNONYMS: dict[str, IocType | None] = {
    "ip": IocType.IP,
    "ipv4": IocType.IP,
    "ipv6": IocType.IP,
    "ip-src": IocType.IP,
    "ip-dst": IocType.IP,
    "ipaddress": IocType.IP,
    "domain": IocType.DOMAIN,
    "fqdn": IocType.DOMAIN,
    "hostname": IocType.DOMAIN,
    "url": IocType.DOMAIN,
    "md5": IocType.MD5,
    "sha1": IocType.SHA1,
    "sha256": IocType.SHA256,
    "hash": None,
    "filehash": None,
    "file_hash": None,
}


def refang(text: str) -> str:
    """Undo common defanging so ``evil[.]example`` becomes ``evil.example``."""
    for fanged, plain in _DEFANG:
        text = text.replace(fanged, plain)
    return text


def parse_declared_type(value: str | None) -> tuple[bool, IocType | None]:
    """Interpret a feed's type column. Returns ``(known, type)``; ``None`` type means any hash."""
    if not value or not value.strip():
        return True, None
    key = value.strip().lower().replace(" ", "")
    if key not in TYPE_SYNONYMS:
        return False, None
    return True, TYPE_SYNONYMS[key]


def normalize_indicator(
    raw: str, declared: IocType | None = None, *, any_hash: bool = False
) -> tuple[IocType, str]:
    """Classify and canonicalise one indicator.

    ``declared`` is the type a feed says the value has; a mismatch is an
    error rather than a silent reinterpretation. ``any_hash`` accepts any
    hash type (for feeds that only say "hash").

    Raises:
        IndicatorError: with a short reason.
    """
    text = refang(raw.strip()).strip().strip("\"'")
    if not text:
        msg = "empty value"
        raise IndicatorError(msg)
    if "://" in text:
        host = urlsplit(text).hostname
        if not host:
            msg = f"URL without a host: {text[:80]!r}"
            raise IndicatorError(msg)
        text = host

    detected, value = _classify(text)
    if any_hash and detected not in HASH_TYPES:
        msg = f"expected a file hash, got a {detected.value}"
        raise IndicatorError(msg)
    if declared is not None and declared is not detected:
        msg = f"value looks like a {detected.value}, not a {declared.value}"
        raise IndicatorError(msg)
    return detected, value


def _classify(text: str) -> tuple[IocType, str]:
    if "/" in text and clean_ip(text.split("/", 1)[0]):
        msg = "CIDR ranges are not supported; list individual addresses"
        raise IndicatorError(msg)
    ip = clean_ip(text)
    if ip is not None:
        return IocType.IP, ip
    lowered = text.lower()
    # Long hex strings are meant as hashes; short ones fall through to "not an indicator".
    if _HEX.match(lowered) and len(lowered) >= _MIN_HASH_ATTEMPT:
        hash_type = _HASH_BY_LENGTH.get(len(lowered))
        if hash_type is None:
            msg = f"{len(lowered)} hex characters is not an MD5, SHA-1 or SHA-256 hash"
            raise IndicatorError(msg)
        return hash_type, lowered
    domain = normalize_domain(lowered)
    if domain is None:
        msg = f"not an IP address, domain or file hash: {text[:80]!r}"
        raise IndicatorError(msg)
    return IocType.DOMAIN, domain


def normalize_domain(value: str) -> str | None:
    """Canonical form of a domain name, or ``None`` if it is not one."""
    text = value.strip().lower().rstrip(".").removeprefix("*.")
    if not text or text.replace(".", "").isdigit():
        return None
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return text if _DOMAIN.match(text) else None


def parent_domains(domain: str) -> list[str]:
    """``a.b.evil.example`` -> ``[a.b.evil.example, b.evil.example, evil.example]``.

    Used for matching: an indicator for ``evil.example`` also covers its
    subdomains. Bare top-level domains are never returned.
    """
    labels = domain.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]
