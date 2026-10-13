"""Helpers that turn messy log values into clean normalised values.

Every helper returns ``None`` for "no value" (empty strings, ``-``, ``N/A``)
instead of raising, so a single odd field never costs a whole event. Only
:func:`parse_timestamp` raises, because an event without a time is useless.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

_EMPTY_VALUES = frozenset({"", "-", "n/a", "na", "null", "none", "(null)", "nil"})
_DOTNET_DATE = re.compile(r"^/Date\((?P<ms>-?\d+)(?:[+-]\d{4})?\)/$")
_EPOCH_MS_THRESHOLD = 10**11  # anything above this is milliseconds, not seconds
_EPOCH_US_THRESHOLD = 10**14


def clean_str(value: object, max_length: int | None = None) -> str | None:
    """Strip a scalar value to text, mapping placeholder values to ``None``."""
    if value is None or isinstance(value, dict | list):
        return None
    text = str(value).strip()
    if text.lower() in _EMPTY_VALUES:
        return None
    if max_length is not None and len(text) > max_length:
        text = text[:max_length]
    return text


def clean_ip(value: object) -> str | None:
    """Return a canonical IP address string, or ``None`` if the value is not an IP.

    Handles bracketed IPv6 (``[2001:db8::1]``), zone IDs (``fe80::1%eth0``) and
    IPv4-mapped IPv6 (``::ffff:10.0.0.5`` becomes ``10.0.0.5``), which Windows
    uses in logon events.
    """
    text = clean_str(value)
    if text is None:
        return None
    text = text.strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return None
    return str(address)


def clean_int(value: object, *, minimum: int = 0, maximum: int = 2**31 - 1) -> int | None:
    """Parse decimal or ``0x`` hex integers (Windows logs PIDs in hex)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    else:
        text = clean_str(value)
        if text is None:
            return None
        try:
            number = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    if not minimum <= number <= maximum:
        return None
    return number


def clean_port(value: object) -> int | None:
    """A TCP/UDP port number, or ``None``."""
    return clean_int(value, maximum=65535)


def basename(path: str | None) -> str | None:
    """Final component of a Windows or POSIX path."""
    if not path:
        return None
    name = re.split(r"[\\/]", path.rstrip("\\/"))[-1]
    return name or None


def split_account(value: object) -> tuple[str | None, str | None]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(user, domain)``."""
    text = clean_str(value)
    if text is None:
        return None, None
    if "\\" in text:
        domain, _, user = text.partition("\\")
        return clean_str(user), clean_str(domain)
    if "@" in text:
        user, _, domain = text.partition("@")
        return clean_str(user), clean_str(domain)
    return text, None


def parse_timestamp(value: object) -> datetime:
    """Parse the timestamp formats seen in log exports into an aware UTC datetime.

    Supports ISO 8601 (with ``Z``, offsets or no zone, which is taken as UTC),
    ``YYYY-MM-DD HH:MM:SS``, epoch seconds/milliseconds/microseconds as numbers
    or strings, and the ``/Date(ms)/`` format written by Windows PowerShell.

    Raises:
        ValueError: if the value is missing or not a recognised timestamp.
    """
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, int | float) and not isinstance(value, bool):
        moment = _from_epoch(float(value))
    elif isinstance(value, str):
        moment = _parse_timestamp_text(value.strip())
    else:
        msg = f"unsupported timestamp value: {value!r}"
        raise ValueError(msg)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _parse_timestamp_text(text: str) -> datetime:
    if not text:
        msg = "empty timestamp"
        raise ValueError(msg)
    dotnet = _DOTNET_DATE.match(text)
    if dotnet:
        return _from_epoch(int(dotnet["ms"]) / 1000)
    if re.fullmatch(r"\d{9,17}(?:\.\d+)?", text):
        return _from_epoch(float(text))
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        msg = f"invalid timestamp {text[:64]!r}"
        raise ValueError(msg) from exc


def _from_epoch(number: float) -> datetime:
    if number > _EPOCH_US_THRESHOLD:
        number /= 1_000_000
    elif number > _EPOCH_MS_THRESHOLD:
        number /= 1000
    try:
        return datetime.fromtimestamp(number, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        msg = f"epoch value out of range: {number}"
        raise ValueError(msg) from exc
