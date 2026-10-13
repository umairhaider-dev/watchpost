"""Custom column types."""

from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class IPAddress(TypeDecorator[str]):
    """An IPv4/IPv6 address stored as PostgreSQL ``INET``.

    Values are validated and normalised on the way in (``::ffff:10.0.0.1`` and
    ``10.0.0.1`` compare as different strings, so a canonical form matters for
    grouping) and always come back as plain strings regardless of how the
    driver decodes ``INET``.
    """

    impl = INET
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return str(ipaddress.ip_address(str(value).strip()))

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        # asyncpg may return an ip_interface; keep only the address part.
        return str(value).split("/", 1)[0]
