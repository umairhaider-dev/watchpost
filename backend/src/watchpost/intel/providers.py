"""Clients for external reputation services.

Two services are supported, each used only when its API key is configured:

* AbuseIPDB: abuse reports for IP addresses;
* VirusTotal: multi-engine verdicts for IPs, domains and file hashes.

Only public indicators are ever sent (see :func:`shareable`). Private,
loopback, documentation and other reserved addresses, single-label host
names and reserved or internal domain suffixes are checked against the local
indicator store only, so internal names never leave the network.
"""

from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar
from urllib.parse import quote

import httpx

from watchpost.core.config import Settings
from watchpost.db.models import EnrichmentStatus, IocType
from watchpost.intel.indicators import HASH_TYPES
from watchpost.intel.ratelimit import Limit

logger = logging.getLogger(__name__)

MINUTE = 60
DAY = 86_400
DEFAULT_COOLDOWN_SECONDS = 60.0

# Names under these suffixes never resolve on the public internet (RFC 2606,
# RFC 6761, RFC 8375) or are conventionally used for internal networks.
RESERVED_DOMAIN_SUFFIXES = (
    "example",
    "example.com",
    "example.net",
    "example.org",
    "invalid",
    "localhost",
    "test",
    "home.arpa",
    "local",
    "internal",
    "intranet",
    "lan",
    "corp",
    "home",
    "private",
)


class Verdict(StrEnum):
    """How an indicator looks, from least to most worrying."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


_VERDICT_RANK = {verdict: rank for rank, verdict in enumerate(Verdict)}


def worst(verdicts: Iterable[Verdict]) -> Verdict:
    """The most worrying verdict, or ``unknown`` if there are none."""
    return max(verdicts, key=_VERDICT_RANK.__getitem__, default=Verdict.UNKNOWN)


def shareable(ioc_type: IocType, value: str) -> bool:
    """Whether an indicator may be sent to a third party."""
    if ioc_type is IocType.IP:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.is_global and not address.is_multicast
    if ioc_type is IocType.DOMAIN:
        if "." not in value:
            return False
        return not any(
            value == suffix or value.endswith(f".{suffix}") for suffix in RESERVED_DOMAIN_SUFFIXES
        )
    return ioc_type in HASH_TYPES


@dataclass(frozen=True, slots=True)
class Answer:
    """What a provider said about one indicator, reduced to the useful fields."""

    status: EnrichmentStatus
    data: dict[str, Any] = field(default_factory=dict)


class ProviderError(Exception):
    """A lookup failed: network trouble, a rejected key or an unexpected reply."""


class RateLimitedError(Exception):
    """The provider answered 429; no more requests until ``retry_after`` seconds pass."""

    def __init__(self, provider: str, retry_after: float) -> None:
        super().__init__(f"{provider} is rate limiting requests")
        self.retry_after = retry_after


def _retry_after(response: httpx.Response) -> float:
    header = response.headers.get("Retry-After", "")
    try:
        seconds = float(header)
    except ValueError:
        return DEFAULT_COOLDOWN_SECONDS
    return min(max(seconds, 1.0), float(DAY))


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _timestamp(value: Any) -> str | None:
    """ISO 8601 from a Unix timestamp, as VirusTotal reports dates."""
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return datetime.fromtimestamp(value, tz=UTC).isoformat()


class Provider(ABC):
    """An external reputation service."""

    name: ClassVar[str]
    label: ClassVar[str]

    def __init__(self, api_key: str, limits: tuple[Limit, ...]) -> None:
        self._api_key = api_key
        self.limits = limits

    @abstractmethod
    def supports(self, ioc_type: IocType) -> bool:
        """Whether this service can look up indicators of this type."""

    @abstractmethod
    async def lookup(self, client: httpx.AsyncClient, ioc_type: IocType, value: str) -> Answer:
        """Ask the service about one indicator."""

    @abstractmethod
    def verdict(self, data: dict[str, Any]) -> Verdict:
        """Judge a successful answer's data."""

    async def _get_json(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """GET a JSON object; ``None`` means the service has no record (404)."""
        try:
            response = await client.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            # The exception text can include the URL; the class name is enough.
            msg = f"{self.label} request failed ({exc.__class__.__name__})"
            raise ProviderError(msg) from exc
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
            raise RateLimitedError(self.label, _retry_after(response))
        if response.status_code in {httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN}:
            msg = f"{self.label} rejected the API key (HTTP {response.status_code})"
            raise ProviderError(msg)
        if response.status_code != httpx.codes.OK:
            msg = f"{self.label} answered HTTP {response.status_code}"
            raise ProviderError(msg)
        try:
            body = response.json()
        except ValueError as exc:
            msg = f"{self.label} sent a reply that is not JSON"
            raise ProviderError(msg) from exc
        if not isinstance(body, dict):
            msg = f"{self.label} sent an unexpected reply"
            raise ProviderError(msg)
        return body


class AbuseIPDB(Provider):
    """AbuseIPDB's check endpoint: community abuse reports for an IP address."""

    name = "abuseipdb"
    label = "AbuseIPDB"
    url = "https://api.abuseipdb.com/api/v2/check"
    max_age_days = 90

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type is IocType.IP

    async def lookup(self, client: httpx.AsyncClient, ioc_type: IocType, value: str) -> Answer:
        body = await self._get_json(
            client,
            self.url,
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": str(self.max_age_days)},
        )
        if body is None:
            return Answer(EnrichmentStatus.NOT_FOUND)
        data = body.get("data")
        if not isinstance(data, dict):
            msg = f"{self.label} reply has no data"
            raise ProviderError(msg)
        return Answer(
            EnrichmentStatus.OK,
            {
                "score": _int(data.get("abuseConfidenceScore")),
                "reports": _int(data.get("totalReports")),
                "reporters": _int(data.get("numDistinctUsers")),
                "last_reported_at": _str(data.get("lastReportedAt")),
                "country": _str(data.get("countryCode")),
                "isp": _str(data.get("isp")),
                "usage_type": _str(data.get("usageType")),
                "domain": _str(data.get("domain")),
                "is_tor": data.get("isTor") is True,
                "is_whitelisted": data.get("isWhitelisted") is True,
                "link": f"https://www.abuseipdb.com/check/{quote(value, safe='')}",
            },
        )

    def verdict(self, data: dict[str, Any]) -> Verdict:
        score = data.get("score")
        if not isinstance(score, int):
            return Verdict.UNKNOWN
        if data.get("is_whitelisted"):
            return Verdict.CLEAN
        if score >= 75:
            return Verdict.MALICIOUS
        if score >= 25:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN


class VirusTotal(Provider):
    """VirusTotal's v3 API: antivirus engine verdicts for IPs, domains and files."""

    name = "virustotal"
    label = "VirusTotal"
    base_url = "https://www.virustotal.com/api/v3"
    # A few engines flag almost anything; one detection alone is only suspicious.
    malicious_engines = 3

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in {IocType.IP, IocType.DOMAIN} or ioc_type in HASH_TYPES

    @staticmethod
    def _paths(ioc_type: IocType) -> tuple[str, str]:
        """(API collection, web UI section) for an indicator type."""
        if ioc_type is IocType.IP:
            return "ip_addresses", "ip-address"
        if ioc_type is IocType.DOMAIN:
            return "domains", "domain"
        return "files", "file"

    async def lookup(self, client: httpx.AsyncClient, ioc_type: IocType, value: str) -> Answer:
        collection, section = self._paths(ioc_type)
        quoted = quote(value, safe="")
        body = await self._get_json(
            client,
            f"{self.base_url}/{collection}/{quoted}",
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        if body is None:
            return Answer(EnrichmentStatus.NOT_FOUND)
        data = body.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            msg = f"{self.label} reply has no attributes"
            raise ProviderError(msg)
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        summary: dict[str, Any] = {
            "malicious": _int(stats.get("malicious")) or 0,
            "suspicious": _int(stats.get("suspicious")) or 0,
            "harmless": _int(stats.get("harmless")) or 0,
            "undetected": _int(stats.get("undetected")) or 0,
            "reputation": _int(attributes.get("reputation")),
            "last_analysis_at": _timestamp(attributes.get("last_analysis_date")),
            "link": f"https://www.virustotal.com/gui/{section}/{quoted}",
        }
        if ioc_type is IocType.IP:
            summary["country"] = _str(attributes.get("country"))
            summary["as_owner"] = _str(attributes.get("as_owner"))
        elif ioc_type is IocType.DOMAIN:
            summary["registrar"] = _str(attributes.get("registrar"))
        else:
            summary["name"] = _str(attributes.get("meaningful_name"))
            summary["file_type"] = _str(attributes.get("type_description"))
        return Answer(EnrichmentStatus.OK, summary)

    def verdict(self, data: dict[str, Any]) -> Verdict:
        malicious = data.get("malicious")
        suspicious = data.get("suspicious")
        if not isinstance(malicious, int) or not isinstance(suspicious, int):
            return Verdict.UNKNOWN
        if malicious >= self.malicious_engines:
            return Verdict.MALICIOUS
        if malicious or suspicious:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN


PROVIDER_LABELS = {AbuseIPDB.name: AbuseIPDB.label, VirusTotal.name: VirusTotal.label}


def configured_providers(settings: Settings) -> list[Provider]:
    """The providers whose API keys are set, with their free-tier rate limits."""
    providers: list[Provider] = []
    if settings.abuseipdb_api_key is not None:
        providers.append(
            AbuseIPDB(
                settings.abuseipdb_api_key.get_secret_value(),
                (Limit(settings.abuseipdb_daily_limit, DAY),),
            )
        )
    if settings.virustotal_api_key is not None:
        providers.append(
            VirusTotal(
                settings.virustotal_api_key.get_secret_value(),
                (
                    Limit(settings.virustotal_per_minute, MINUTE),
                    Limit(settings.virustotal_daily_limit, DAY),
                ),
            )
        )
    return providers
