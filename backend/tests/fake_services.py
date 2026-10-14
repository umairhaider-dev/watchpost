"""Offline stand-ins for AbuseIPDB and VirusTotal.

Nothing in the test suite talks to the network: provider clients are given an
``httpx.AsyncClient`` whose transport is :class:`FakeServices`, which answers
the way the real APIs do and records every request.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.intel.enrichment import Enricher
from watchpost.intel.providers import DAY, MINUTE, AbuseIPDB, Provider, VirusTotal
from watchpost.intel.ratelimit import Limit, RateLimiter

ABUSE_KEY = "abuse-test-key"
VT_KEY = "vt-test-key"
MIMIKATZ_SHA256 = "3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a"


class FakeServices:
    """Answers like the two services; unknown indicators get a 404."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.abuse_scores: dict[str, int] = {}
        self.vt_detections: dict[str, int] = {}
        # When set, every request gets this status (and headers) instead.
        self.fail_with: int | None = None
        self.fail_headers: dict[str, str] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            return httpx.Response(
                self.fail_with, headers=self.fail_headers, json={"errors": [{"detail": "no"}]}
            )
        if request.url.host == "api.abuseipdb.com":
            return self._abuseipdb(request)
        if request.url.host == "www.virustotal.com":
            return self._virustotal(request)
        return httpx.Response(500)

    def _abuseipdb(self, request: httpx.Request) -> httpx.Response:
        address = request.url.params["ipAddress"]
        score = self.abuse_scores.get(address, 0)
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": address,
                    "isPublic": True,
                    "abuseConfidenceScore": score,
                    "countryCode": "NL",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example Hosting B.V.",
                    "domain": "example.net",
                    "isTor": False,
                    "isWhitelisted": False,
                    "totalReports": score // 5,
                    "numDistinctUsers": score // 10,
                    "lastReportedAt": "2026-10-11T22:14:03+00:00" if score else None,
                }
            },
        )

    def _virustotal(self, request: httpx.Request) -> httpx.Response:
        value = request.url.path.rsplit("/", 1)[-1]
        if value not in self.vt_detections:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        malicious = self.vt_detections[value]
        attributes: dict[str, Any] = {
            "last_analysis_stats": {
                "malicious": malicious,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 70 - malicious,
            },
            "reputation": -malicious,
            "last_analysis_date": 1_791_763_200,
            "meaningful_name": "m.exe",
            "type_description": "Win32 EXE",
            "country": "NL",
            "as_owner": "Example Hosting B.V.",
            "registrar": "Example Registrar",
        }
        return httpx.Response(200, json={"data": {"id": value, "attributes": attributes}})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self))

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]


def abuseipdb(per_day: int = 1000) -> AbuseIPDB:
    return AbuseIPDB(ABUSE_KEY, (Limit(per_day, DAY),))


def virustotal(per_minute: int = 4, per_day: int = 500) -> VirusTotal:
    return VirusTotal(VT_KEY, (Limit(per_minute, MINUTE), Limit(per_day, DAY)))


def make_enricher(
    session_factory: async_sessionmaker[AsyncSession],
    redis: Redis,
    client: httpx.AsyncClient,
    providers: list[Provider] | None = None,
) -> Enricher:
    return Enricher(
        session_factory,
        [abuseipdb(), virustotal()] if providers is None else providers,
        RateLimiter(redis),
        client,
        cache_ttl=timedelta(hours=24),
    )
