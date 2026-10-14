from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.fake_services import ABUSE_KEY, MIMIKATZ_SHA256, VT_KEY, abuseipdb, virustotal
from watchpost.core.config import Settings
from watchpost.db.models import EnrichmentStatus, IocType
from watchpost.intel.providers import (
    DAY,
    DEFAULT_COOLDOWN_SECONDS,
    MINUTE,
    AbuseIPDB,
    ProviderError,
    RateLimitedError,
    Verdict,
    VirusTotal,
    configured_providers,
    shareable,
    worst,
)
from watchpost.intel.ratelimit import Limit

Handler = Callable[[httpx.Request], httpx.Response]


def client(handler: Handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def answer(status: int, **kwargs: Any) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, **kwargs)

    return handler


# --------------------------------------------------------------------------
# What may leave the network
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IocType.IP, "10.20.0.30"),
        (IocType.IP, "192.168.1.31"),
        (IocType.IP, "203.0.113.45"),  # documentation range
        (IocType.IP, "198.51.100.23"),  # documentation range
        (IocType.IP, "127.0.0.1"),
        (IocType.IP, "224.0.0.251"),
        (IocType.IP, "fe80::1"),
        (IocType.IP, "2001:db8::1"),
        (IocType.IP, "not-an-address"),
        (IocType.DOMAIN, "update-check.example.net"),
        (IocType.DOMAIN, "example.com"),
        (IocType.DOMAIN, "files-01"),
        (IocType.DOMAIN, "dc01.corp"),
        (IocType.DOMAIN, "nas.home.arpa"),
        (IocType.DOMAIN, "wiki.internal"),
        (IocType.DOMAIN, "printer.local"),
    ],
)
def test_internal_and_reserved_indicators_stay_local(ioc_type: IocType, value: str) -> None:
    assert not shareable(ioc_type, value)


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IocType.DOMAIN, "cdn.loader-c2-sample.net"),
        (IocType.SHA256, MIMIKATZ_SHA256),
        (IocType.MD5, "9e107d9d372bb6826bd81d3542a419d6"),
    ],
)
def test_public_domains_and_hashes_may_be_shared(ioc_type: IocType, value: str) -> None:
    assert shareable(ioc_type, value)


def test_worst_verdict() -> None:
    assert worst([]) is Verdict.UNKNOWN
    assert worst([Verdict.CLEAN, Verdict.UNKNOWN]) is Verdict.CLEAN
    assert worst([Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.CLEAN]) is Verdict.MALICIOUS


# --------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------


async def test_abuseipdb_check_request_and_summary() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": "203.0.113.45",
                    "abuseConfidenceScore": 100,
                    "countryCode": "NL",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example Hosting B.V.",
                    "domain": "example.net",
                    "isTor": False,
                    "isWhitelisted": None,
                    "totalReports": 312,
                    "numDistinctUsers": 87,
                    "lastReportedAt": "2026-10-11T22:14:03+00:00",
                }
            },
        )

    provider = abuseipdb()
    async with client(handler) as http:
        result = await provider.lookup(http, IocType.IP, "203.0.113.45")

    [request] = seen
    assert request.url.host == "api.abuseipdb.com"
    assert request.url.params["ipAddress"] == "203.0.113.45"
    assert request.url.params["maxAgeInDays"] == "90"
    assert request.headers["Key"] == ABUSE_KEY
    assert ABUSE_KEY not in str(request.url)
    assert result.status is EnrichmentStatus.OK
    assert result.data["score"] == 100
    assert result.data["reports"] == 312
    assert result.data["reporters"] == 87
    assert result.data["country"] == "NL"
    assert result.data["is_whitelisted"] is False
    assert result.data["link"] == "https://www.abuseipdb.com/check/203.0.113.45"
    assert provider.verdict(result.data) is Verdict.MALICIOUS


@pytest.mark.parametrize(
    ("data", "verdict"),
    [
        ({"score": 90}, Verdict.MALICIOUS),
        ({"score": 75}, Verdict.MALICIOUS),
        ({"score": 40}, Verdict.SUSPICIOUS),
        ({"score": 3}, Verdict.CLEAN),
        ({"score": 90, "is_whitelisted": True}, Verdict.CLEAN),
        ({"score": None}, Verdict.UNKNOWN),
    ],
)
def test_abuseipdb_verdicts(data: dict[str, object], verdict: Verdict) -> None:
    assert abuseipdb().verdict(data) is verdict


def test_abuseipdb_only_handles_addresses() -> None:
    provider = abuseipdb()
    assert provider.supports(IocType.IP)
    assert not provider.supports(IocType.DOMAIN)
    assert not provider.supports(IocType.SHA256)


async def test_abuseipdb_reply_without_data_is_an_error() -> None:
    async with client(answer(200, json={"errors": []})) as http:
        with pytest.raises(ProviderError, match="no data"):
            await abuseipdb().lookup(http, IocType.IP, "203.0.113.45")


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------


def vt_reply(malicious: int, **attributes: object) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == VT_KEY
        stats = {"malicious": malicious, "suspicious": 1, "harmless": 0, "undetected": 60}
        body = {
            "data": {
                "attributes": {
                    "last_analysis_stats": stats,
                    "reputation": -40,
                    "last_analysis_date": 1_791_763_200,
                    **attributes,
                }
            }
        }
        return httpx.Response(200, json=body)

    return handler


async def test_virustotal_file_report() -> None:
    provider = virustotal()
    handler = vt_reply(52, meaningful_name="m.exe", type_description="Win32 EXE")
    async with client(handler) as http:
        result = await provider.lookup(http, IocType.SHA256, MIMIKATZ_SHA256)

    assert result.status is EnrichmentStatus.OK
    assert result.data["malicious"] == 52
    assert result.data["suspicious"] == 1
    assert result.data["reputation"] == -40
    assert result.data["last_analysis_at"] == "2026-10-12T00:00:00+00:00"
    assert result.data["name"] == "m.exe"
    assert result.data["file_type"] == "Win32 EXE"
    assert result.data["link"] == f"https://www.virustotal.com/gui/file/{MIMIKATZ_SHA256}"
    assert provider.verdict(result.data) is Verdict.MALICIOUS


@pytest.mark.parametrize(
    ("ioc_type", "value", "path", "extra"),
    [
        (IocType.IP, "203.0.113.45", "/api/v3/ip_addresses/203.0.113.45", "as_owner"),
        (
            IocType.DOMAIN,
            "update-check.example.net",
            "/api/v3/domains/update-check.example.net",
            "registrar",
        ),
    ],
)
async def test_virustotal_address_and_domain_reports(
    ioc_type: IocType, value: str, path: str, extra: str
) -> None:
    seen: list[str] = []
    reply = vt_reply(0, country="NL", as_owner="Example Hosting", registrar="Example Registrar")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return reply(request)

    async with client(handler) as http:
        result = await virustotal().lookup(http, ioc_type, value)

    assert seen == [path]
    assert result.data[extra]
    assert VirusTotal.name in result.data["link"]


@pytest.mark.parametrize(
    ("data", "verdict"),
    [
        ({"malicious": 3, "suspicious": 0}, Verdict.MALICIOUS),
        ({"malicious": 1, "suspicious": 0}, Verdict.SUSPICIOUS),
        ({"malicious": 0, "suspicious": 2}, Verdict.SUSPICIOUS),
        ({"malicious": 0, "suspicious": 0}, Verdict.CLEAN),
        ({}, Verdict.UNKNOWN),
    ],
)
def test_virustotal_verdicts(data: dict[str, object], verdict: Verdict) -> None:
    assert virustotal().verdict(data) is verdict


async def test_virustotal_reply_without_attributes_is_an_error() -> None:
    async with client(answer(200, json={"data": {"id": "x"}})) as http:
        with pytest.raises(ProviderError, match="no attributes"):
            await virustotal().lookup(http, IocType.SHA256, MIMIKATZ_SHA256)


def test_virustotal_handles_every_indicator_type() -> None:
    assert all(virustotal().supports(ioc_type) for ioc_type in IocType)


# --------------------------------------------------------------------------
# Failures shared by both clients
# --------------------------------------------------------------------------


async def test_unknown_indicator_is_not_found() -> None:
    async with client(answer(404, json={"error": {"code": "NotFoundError"}})) as http:
        result = await virustotal().lookup(http, IocType.SHA256, MIMIKATZ_SHA256)
    assert result.status is EnrichmentStatus.NOT_FOUND
    assert result.data == {}


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Retry-After": "120"}, 120.0),
        ({}, DEFAULT_COOLDOWN_SECONDS),
        ({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, DEFAULT_COOLDOWN_SECONDS),
        ({"Retry-After": "999999"}, float(DAY)),
    ],
)
async def test_rate_limit_reply_carries_the_retry_delay(
    headers: dict[str, str], expected: float
) -> None:
    async with client(answer(429, headers=headers)) as http:
        with pytest.raises(RateLimitedError) as caught:
            await abuseipdb().lookup(http, IocType.IP, "203.0.113.45")
    assert caught.value.retry_after == expected


@pytest.mark.parametrize("status", [401, 403])
async def test_rejected_key_is_reported_without_the_key(status: int) -> None:
    async with client(answer(status)) as http:
        with pytest.raises(ProviderError, match="rejected the API key") as caught:
            await virustotal().lookup(http, IocType.SHA256, MIMIKATZ_SHA256)
    assert VT_KEY not in str(caught.value)


@pytest.mark.parametrize(
    ("handler", "message"),
    [
        (answer(503), "HTTP 503"),
        (answer(200, content=b"<html>maintenance</html>"), "not JSON"),
        (answer(200, json=["unexpected"]), "unexpected reply"),
    ],
)
async def test_bad_replies_raise_provider_errors(handler: Handler, message: str) -> None:
    async with client(handler) as http:
        with pytest.raises(ProviderError, match=message):
            await abuseipdb().lookup(http, IocType.IP, "203.0.113.45")


async def test_network_failure_names_the_error_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out connecting", request=request)

    async with client(handler) as http:
        with pytest.raises(ProviderError, match=r"VirusTotal request failed \(ConnectTimeout\)"):
            await virustotal().lookup(http, IocType.SHA256, MIMIKATZ_SHA256)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_no_keys_means_no_providers(settings: Settings) -> None:
    assert configured_providers(settings) == []


def test_providers_follow_configured_keys_and_limits(settings: Settings) -> None:
    configured = settings.model_copy(
        update={
            "abuseipdb_api_key": SecretStr("a-key"),
            "virustotal_api_key": SecretStr("v-key"),
            "abuseipdb_daily_limit": 3000,
            "virustotal_per_minute": 2,
        }
    )

    abuse, vt = configured_providers(configured)

    assert isinstance(abuse, AbuseIPDB)
    assert abuse.limits == (Limit(3000, DAY),)
    assert isinstance(vt, VirusTotal)
    assert vt.limits == (Limit(2, MINUTE), Limit(500, DAY))
    only_vt = settings.model_copy(update={"virustotal_api_key": SecretStr("v-key")})
    assert [provider.name for provider in configured_providers(only_vt)] == ["virustotal"]
