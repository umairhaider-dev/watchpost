"""Looking indicators up with external providers, through a shared cache.

:class:`Enricher` answers "what do the configured providers say about this
indicator?". Answers are cached in ``enrichment_cache`` (errors only
briefly), so repeated alerts about the same address cost one request per
provider per cache period. A request that would exceed a provider's rate
limit is not made: it comes back as ``rate_limited`` and is retried later.
No database transaction is held open while a provider is being called.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import httpx
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from watchpost.core.config import Settings
from watchpost.db.models import EnrichmentCache, EnrichmentStatus, IocType
from watchpost.intel.providers import (
    PROVIDER_LABELS,
    Answer,
    Provider,
    ProviderError,
    RateLimitedError,
    Verdict,
    configured_providers,
    shareable,
)
from watchpost.intel.ratelimit import RateLimiter

logger = logging.getLogger(__name__)

ERROR_CACHE_TTL = timedelta(minutes=15)


class LookupStatus(StrEnum):
    """Outcome of asking one provider about one indicator."""

    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"  # not asked yet; try again later


@dataclass(frozen=True, slots=True)
class ProviderResult:
    provider: str
    status: LookupStatus
    verdict: Verdict = Verdict.UNKNOWN
    data: dict[str, Any] = field(default_factory=dict)
    fetched_at: datetime | None = None
    cached: bool = False

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form, as stored on alerts and returned by the API."""
        return {
            "provider": self.provider,
            "label": PROVIDER_LABELS.get(self.provider, self.provider),
            "status": self.status.value,
            "verdict": self.verdict.value,
            "data": self.data,
            "fetched_at": self.fetched_at.isoformat() if self.fetched_at else None,
            "cached": self.cached,
        }


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    name: str
    label: str
    configured: bool
    cooling_down: bool = False
    remaining: dict[str, int] = field(default_factory=dict)


class Enricher:
    """Cached, rate-limited indicator lookups against the configured providers."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        providers: Sequence[Provider],
        limiter: RateLimiter,
        client: httpx.AsyncClient,
        cache_ttl: timedelta = timedelta(hours=24),
    ) -> None:
        self._session_factory = session_factory
        self._providers = {provider.name: provider for provider in providers}
        self._limiter = limiter
        self._client = client
        self._cache_ttl = cache_ttl

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    @property
    def online(self) -> bool:
        """Whether any external provider is configured."""
        return bool(self._providers)

    async def lookup(
        self, ioc_type: IocType, value: str, *, refresh: bool = False
    ) -> list[ProviderResult]:
        """Every applicable provider's answer; ``[]`` if the indicator must stay local."""
        providers = [p for p in self._providers.values() if p.supports(ioc_type)]
        if not providers or not shareable(ioc_type, value):
            return []
        cached = {} if refresh else await self._cached(ioc_type, value, providers)
        results = []
        for provider in providers:
            hit = cached.get(provider.name)
            results.append(hit if hit is not None else await self._fetch(provider, ioc_type, value))
        return results

    async def _cached(
        self, ioc_type: IocType, value: str, providers: Sequence[Provider]
    ) -> dict[str, ProviderResult]:
        async with self._session_factory() as session:
            rows = await session.scalars(
                select(EnrichmentCache).where(
                    EnrichmentCache.provider.in_([provider.name for provider in providers]),
                    EnrichmentCache.indicator_type == ioc_type,
                    EnrichmentCache.indicator == value,
                    EnrichmentCache.expires_at > datetime.now(UTC),
                )
            )
            return {
                row.provider: self._result(
                    self._providers[row.provider],
                    Answer(row.status, row.data),
                    row.fetched_at,
                    cached=True,
                )
                for row in rows
            }

    @staticmethod
    def _result(
        provider: Provider, answer: Answer, fetched_at: datetime, *, cached: bool
    ) -> ProviderResult:
        verdict = (
            provider.verdict(answer.data)
            if answer.status is EnrichmentStatus.OK
            else Verdict.UNKNOWN
        )
        return ProviderResult(
            provider=provider.name,
            status=LookupStatus(answer.status.value),
            verdict=verdict,
            data=answer.data,
            fetched_at=fetched_at,
            cached=cached,
        )

    async def _fetch(self, provider: Provider, ioc_type: IocType, value: str) -> ProviderResult:
        postponed = ProviderResult(provider.name, LookupStatus.RATE_LIMITED)
        try:
            if not await self._limiter.acquire(provider.name, provider.limits):
                logger.info("%s lookup of %s postponed by the rate limit", provider.label, value)
                return postponed
        except RedisError:
            logger.warning("Rate limit store unavailable; postponing %s lookup", provider.label)
            return postponed

        try:
            answer = await provider.lookup(self._client, ioc_type, value)
        except RateLimitedError as exc:
            logger.warning(
                "%s is rate limiting; pausing lookups for %.0f s", provider.label, exc.retry_after
            )
            try:
                await self._limiter.cooldown(provider.name, exc.retry_after)
            except RedisError:
                logger.warning("Could not record the %s cooldown in Redis", provider.label)
            return postponed
        except ProviderError as exc:
            logger.warning("%s lookup of %s %s failed: %s", provider.label, ioc_type, value, exc)
            answer = Answer(EnrichmentStatus.ERROR, {"error": str(exc)})

        fetched_at = datetime.now(UTC)
        ttl = self._cache_ttl
        if answer.status is EnrichmentStatus.ERROR:
            ttl = min(ttl, ERROR_CACHE_TTL)
        await self._store(provider.name, ioc_type, value, answer, fetched_at, fetched_at + ttl)
        return self._result(provider, answer, fetched_at, cached=False)

    async def _store(
        self,
        provider: str,
        ioc_type: IocType,
        value: str,
        answer: Answer,
        fetched_at: datetime,
        expires_at: datetime,
    ) -> None:
        insert = pg_insert(EnrichmentCache).values(
            provider=provider,
            indicator_type=ioc_type,
            indicator=value,
            status=answer.status,
            data=answer.data,
            fetched_at=fetched_at,
            expires_at=expires_at,
        )
        async with self._session_factory() as session:
            await session.execute(
                insert.on_conflict_do_update(
                    index_elements=[
                        EnrichmentCache.provider,
                        EnrichmentCache.indicator_type,
                        EnrichmentCache.indicator,
                    ],
                    set_={
                        "status": insert.excluded.status,
                        "data": insert.excluded.data,
                        "fetched_at": insert.excluded.fetched_at,
                        "expires_at": insert.excluded.expires_at,
                    },
                )
            )
            await session.commit()

    async def status(self) -> list[ProviderStatus]:
        """Every known provider, whether it is configured, and its remaining budget."""
        statuses = []
        for name, label in PROVIDER_LABELS.items():
            provider = self._providers.get(name)
            if provider is None:
                statuses.append(ProviderStatus(name, label, configured=False))
                continue
            try:
                cooling = await self._limiter.cooling_down(name)
                remaining = await self._limiter.remaining(name, provider.limits)
            except RedisError:
                logger.warning("Rate limit store unavailable; %s budget unknown", label)
                cooling, remaining = False, {}
            statuses.append(ProviderStatus(name, label, True, cooling, remaining))
        return statuses


def build_enricher(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    redis: Redis,
    client: httpx.AsyncClient,
) -> Enricher:
    """An :class:`Enricher` for the providers configured in ``settings``."""
    providers = configured_providers(settings)
    if providers:
        logger.info(
            "Online enrichment enabled: %s", ", ".join(provider.label for provider in providers)
        )
    return Enricher(
        session_factory,
        providers,
        RateLimiter(redis),
        client,
        cache_ttl=timedelta(hours=settings.enrichment_cache_hours),
    )


def http_client(settings: Settings) -> httpx.AsyncClient:
    """The HTTP client used for provider lookups."""
    return httpx.AsyncClient(
        timeout=settings.enrichment_timeout_seconds,
        headers={"User-Agent": "watchpost-enrichment"},
        follow_redirects=False,
    )
