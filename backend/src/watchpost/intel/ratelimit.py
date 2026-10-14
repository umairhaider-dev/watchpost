"""Shared rate limits for external enrichment providers.

Limits live in Redis so the API and every worker process draw from the same
budget. Each limit is a fixed window (for example 4 requests per minute and
500 per day for VirusTotal's free tier): a request is allowed only if every
window still has room. When a provider answers 429, :meth:`cooldown` blocks
it entirely until its ``Retry-After`` has passed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from redis.asyncio import Redis

_PREFIX = "watchpost:ratelimit"
_WINDOW_NAMES = {60: "min", 3_600: "hour", 86_400: "day"}


@dataclass(frozen=True, slots=True)
class Limit:
    """At most ``requests`` calls per ``window_seconds``."""

    requests: int
    window_seconds: int

    @property
    def label(self) -> str:
        """Short form such as ``4/min`` or ``500/day``."""
        window = _WINDOW_NAMES.get(self.window_seconds, f"{self.window_seconds}s")
        return f"{self.requests}/{window}"


class RateLimiter:
    """Fixed-window request budgets per provider, stored in Redis."""

    def __init__(self, redis: Redis, clock: Callable[[], float] = time.time) -> None:
        self._redis = redis
        self._now = clock

    def _key(self, provider: str, limit: Limit) -> str:
        window = int(self._now()) // limit.window_seconds
        return f"{_PREFIX}:{provider}:{limit.window_seconds}:{window}"

    async def acquire(self, provider: str, limits: tuple[Limit, ...]) -> bool:
        """Take one request from every window; ``False`` (and nothing taken) if any is full."""
        if await self._redis.exists(f"{_PREFIX}:{provider}:cooldown"):
            return False
        taken: list[str] = []
        for limit in limits:
            key = self._key(provider, limit)
            count = int(await self._redis.incr(key))
            if count == 1:
                await self._redis.expire(key, limit.window_seconds)
            taken.append(key)
            if count > limit.requests:
                for used in taken:
                    await self._redis.decr(used)
                return False
        return True

    async def cooldown(self, provider: str, seconds: float) -> None:
        """Pause a provider, e.g. after a 429 with ``Retry-After``."""
        await self._redis.set(f"{_PREFIX}:{provider}:cooldown", "1", ex=max(1, int(seconds)))

    async def remaining(self, provider: str, limits: tuple[Limit, ...]) -> dict[str, int]:
        """Requests left in each current window, keyed by the limit's label."""
        left: dict[str, int] = {}
        for limit in limits:
            used = await self._redis.get(self._key(provider, limit))
            left[limit.label] = max(limit.requests - int(used or 0), 0)
        return left

    async def cooling_down(self, provider: str) -> bool:
        return bool(await self._redis.exists(f"{_PREFIX}:{provider}:cooldown"))
