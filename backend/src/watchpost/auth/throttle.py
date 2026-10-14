"""Slowing down password guessing.

Failed sign-ins are counted in Redis per user name and per client address,
each in a window that starts with the first failure. Once either count
reaches the limit, further attempts are refused until the window ends, even
with the right password. A successful sign-in clears that user's count.

If Redis is unreachable the throttle lets attempts through and logs a
warning: refusing every sign-in during an outage would lock analysts out,
and Argon2 hashing still makes each guess slow.
"""

from __future__ import annotations

import logging

from redis.asyncio import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

_PREFIX = "watchpost:login-failures"


class LoginThrottle:
    def __init__(self, redis: Redis, max_failures: int, window_seconds: int) -> None:
        self._redis = redis
        self._max = max_failures
        self._window = window_seconds

    def _keys(self, username: str, address: str | None) -> list[str]:
        keys = [f"{_PREFIX}:user:{username.strip().lower()}"]
        if address:
            keys.append(f"{_PREFIX}:ip:{address}")
        return keys

    async def retry_after(self, username: str, address: str | None) -> int | None:
        """Seconds until another attempt is allowed, or ``None`` if one is allowed now."""
        try:
            for key in self._keys(username, address):
                failures = int(await self._redis.get(key) or 0)
                if failures >= self._max:
                    ttl = int(await self._redis.ttl(key))
                    return max(ttl, 1)
        except RedisError:
            logger.warning("Login throttle unavailable; allowing the attempt")
        return None

    async def failed(self, username: str, address: str | None) -> None:
        try:
            for key in self._keys(username, address):
                if int(await self._redis.incr(key)) == 1:
                    await self._redis.expire(key, self._window)
        except RedisError:
            logger.warning("Login throttle unavailable; failure not counted")

    async def succeeded(self, username: str) -> None:
        try:
            await self._redis.delete(self._keys(username, None)[0])
        except RedisError:
            logger.warning("Login throttle unavailable; could not reset the failure count")
