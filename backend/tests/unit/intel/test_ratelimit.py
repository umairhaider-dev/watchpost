from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fakeredis import FakeAsyncRedis

from watchpost.intel.ratelimit import Limit, RateLimiter

PER_MINUTE = Limit(2, 60)
PER_DAY = Limit(5, 86_400)


class Clock:
    def __init__(self) -> None:
        # Start just after a day boundary so minute and day windows both begin here.
        self.now = 1_791_763_200.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.aclose()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def limiter(redis: FakeAsyncRedis, clock: Clock) -> RateLimiter:
    return RateLimiter(redis, clock)


async def test_requests_are_allowed_until_the_window_is_full(
    limiter: RateLimiter, clock: Clock
) -> None:
    assert await limiter.acquire("virustotal", (PER_MINUTE,))
    assert await limiter.acquire("virustotal", (PER_MINUTE,))
    assert not await limiter.acquire("virustotal", (PER_MINUTE,))

    clock.now += 60
    assert await limiter.acquire("virustotal", (PER_MINUTE,))


async def test_a_refused_request_takes_nothing_from_the_other_windows(
    limiter: RateLimiter,
) -> None:
    limits = (PER_DAY, PER_MINUTE)
    for _ in range(4):
        await limiter.acquire("virustotal", limits)

    # 2 used per minute, so two of the four attempts were refused and given back.
    assert await limiter.remaining("virustotal", limits) == {"5/day": 3, "2/min": 0}


async def test_providers_have_separate_budgets(limiter: RateLimiter) -> None:
    one = Limit(1, 60)
    assert await limiter.acquire("abuseipdb", (one,))
    assert await limiter.acquire("virustotal", (one,))
    assert not await limiter.acquire("abuseipdb", (one,))


async def test_window_counters_expire_with_their_window(
    limiter: RateLimiter, redis: FakeAsyncRedis
) -> None:
    await limiter.acquire("virustotal", (PER_MINUTE,))

    [key] = await redis.keys("watchpost:ratelimit:virustotal:*")
    assert 0 < await redis.ttl(key) <= 60


async def test_cooldown_blocks_a_provider_until_it_expires(
    limiter: RateLimiter, redis: FakeAsyncRedis
) -> None:
    await limiter.cooldown("abuseipdb", 120)

    assert await limiter.cooling_down("abuseipdb")
    assert not await limiter.acquire("abuseipdb", (PER_DAY,))
    assert await limiter.remaining("abuseipdb", (PER_DAY,)) == {"5/day": 5}
    assert 0 < await redis.ttl("watchpost:ratelimit:abuseipdb:cooldown") <= 120

    await redis.delete("watchpost:ratelimit:abuseipdb:cooldown")
    assert await limiter.acquire("abuseipdb", (PER_DAY,))


async def test_cooldown_lasts_at_least_a_second(
    limiter: RateLimiter, redis: FakeAsyncRedis
) -> None:
    await limiter.cooldown("virustotal", 0.2)

    assert await redis.ttl("watchpost:ratelimit:virustotal:cooldown") == 1


@pytest.mark.parametrize(
    ("limit", "label"),
    [
        (Limit(4, 60), "4/min"),
        (Limit(100, 3_600), "100/hour"),
        (Limit(1000, 86_400), "1000/day"),
        (Limit(3, 120), "3/120s"),
    ],
)
def test_limit_labels(limit: Limit, label: str) -> None:
    assert limit.label == label
