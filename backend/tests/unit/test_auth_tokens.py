from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fakeredis import FakeAsyncRedis, FakeServer

from watchpost.auth.throttle import LoginThrottle
from watchpost.auth.tokens import ALGORITHM, InvalidSessionError, issue_session, read_session
from watchpost.core.config import Settings
from watchpost.db.models import User, UserRole


def make_user(version: int = 0) -> User:
    return User(id=7, username="analyst.one", role=UserRole.ANALYST, session_version=version)


def key(settings: Settings) -> str:
    assert settings.secret_key is not None
    return settings.secret_key.get_secret_value()


# --------------------------------------------------------------------------
# Session tokens
# --------------------------------------------------------------------------


def test_issued_sessions_round_trip(settings: Settings) -> None:
    now = datetime.now(UTC)
    session = issue_session(make_user(version=3), settings, now=now)

    claims = read_session(session.token, settings)

    assert claims.user_id == 7
    assert claims.session_version == 3
    assert claims.csrf == session.csrf
    assert len(session.csrf) >= 40
    assert claims.expires_at == session.expires_at.replace(microsecond=0)
    assert session.expires_at - now == timedelta(hours=settings.session_hours)


def test_each_session_has_its_own_csrf_secret(settings: Settings) -> None:
    first = issue_session(make_user(), settings)
    second = issue_session(make_user(), settings)

    assert first.csrf != second.csrf
    assert first.token != second.token


def test_expired_sessions_are_rejected(settings: Settings) -> None:
    long_ago = datetime.now(UTC) - timedelta(hours=settings.session_hours + 1)
    expired = issue_session(make_user(), settings, now=long_ago)

    with pytest.raises(InvalidSessionError):
        read_session(expired.token, settings)


def forged(settings: Settings, **overrides: object) -> str:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": "watchpost",
        "sub": "7",
        "sv": 0,
        "csrf": "x",
        "iat": now,
        "exp": now + timedelta(hours=1),
    }
    payload.update(overrides)
    payload = {name: value for name, value in payload.items() if value is not None}
    return jwt.encode(payload, key(settings), algorithm=ALGORITHM)


@pytest.mark.parametrize(
    "token_for",
    [
        lambda s: forged(s, iss="someone-else"),
        lambda s: forged(s, sub=None),
        lambda s: forged(s, exp=None),
        lambda s: forged(s, sv=None),
        lambda s: forged(s, sub="not-a-number"),
        lambda s: jwt.encode(
            {"sub": "7"}, "a-different-secret-key-of-enough-length!", algorithm=ALGORITHM
        ),
        lambda s: jwt.encode({"iss": "watchpost", "sub": "7"}, None, algorithm="none"),
        lambda s: "not.a.token",
        lambda s: "",
    ],
)
def test_forged_and_malformed_tokens_are_rejected(
    settings: Settings, token_for: Callable[[Settings], str]
) -> None:
    with pytest.raises(InvalidSessionError):
        read_session(token_for(settings), settings)


def test_tampered_payload_breaks_the_signature(settings: Settings) -> None:
    token = issue_session(make_user(), settings).token
    header, payload, signature = token.split(".")
    tampered = f"{header}.{payload[:-2]}AA.{signature}"

    with pytest.raises(InvalidSessionError):
        read_session(tampered, settings)


def test_roles_are_ordered() -> None:
    assert UserRole.ADMIN.allows(UserRole.ANALYST)
    assert UserRole.ANALYST.allows(UserRole.ANALYST)
    assert UserRole.ANALYST.allows(UserRole.VIEWER)
    assert not UserRole.VIEWER.allows(UserRole.ANALYST)
    assert not UserRole.ANALYST.allows(UserRole.ADMIN)


# --------------------------------------------------------------------------
# Login throttle
# --------------------------------------------------------------------------


@pytest.fixture
async def redis() -> AsyncIterator[FakeAsyncRedis]:
    client = FakeAsyncRedis()
    yield client
    await client.aclose()


async def test_throttle_blocks_after_the_limit_and_resets_on_success(
    redis: FakeAsyncRedis,
) -> None:
    throttle = LoginThrottle(redis, max_failures=3, window_seconds=900)

    for _ in range(2):
        await throttle.failed("Analyst.One", "192.168.1.31")
    assert await throttle.retry_after("analyst.one", "192.168.1.31") is None

    await throttle.succeeded("analyst.one")
    for _ in range(3):
        await throttle.failed("analyst.one", "192.168.1.31")
    wait = await throttle.retry_after("analyst.one", "192.168.1.31")
    assert wait is not None and 0 < wait <= 900


async def test_throttle_counts_per_address_across_user_names(redis: FakeAsyncRedis) -> None:
    throttle = LoginThrottle(redis, max_failures=3, window_seconds=900)

    for name in ("root", "admin", "oracle"):
        await throttle.failed(name, "10.20.0.99")

    assert await throttle.retry_after("someone-new", "10.20.0.99") is not None
    assert await throttle.retry_after("someone-new", "10.20.0.50") is None


async def test_throttle_lets_attempts_through_when_redis_is_down(
    caplog: pytest.LogCaptureFixture,
) -> None:
    server = FakeServer()
    server.connected = False
    redis = FakeAsyncRedis(server=server)
    throttle = LoginThrottle(redis, max_failures=1, window_seconds=900)

    await throttle.failed("analyst.one", None)
    assert await throttle.retry_after("analyst.one", None) is None
    await throttle.succeeded("analyst.one")

    assert "Login throttle unavailable" in caplog.text
    await redis.aclose()
