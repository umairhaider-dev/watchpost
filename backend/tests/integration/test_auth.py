from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import FakeAsyncRedis, FakeServer
from fastapi import FastAPI
from httpx import AsyncClient, Response
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_alert
from tests.integration.conftest import TEST_PASSWORD, add_user
from watchpost.api.deps import get_login_throttle
from watchpost.auth.throttle import LoginThrottle
from watchpost.auth.tokens import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, issue_session
from watchpost.core.config import Settings
from watchpost.db.models import AuditLog, User, UserRole

NEW_PASSWORD = "a-much-longer-passphrase"


async def sign_in(client: AsyncClient, username: str, password: str = TEST_PASSWORD) -> Response:
    return await client.post("/api/auth/login", json={"username": username, "password": password})


def csrf(client: AsyncClient) -> dict[str, str]:
    return {CSRF_HEADER: client.cookies[CSRF_COOKIE]}


async def audit_actions(session: AsyncSession) -> list[tuple[str, str | None]]:
    session.expire_all()
    rows = await session.execute(select(AuditLog.action, AuditLog.username).order_by(AuditLog.id))
    return [(action, username) for action, username in rows]


# --------------------------------------------------------------------------
# Signing in
# --------------------------------------------------------------------------


async def test_sign_in_sets_secure_cookies_and_is_audited(
    anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)

    response = await sign_in(anonymous_client, "Analyst.One")

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "analyst.one"
    assert body["user"]["role"] == "analyst"
    cookies = {
        header.split("=", 1)[0]: header for header in response.headers.get_list("set-cookie")
    }
    session_cookie = cookies[SESSION_COOKIE].lower()
    assert "httponly" in session_cookie
    assert "samesite=strict" in session_cookie
    assert "path=/api" in session_cookie
    assert "httponly" not in cookies[CSRF_COOKIE].lower()

    me = await anonymous_client.get("/api/auth/me")
    assert me.json()["username"] == "analyst.one"
    entry = await db_session.scalar(select(AuditLog).where(AuditLog.action == "auth.login"))
    assert entry is not None
    assert entry.username == "analyst.one"
    assert entry.ip_address == "127.0.0.1"
    user = await db_session.scalar(select(User).where(User.username == "analyst.one"))
    assert user is not None and user.last_login_at is not None


@pytest.mark.parametrize(
    ("username", "password"),
    [("analyst.one", "wrong-password-here"), ("nobody.here", TEST_PASSWORD)],
)
async def test_wrong_credentials_get_the_same_answer(
    anonymous_client: AsyncClient, db_session: AsyncSession, username: str, password: str
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)

    response = await sign_in(anonymous_client, username, password)

    assert response.status_code == 401
    assert response.json()["detail"] == "wrong user name or password"
    assert SESSION_COOKIE not in anonymous_client.cookies
    assert await audit_actions(db_session) == [("auth.login_failed", username)]


async def test_inactive_users_cannot_sign_in(
    anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    user = await add_user(db_session, "retired.analyst", UserRole.ANALYST)
    user.is_active = False
    await db_session.flush()

    assert (await sign_in(anonymous_client, "retired.analyst")).status_code == 401


async def test_repeated_failures_are_throttled(
    anonymous_client: AsyncClient, db_session: AsyncSession, app_settings: Settings
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    for _ in range(app_settings.login_max_failures):
        assert (
            await sign_in(anonymous_client, "analyst.one", "guess-guess-guess")
        ).status_code == 401

    blocked = await sign_in(anonymous_client, "analyst.one")  # even the right password

    assert blocked.status_code == 429
    assert 0 < int(blocked.headers["retry-after"]) <= app_settings.login_window_minutes * 60
    assert (await audit_actions(db_session))[-1] == ("auth.login_blocked", "analyst.one")


async def test_success_resets_the_user_count_but_not_the_address_count(
    anonymous_client: AsyncClient, db_session: AsyncSession, app_settings: Settings
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    await add_user(db_session, "analyst.two", UserRole.ANALYST)
    for _ in range(app_settings.login_max_failures - 1):
        await sign_in(anonymous_client, "analyst.one", "guess-guess-guess")
    assert (await sign_in(anonymous_client, "analyst.one")).status_code == 200

    # The address keeps its count, so a known-good account cannot be used to
    # reset it while guessing other accounts' passwords.
    await sign_in(anonymous_client, "analyst.two", "guess-guess-guess")
    assert (await sign_in(anonymous_client, "analyst.two")).status_code == 429


async def test_redis_outage_does_not_block_sign_in(
    anonymous_app: FastAPI, anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    server = FakeServer()
    server.connected = False
    broken = FakeAsyncRedis(server=server)
    anonymous_app.dependency_overrides[get_login_throttle] = lambda: LoginThrottle(broken, 5, 900)

    assert (await sign_in(anonymous_client, "analyst.one")).status_code == 200
    await broken.aclose()


async def test_bearer_tokens_for_scripts(
    anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    [alert] = [make_alert()]
    db_session.add(alert)
    await db_session.flush()

    token = await anonymous_client.post(
        "/api/auth/token", data={"username": "analyst.one", "password": TEST_PASSWORD}
    )
    assert token.status_code == 200
    body = token.json()
    assert body["token_type"] == "bearer"
    headers = {"Authorization": f"Bearer {body['access_token']}"}

    # No cookie, so no CSRF token is needed.
    triaged = await anonymous_client.patch(
        f"/api/alerts/{alert.id}", json={"status": "investigating"}, headers=headers
    )
    assert triaged.status_code == 200
    bad = await anonymous_client.post(
        "/api/auth/token", data={"username": "analyst.one", "password": "wrong-password-here"}
    )
    assert bad.status_code == 401


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


async def test_protected_routes_need_a_session(anonymous_client: AsyncClient) -> None:
    for path in ("/api/alerts", "/api/dashboard", "/api/users", "/api/auth/me", "/api/meta/fields"):
        response = await anonymous_client.get(path)
        assert response.status_code == 401, path
        assert response.headers["www-authenticate"] == "Bearer"
    assert (await anonymous_client.get("/api/health")).status_code == 200


async def test_cookie_sessions_need_the_csrf_token_to_change_data(
    anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    alert = make_alert()
    db_session.add(alert)
    await db_session.flush()
    await sign_in(anonymous_client, "analyst.one")
    url = f"/api/alerts/{alert.id}"

    missing = await anonymous_client.patch(url, json={"status": "investigating"})
    wrong = await anonymous_client.patch(
        url, json={"status": "investigating"}, headers={CSRF_HEADER: "nope"}
    )
    right = await anonymous_client.patch(
        url, json={"status": "investigating"}, headers=csrf(anonymous_client)
    )

    assert (missing.status_code, wrong.status_code, right.status_code) == (403, 403, 200)
    assert missing.json()["detail"] == "missing or invalid CSRF token"
    # Reads need no token.
    assert (await anonymous_client.get(url)).status_code == 200
    entry = await db_session.scalar(
        select(AuditLog).where(AuditLog.action == "alert.status_changed")
    )
    assert entry is not None and entry.username == "analyst.one"


@pytest.mark.parametrize("problem", ["expired", "forged", "garbage"])
async def test_unusable_sessions_are_rejected(
    anonymous_client: AsyncClient,
    db_session: AsyncSession,
    app_settings: Settings,
    problem: str,
) -> None:
    user = await add_user(db_session, "analyst.one", UserRole.ANALYST)
    if problem == "expired":
        token = issue_session(user, app_settings, now=datetime.now(UTC) - timedelta(days=30)).token
    elif problem == "forged":
        elsewhere = Settings(
            _env_file=None, secret_key=SecretStr("another-secret-that-is-at-least-32-chars")
        )
        token = issue_session(user, elsewhere).token
    else:
        token = "garbage"
    anonymous_client.cookies.set(SESSION_COOKIE, token, path="/api")

    assert (await anonymous_client.get("/api/auth/me")).status_code == 401


async def test_sign_out_and_sign_out_everywhere(
    anonymous_client: AsyncClient, db_session: AsyncSession, app_settings: Settings
) -> None:
    user = await add_user(db_session, "analyst.one", UserRole.ANALYST)
    other_device = issue_session(user, app_settings).token
    await sign_in(anonymous_client, "analyst.one")

    out = await anonymous_client.post(
        "/api/auth/logout", params={"everywhere": True}, headers=csrf(anonymous_client)
    )

    assert out.status_code == 204
    assert SESSION_COOKIE not in anonymous_client.cookies
    assert (await anonymous_client.get("/api/auth/me")).status_code == 401
    bearer = {"Authorization": f"Bearer {other_device}"}
    assert (await anonymous_client.get("/api/auth/me", headers=bearer)).status_code == 401
    # Signing out without a session just clears the cookies.
    assert (await anonymous_client.post("/api/auth/logout")).status_code == 204
    assert ("auth.logout", "analyst.one") in await audit_actions(db_session)


async def test_change_own_password(
    anonymous_client: AsyncClient, db_session: AsyncSession, app_settings: Settings
) -> None:
    user = await add_user(db_session, "analyst.one", UserRole.ANALYST)
    other_device = issue_session(user, app_settings).token
    await sign_in(anonymous_client, "analyst.one")
    url = "/api/auth/password"

    wrong = await anonymous_client.post(
        url,
        json={"current_password": "not-my-password", "new_password": NEW_PASSWORD},
        headers=csrf(anonymous_client),
    )
    weak = await anonymous_client.post(
        url,
        json={"current_password": TEST_PASSWORD, "new_password": "short"},
        headers=csrf(anonymous_client),
    )
    changed = await anonymous_client.post(
        url,
        json={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf(anonymous_client),
    )

    assert (wrong.status_code, weak.status_code, changed.status_code) == (400, 400, 200)
    # This browser got a fresh session; the other device was signed out.
    assert (await anonymous_client.get("/api/auth/me")).status_code == 200
    bearer = {"Authorization": f"Bearer {other_device}"}
    assert (await anonymous_client.get("/api/auth/me", headers=bearer)).status_code == 401
    anonymous_client.cookies.clear()
    assert (await sign_in(anonymous_client, "analyst.one")).status_code == 401
    assert (await sign_in(anonymous_client, "analyst.one", NEW_PASSWORD)).status_code == 200


# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------


async def test_viewers_only_read(anonymous_client: AsyncClient, db_session: AsyncSession) -> None:
    await add_user(db_session, "viewer.one", UserRole.VIEWER)
    alert = make_alert()
    db_session.add(alert)
    await db_session.flush()
    await sign_in(anonymous_client, "viewer.one")

    assert (await anonymous_client.get("/api/alerts")).status_code == 200
    denied = await anonymous_client.patch(
        f"/api/alerts/{alert.id}", json={"status": "closed"}, headers=csrf(anonymous_client)
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "viewers have read-only access"
    # Viewers can still change their own password and sign out.
    signed_out = await anonymous_client.post("/api/auth/logout", headers=csrf(anonymous_client))
    assert signed_out.status_code == 204


@pytest.mark.usefixtures("rules")
async def test_analysts_cannot_edit_rules_or_manage_users(
    anonymous_client: AsyncClient, db_session: AsyncSession
) -> None:
    await add_user(db_session, "analyst.one", UserRole.ANALYST)
    await sign_in(anonymous_client, "analyst.one")
    headers = csrf(anonymous_client)

    toggle = await anonymous_client.patch(
        "/api/rules/ssh-brute-force", json={"enabled": False}, headers=headers
    )
    create = await anonymous_client.post(
        "/api/users",
        json={"username": "new.analyst", "password": NEW_PASSWORD},
        headers=headers,
    )
    audit = await anonymous_client.get("/api/audit")
    test = await anonymous_client.post(
        "/api/rules/validate", json={"source_yaml": "id: x"}, headers=headers
    )

    assert (toggle.status_code, create.status_code, audit.status_code) == (403, 403, 403)
    assert toggle.json()["detail"] == "only admins can do this"
    assert test.status_code == 200  # analysts may still validate and test rules
