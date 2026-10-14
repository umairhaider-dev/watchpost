from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.integration.conftest import TEST_PASSWORD, add_user
from watchpost.auth.tokens import issue_session
from watchpost.core.config import Settings
from watchpost.core.passwords import verify_password
from watchpost.db.models import AuditLog, User, UserRole

NEW_PASSWORD = "a-much-longer-passphrase"


async def test_admins_create_users(client: AsyncClient, db_session: AsyncSession) -> None:
    created = await client.post(
        "/api/users",
        json={
            "username": "analyst.two",
            "password": NEW_PASSWORD,
            "role": "analyst",
            "full_name": "Analyst Two",
            "email": "analyst.two@example.org",
        },
    )

    assert created.status_code == 201
    body = created.json()
    assert (body["username"], body["role"], body["is_active"]) == ("analyst.two", "analyst", True)
    assert "password_hash" not in body
    user = await db_session.scalar(select(User).where(User.username == "analyst.two"))
    assert user is not None and verify_password(user.password_hash, NEW_PASSWORD)

    duplicate = await client.post(
        "/api/users", json={"username": "analyst.two", "password": NEW_PASSWORD}
    )
    weak = await client.post("/api/users", json={"username": "analyst.three", "password": "short"})
    bad_name = await client.post(
        "/api/users", json={"username": "Bad Name!", "password": NEW_PASSWORD}
    )
    assert (duplicate.status_code, weak.status_code, bad_name.status_code) == (409, 422, 422)


async def test_role_and_activation_changes(
    client: AsyncClient,
    anonymous_client: AsyncClient,
    db_session: AsyncSession,
    app_settings: Settings,
) -> None:
    user = await add_user(db_session, "analyst.one", UserRole.ANALYST)
    session_token = issue_session(user, app_settings).token
    bearer = {"Authorization": f"Bearer {session_token}"}
    assert (await anonymous_client.get("/api/auth/me", headers=bearer)).status_code == 200
    url = f"/api/users/{user.id}"

    promoted = await client.patch(url, json={"role": "admin", "full_name": "Analyst One"})
    assert (promoted.json()["role"], promoted.json()["full_name"]) == ("admin", "Analyst One")

    deactivated = await client.patch(url, json={"is_active": False})
    assert deactivated.json()["is_active"] is False
    # A deactivated user's sessions stop working at once.
    assert (await anonymous_client.get("/api/auth/me", headers=bearer)).status_code == 401

    entries = list(
        await db_session.scalars(
            select(AuditLog).where(AuditLog.action == "user.updated").order_by(AuditLog.id)
        )
    )
    assert entries[0].details == {
        "role": {"from": "analyst", "to": "admin"},
        "full_name": {"from": None, "to": "Analyst One"},
    }
    assert entries[1].details == {"is_active": {"from": True, "to": False}}
    assert (await client.patch("/api/users/999999", json={"role": "viewer"})).status_code == 404


async def test_admins_cannot_demote_or_deactivate_themselves(
    client: AsyncClient, db_session: AsyncSession, admin: User
) -> None:
    own = f"/api/users/{admin.id}"
    assert (await client.patch(own, json={"role": "analyst"})).status_code == 409
    assert (await client.patch(own, json={"is_active": False})).status_code == 409
    # Changing one's own name is fine.
    assert (await client.patch(own, json={"full_name": "Test Admin"})).status_code == 200

    other = await add_user(db_session, "admin.two", UserRole.ADMIN)
    other.is_active = False
    await db_session.flush()
    # Reactivating and demoting another admin works while one active admin remains.
    assert (
        await client.patch(f"/api/users/{other.id}", json={"is_active": True})
    ).status_code == 200
    demoted = await client.patch(f"/api/users/{other.id}", json={"role": "viewer"})
    assert demoted.status_code == 200


async def test_reset_password(
    client: AsyncClient,
    anonymous_client: AsyncClient,
    db_session: AsyncSession,
    app_settings: Settings,
) -> None:
    user = await add_user(db_session, "analyst.one", UserRole.ANALYST)
    bearer = {"Authorization": f"Bearer {issue_session(user, app_settings).token}"}

    reset = await client.post(f"/api/users/{user.id}/password", json={"password": NEW_PASSWORD})
    weak = await client.post(f"/api/users/{user.id}/password", json={"password": "short"})

    assert (reset.status_code, weak.status_code) == (204, 422)
    assert (await anonymous_client.get("/api/auth/me", headers=bearer)).status_code == 401
    login = await anonymous_client.post(
        "/api/auth/login", json={"username": "analyst.one", "password": NEW_PASSWORD}
    )
    assert login.status_code == 200
    old = await anonymous_client.post(
        "/api/auth/login", json={"username": "analyst.one", "password": TEST_PASSWORD}
    )
    assert old.status_code == 401


async def test_audit_log_api(client: AsyncClient, db_session: AsyncSession) -> None:
    await client.post("/api/users", json={"username": "analyst.two", "password": NEW_PASSWORD})
    await client.post("/api/cases", json={"title": "Phishing wave"})
    await client.post("/api/cases", json={"title": "SSH brute force"})

    everything = (await client.get("/api/audit")).json()
    cases = (await client.get("/api/audit", params={"action": "case."})).json()
    created = (await client.get("/api/audit", params={"action": "user.created"})).json()
    by_target = (await client.get("/api/audit", params={"target_type": "case", "limit": 1})).json()

    assert everything["total"] == 3
    assert [entry["action"] for entry in everything["items"]] == [
        "case.created",
        "case.created",
        "user.created",
    ]
    first = everything["items"][-1]
    assert first["username"] == "test.admin"
    assert first["ip_address"] == "127.0.0.1"
    assert first["details"] == {"username": "analyst.two", "role": "analyst"}
    assert cases["total"] == 2
    assert created["total"] == 1
    assert (len(by_target["items"]), by_target["total"]) == (1, 2)
    assert (await client.get("/api/audit", params={"username": "nobody"})).json()["total"] == 0
