from __future__ import annotations

import asyncio
import io

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from watchpost.accounts import AccountError, assignable_user, create_user
from watchpost.audit import history, record
from watchpost.cli import main
from watchpost.core.config import Settings
from watchpost.core.passwords import WeakPasswordError, verify_password
from watchpost.db.models import User, UserRole

PASSWORD = "correct-horse-battery"


async def test_create_user_hashes_the_password_and_normalises_names(
    db_session: AsyncSession,
) -> None:
    user = await create_user(
        db_session,
        username="  Analyst.One ",
        password=PASSWORD,
        role=UserRole.ANALYST,
        full_name=" Analyst One ",
        email="Analyst.One@Example.org",
    )

    assert user.id is not None
    assert (user.username, user.full_name, user.email) == (
        "analyst.one",
        "Analyst One",
        "analyst.one@example.org",
    )
    assert verify_password(user.password_hash, PASSWORD)


@pytest.mark.parametrize(
    ("username", "email", "message"),
    [
        ("analyst.one", None, "already exists"),
        ("someone-else", "analyst.one@example.org", "already exists"),
        ("ab", None, "3-64 characters"),
        ("-dash-first", None, "3-64 characters"),
        ("has space", None, "3-64 characters"),
    ],
)
async def test_create_user_rejects_bad_or_taken_names(
    db_session: AsyncSession, username: str, email: str | None, message: str
) -> None:
    await create_user(
        db_session,
        username="analyst.one",
        password=PASSWORD,
        role=UserRole.ANALYST,
        email="analyst.one@example.org",
    )

    with pytest.raises(AccountError, match=message):
        await create_user(
            db_session, username=username, password=PASSWORD, role=UserRole.ADMIN, email=email
        )


async def test_create_user_enforces_the_password_policy(db_session: AsyncSession) -> None:
    with pytest.raises(WeakPasswordError):
        await create_user(db_session, username="shorty", password="short", role=UserRole.VIEWER)


async def test_only_active_analysts_and_admins_can_be_assigned(
    db_session: AsyncSession,
) -> None:
    analyst = await create_user(
        db_session, username="analyst.one", password=PASSWORD, role=UserRole.ANALYST
    )
    viewer = await create_user(
        db_session, username="viewer.one", password=PASSWORD, role=UserRole.VIEWER
    )
    retired = await create_user(
        db_session, username="admin.old", password=PASSWORD, role=UserRole.ADMIN
    )
    retired.is_active = False
    await db_session.flush()

    assert await assignable_user(db_session, analyst.id) is analyst
    with pytest.raises(AccountError, match="viewer"):
        await assignable_user(db_session, viewer.id)
    with pytest.raises(AccountError, match="no active user"):
        await assignable_user(db_session, retired.id)
    with pytest.raises(AccountError, match="no active user"):
        await assignable_user(db_session, 999_999)


async def test_audit_history_is_per_target_and_in_order(db_session: AsyncSession) -> None:
    analyst = await create_user(
        db_session, username="analyst.one", password=PASSWORD, role=UserRole.ANALYST
    )
    await record(db_session, "case.created", actor=analyst, target_type="case", target_id=7)
    await record(
        db_session,
        "case.status_changed",
        actor=None,
        target_type="case",
        target_id=7,
        details={"from": "open", "to": "closed"},
    )
    await record(db_session, "case.created", actor=None, target_type="case", target_id=8)

    entries = await history(db_session, "case", 7)

    assert [entry.action for entry in entries] == ["case.created", "case.status_changed"]
    assert (entries[0].user_id, entries[0].username) == (analyst.id, "analyst.one")
    assert entries[1].username is None
    assert entries[1].details == {"from": "open", "to": "closed"}


async def test_users_api_lists_assignable_users(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    for name, role in (("analyst.one", UserRole.ANALYST), ("viewer.one", UserRole.VIEWER)):
        await create_user(db_session, username=name, password=PASSWORD, role=role)

    everyone = (await client.get("/api/users")).json()
    assignable = (await client.get("/api/users", params={"assignable": True})).json()

    assert [user["username"] for user in everyone] == ["analyst.one", "viewer.one"]
    assert [user["username"] for user in assignable] == ["analyst.one"]
    assert "password_hash" not in everyone[0]


async def test_cli_create_user(
    settings: Settings, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("watchpost.cli.get_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    args = ["create-user", "cli.analyst", "--role", "admin", "--full-name", "CLI Analyst"]

    try:
        # The CLI starts its own event loop, as it would from a shell.
        assert await asyncio.to_thread(main, [*args, "--password-stdin"]) == 0
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(User.role, User.full_name, User.password_hash).where(
                        User.username == "cli.analyst"
                    )
                )
            ).one()
        assert row.role is UserRole.ADMIN
        assert row.full_name == "CLI Analyst"
        assert verify_password(row.password_hash, PASSWORD)

        monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
        assert await asyncio.to_thread(main, [*args, "--password-stdin"]) == 1  # taken
    finally:
        async with engine.begin() as conn:
            await conn.execute(delete(User).where(User.username == "cli.analyst"))


def test_cli_rejects_weak_or_mismatched_passwords(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("watchpost.cli.get_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert main(["create-user", "weak.user", "--password-stdin"]) == 1

    answers = iter([PASSWORD, PASSWORD + "x"])
    monkeypatch.setattr("watchpost.cli.getpass.getpass", lambda prompt: next(answers))
    assert main(["create-user", "typo.user"]) == 1
