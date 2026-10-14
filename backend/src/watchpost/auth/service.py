"""Checking credentials and changing passwords."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.core.passwords import hash_password, needs_rehash, verify_password
from watchpost.db.models import User

# Checked when the user name is unknown, so a miss costs as much time as a
# wrong password and response times do not reveal which accounts exist.
_DUMMY_HASH = hash_password("not-a-real-password-for-timing")


async def authenticate(session: AsyncSession, username: str, password: str) -> User | None:
    """The active user with these credentials, or ``None``. Flushes on success.

    A successful sign-in records ``last_login_at`` and upgrades the stored
    hash if the hashing parameters have been raised since it was made.
    """
    user = await session.scalar(
        select(User).where(func.lower(User.username) == username.strip().lower())
    )
    if user is None:
        verify_password(_DUMMY_HASH, password)
        return None
    if not verify_password(user.password_hash, password) or not user.is_active:
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(UTC)
    await session.flush()
    return user


async def set_password(session: AsyncSession, user: User, password: str) -> None:
    """Store a new password and sign the user out of every existing session. Flushes.

    Raises:
        WeakPasswordError: if the password does not meet the policy.
    """
    user.password_hash = hash_password(password)
    user.session_version += 1
    await session.flush()
