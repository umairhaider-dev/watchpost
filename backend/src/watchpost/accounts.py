"""Creating and listing platform users."""

from __future__ import annotations

import logging
import re

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.core.passwords import hash_password
from watchpost.db.models import User, UserRole

logger = logging.getLogger(__name__)

USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
_USERNAME = re.compile(USERNAME_PATTERN)
# Roles that can own alerts and cases; viewers only read.
ASSIGNABLE_ROLES = frozenset({UserRole.ADMIN, UserRole.ANALYST})


class AccountError(ValueError):
    """A user could not be created as requested."""


async def create_user(
    session: AsyncSession,
    *,
    username: str,
    password: str,
    role: UserRole,
    full_name: str | None = None,
    email: str | None = None,
) -> User:
    """Add a user with a hashed password. Flushes, does not commit.

    Raises:
        AccountError: for an invalid or taken username or email.
        WeakPasswordError: if the password does not meet the policy.
    """
    username = username.strip().lower()
    if not _USERNAME.match(username):
        msg = (
            "usernames are 3-64 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
        )
        raise AccountError(msg)
    email = email.strip().lower() if email and email.strip() else None
    clashes = [User.username == username]
    if email:
        clashes.append(User.email == email)
    taken = await session.scalar(select(func.count()).select_from(User).where(or_(*clashes)))
    if taken:
        msg = f"a user named {username!r} or with that email already exists"
        raise AccountError(msg)
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
        full_name=full_name.strip() if full_name and full_name.strip() else None,
        email=email,
    )
    session.add(user)
    await session.flush()
    logger.info("Created %s account %r", role.value, username)
    return user


async def assignable_user(session: AsyncSession, user_id: int) -> User:
    """The active analyst or admin with this ID.

    Raises:
        AccountError: if there is no such user or they cannot own work.
    """
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        msg = f"no active user with id {user_id}"
        raise AccountError(msg)
    if user.role not in ASSIGNABLE_ROLES:
        msg = f"{user.username} is a viewer and cannot be assigned work"
        raise AccountError(msg)
    return user
