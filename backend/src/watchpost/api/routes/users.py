"""Users: listing for pickers, and account management for admins."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from watchpost import audit
from watchpost.accounts import ASSIGNABLE_ROLES, USERNAME_PATTERN, AccountError, create_user
from watchpost.api.deps import AdminDep, SessionDep, UserDep
from watchpost.auth.service import set_password
from watchpost.core.passwords import MAX_PASSWORD_LENGTH, WeakPasswordError
from watchpost.db.models import User, UserRole

router = APIRouter(prefix="/users", tags=["users"])


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None
    role: UserRole
    is_active: bool


class UserDetail(UserOut):
    email: str | None
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    role: UserRole = UserRole.ANALYST
    full_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=255, pattern=r"^[^@\s]+@[^@\s]+$")


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, max_length=128)


class PasswordReset(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


@router.get("", response_model=list[UserDetail | UserOut])
async def list_users(
    session: SessionDep,
    viewer: UserDep,
    assignable: Annotated[
        bool, Query(description="Only active analysts and admins, who can own alerts and cases")
    ] = False,
) -> list[UserDetail] | list[UserOut]:
    """Users by name. Only admins see e-mail addresses and sign-in times."""
    query = select(User).order_by(User.username)
    if assignable:
        query = query.where(User.is_active.is_(True), User.role.in_(sorted(ASSIGNABLE_ROLES)))
    users = await session.scalars(query)
    if viewer.role is UserRole.ADMIN:
        return [UserDetail.model_validate(user) for user in users]
    return [UserOut.model_validate(user) for user in users]


async def _get_user(session: SessionDep, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


@router.post("", response_model=UserDetail, status_code=status.HTTP_201_CREATED)
async def add_user(body: UserCreate, session: SessionDep, admin: AdminDep) -> User:
    """Create an account (admins only)."""
    try:
        user = await create_user(
            session,
            username=body.username,
            password=body.password,
            role=body.role,
            full_name=body.full_name,
            email=body.email,
        )
    except AccountError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await audit.record(
        session,
        "user.created",
        actor=admin,
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "role": user.role.value},
    )
    await session.commit()
    await session.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserDetail)
async def update_user(user_id: int, body: UserUpdate, session: SessionDep, admin: AdminDep) -> User:
    """Change a user's role, name or whether they can sign in (admins only)."""
    user = await _get_user(session, user_id)
    changes = {
        name: value
        for name, value in body.model_dump(exclude_unset=True).items()
        if value is not None or name == "full_name"
    }
    # Only active admins get here, so refusing self-demotion and self-deactivation
    # also guarantees that at least one active admin always remains.
    if user.id == admin.id and ("role" in changes or changes.get("is_active") is False):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "you cannot change your own role or deactivate yourself"
        )
    recorded: dict[str, Any] = {}
    for name, value in changes.items():
        before = getattr(user, name)
        if before != value:
            setattr(user, name, value)
            recorded[name] = {
                "from": getattr(before, "value", before),
                "to": getattr(value, "value", value),
            }
    if recorded.get("is_active", {}).get("to") is False:
        user.session_version += 1
    if recorded:
        await audit.record(
            session,
            "user.updated",
            actor=admin,
            target_type="user",
            target_id=user.id,
            details=recorded,
        )
    await session.commit()
    await session.refresh(user)
    return user


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    user_id: int, body: PasswordReset, session: SessionDep, admin: AdminDep
) -> None:
    """Set a new password for a user and sign them out everywhere (admins only)."""
    user = await _get_user(session, user_id)
    try:
        await set_password(session, user, body.password)
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await audit.record(
        session, "user.password_reset", actor=admin, target_type="user", target_id=user.id
    )
    await session.commit()
