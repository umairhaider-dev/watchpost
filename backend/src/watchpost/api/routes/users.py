"""Listing users, for assignment pickers and author names."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from watchpost.accounts import ASSIGNABLE_ROLES
from watchpost.api.deps import SessionDep
from watchpost.db.models import User, UserRole

router = APIRouter(prefix="/users", tags=["users"])


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    full_name: str | None
    role: UserRole
    is_active: bool


@router.get("", response_model=list[UserOut])
async def list_users(
    session: SessionDep,
    assignable: Annotated[
        bool, Query(description="Only active analysts and admins, who can own alerts and cases")
    ] = False,
) -> list[User]:
    """Users by name."""
    query = select(User).order_by(User.username)
    if assignable:
        query = query.where(User.is_active.is_(True), User.role.in_(sorted(ASSIGNABLE_ROLES)))
    return list(await session.scalars(query))
