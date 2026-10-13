"""Platform users."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Identity, Integer, String, true
from sqlalchemy.orm import Mapped, mapped_column

from watchpost.db.base import Base, TimestampMixin, str_enum
from watchpost.db.models.enums import UserRole


class User(TimestampMixin, Base):
    """An analyst, administrator or read-only viewer."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        str_enum(UserRole, "user_role"), default=UserRole.VIEWER, server_default=UserRole.VIEWER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role}>"
