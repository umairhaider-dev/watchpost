"""Browsing the audit log (admins only)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import ColumnElement, func, select

from watchpost.api.deps import AdminDep, SessionDep
from watchpost.db.models import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEntry(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    user_id: int | None
    username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    ip_address: str | None
    user_agent: str | None


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int


@router.get("", response_model=AuditPage)
async def list_audit(
    session: SessionDep,
    _admin: AdminDep,
    action: Annotated[
        str | None, Query(max_length=64, description="Exact action, or a prefix ending in '.'")
    ] = None,
    username: Annotated[str | None, Query(max_length=64)] = None,
    target_type: Annotated[str | None, Query(max_length=32)] = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Recorded actions, newest first."""
    conditions: list[ColumnElement[bool]] = []
    if action:
        conditions.append(
            AuditLog.action.startswith(action, autoescape=True)
            if action.endswith(".")
            else AuditLog.action == action
        )
    if username:
        conditions.append(AuditLog.username == username)
    if target_type:
        conditions.append(AuditLog.target_type == target_type)
    if target_id:
        conditions.append(AuditLog.target_id == target_id)
    if since is not None:
        conditions.append(AuditLog.occurred_at >= since)
    items = await session.scalars(
        select(AuditLog)
        .where(*conditions)
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await session.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    return {"items": list(items), "total": total or 0}
