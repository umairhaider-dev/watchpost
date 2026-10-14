"""Recording analyst actions in the append-only audit log."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import AuditLog, User


async def record(
    session: AsyncSession,
    action: str,
    *,
    actor: User | None,
    target_type: str,
    target_id: int | str,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Add one audit entry in the caller's transaction. Flushes, does not commit.

    ``action`` is a dotted name such as ``case.status_changed``; ``details``
    holds what changed (for example ``{"from": "open", "to": "closed"}``).
    """
    entry = AuditLog(
        user_id=actor.id if actor else None,
        username=actor.username if actor else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        details=details or {},
    )
    session.add(entry)
    await session.flush()
    return entry


async def history(
    session: AsyncSession, target_type: str, target_id: int | str, limit: int = 200
) -> Sequence[AuditLog]:
    """The most recent entries about one target, oldest first."""
    rows = await session.scalars(
        select(AuditLog)
        .where(AuditLog.target_type == target_type, AuditLog.target_id == str(target_id))
        .order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc())
        .limit(limit)
    )
    return list(reversed(list(rows)))
