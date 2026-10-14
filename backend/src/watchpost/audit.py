"""Recording analyst actions in the append-only audit log.

Each entry names the user, the action and its target, and, for actions
made through the API, the client address and user agent of the request.
Those come from :data:`request_context`, which the API sets for every
request, so services that record actions do not need to know about HTTP.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import AuditLog, User

MAX_USER_AGENT = 512


@dataclass(frozen=True, slots=True)
class RequestContext:
    ip_address: str | None
    user_agent: str | None


request_context: ContextVar[RequestContext | None] = ContextVar(
    "watchpost_audit_request", default=None
)


async def record(
    session: AsyncSession,
    action: str,
    *,
    actor: User | None,
    target_type: str,
    target_id: int | str,
    details: dict[str, Any] | None = None,
    username: str | None = None,
) -> AuditLog:
    """Add one audit entry in the caller's transaction. Flushes, does not commit.

    ``action`` is a dotted name such as ``case.status_changed``; ``details``
    holds what changed (for example ``{"from": "open", "to": "closed"}``).
    ``username`` names the account when there is no actor, as for a failed
    sign-in.
    """
    context = request_context.get()
    entry = AuditLog(
        user_id=actor.id if actor else None,
        username=actor.username if actor else username,
        action=action,
        target_type=target_type,
        target_id=str(target_id)[:64],
        details=details or {},
        ip_address=context.ip_address if context else None,
        user_agent=context.user_agent[:MAX_USER_AGENT] if context and context.user_agent else None,
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
