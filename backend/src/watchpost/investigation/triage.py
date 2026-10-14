"""Alert triage: status changes and assignment.

Alerts move between ``new`` and ``investigating`` while open, and end as
``true_positive``, ``false_positive`` or ``closed``. Ending an alert sets
``resolved_at``; reopening clears it. Only one open alert may exist per
rule and entity (the detection engine relies on that to group repeated
hits), so reopening an alert is refused while a newer open alert already
tracks the same activity.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost import audit
from watchpost.db.models import OPEN_ALERT_STATUSES, Alert, AlertStatus, User

RESOLVED_STATUSES = frozenset(
    {AlertStatus.TRUE_POSITIVE, AlertStatus.FALSE_POSITIVE, AlertStatus.CLOSED}
)


class ReopenConflictError(Exception):
    """Reopening would create a second open alert for the same activity."""

    def __init__(self, alert_id: int, open_alert_id: int) -> None:
        super().__init__(
            f"alert {open_alert_id} is already open for the same rule and entity; "
            f"work on that one instead of reopening alert {alert_id}"
        )
        self.alert_id = alert_id
        self.open_alert_id = open_alert_id


async def set_status(
    session: AsyncSession, alert: Alert, status: AlertStatus, *, actor: User | None
) -> bool:
    """Change an alert's status. Returns ``False`` if it already had it. Flushes.

    Raises:
        ReopenConflictError: when reopening collides with another open alert.
    """
    previous = alert.status
    if previous is status:
        return False
    reopening = status in OPEN_ALERT_STATUSES and previous not in OPEN_ALERT_STATUSES
    if reopening:
        other = await session.scalar(
            select(Alert.id).where(
                Alert.group_key == alert.group_key,
                Alert.status.in_(OPEN_ALERT_STATUSES),
                Alert.id != alert.id,
            )
        )
        if other is not None:
            raise ReopenConflictError(alert.id, other)

    alert.status = status
    if status in RESOLVED_STATUSES:
        if previous not in RESOLVED_STATUSES:
            alert.resolved_at = datetime.now(UTC)
    else:
        alert.resolved_at = None
    await audit.record(
        session,
        "alert.status_changed",
        actor=actor,
        target_type="alert",
        target_id=alert.id,
        details={"from": previous.value, "to": status.value},
    )
    return True


async def assign(
    session: AsyncSession, alert: Alert, assignee: User | None, *, actor: User | None
) -> bool:
    """Give an alert to an analyst (or nobody). Returns ``False`` if unchanged. Flushes."""
    new_id = assignee.id if assignee else None
    if alert.assignee_id == new_id:
        return False
    previous = alert.assignee_id
    alert.assignee_id = new_id
    await audit.record(
        session,
        "alert.assigned",
        actor=actor,
        target_type="alert",
        target_id=alert.id,
        details={
            "from": previous,
            "to": new_id,
            "assignee": assignee.username if assignee else None,
        },
    )
    return True
