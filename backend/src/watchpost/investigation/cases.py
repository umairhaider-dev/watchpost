"""Cases: investigations that group alerts, with notes and pinned evidence.

A case moves ``open -> in_progress -> resolved -> closed`` and can be
reopened. ``resolved_at`` and ``closed_at`` record when it last reached
those states; reopening clears them. Every change is written to the audit
log, which doubles as the case's activity feed.

Linking a ``new`` alert to a case moves it to ``investigating``. An alert
belongs to at most one case, so linking it to another case moves it.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost import audit
from watchpost.db.models import (
    Alert,
    AlertStatus,
    Case,
    CaseEvidence,
    CaseNote,
    CaseStatus,
    Event,
    Severity,
    User,
)
from watchpost.investigation.triage import set_status

logger = logging.getLogger(__name__)

DEFAULT_SEVERITY = Severity.MEDIUM
_REOPENED = frozenset({CaseStatus.OPEN, CaseStatus.IN_PROGRESS})


class CaseError(ValueError):
    """A case change refers to something missing or not allowed."""


class DuplicateEvidenceError(CaseError):
    """The event is already pinned to the case."""


async def _record(
    session: AsyncSession,
    case: Case,
    action: str,
    actor: User | None,
    details: dict[str, object] | None = None,
) -> None:
    await audit.record(
        session, action, actor=actor, target_type="case", target_id=case.id, details=details
    )


def _touch(case: Case) -> None:
    """Mark the case as changed when only its notes, evidence or alerts changed."""
    case.updated_at = datetime.now(UTC)


async def _load_alerts(session: AsyncSession, alert_ids: Sequence[int]) -> list[Alert]:
    wanted = list(dict.fromkeys(alert_ids))
    if not wanted:
        return []
    found = {
        alert.id: alert
        for alert in await session.scalars(select(Alert).where(Alert.id.in_(wanted)))
    }
    missing = [alert_id for alert_id in wanted if alert_id not in found]
    if missing:
        msg = f"no alert with id {', '.join(map(str, missing))}"
        raise CaseError(msg)
    return [found[alert_id] for alert_id in wanted]


async def create_case(
    session: AsyncSession,
    *,
    title: str,
    description: str = "",
    severity: Severity | None = None,
    assignee: User | None = None,
    alert_ids: Sequence[int] = (),
    actor: User | None,
) -> Case:
    """Open a case, optionally around some alerts. Flushes, does not commit.

    Without an explicit severity the case takes the highest severity of its
    alerts (medium if it has none).
    """
    alerts = await _load_alerts(session, alert_ids)
    if severity is None:
        severity = max((alert.severity for alert in alerts), key=lambda s: s.rank, default=None)
    case = Case(
        title=title.strip(),
        description=description.strip(),
        severity=severity or DEFAULT_SEVERITY,
        status=CaseStatus.OPEN,
        assignee_id=assignee.id if assignee else None,
        created_by_id=actor.id if actor else None,
    )
    session.add(case)
    await session.flush()
    await _record(
        session, case, "case.created", actor, {"title": case.title, "severity": case.severity}
    )
    if assignee:
        await _record(
            session,
            case,
            "case.assigned",
            actor,
            {"to": assignee.id, "assignee": assignee.username},
        )
    if alerts:
        await _link(session, case, alerts, actor)
    logger.info("Case %d opened with %d alerts", case.id, len(alerts))
    return case


async def _link(
    session: AsyncSession, case: Case, alerts: Sequence[Alert], actor: User | None
) -> list[int]:
    linked: list[int] = []
    for alert in alerts:
        if alert.case_id == case.id:
            continue
        moved_from = alert.case_id
        alert.case_id = case.id
        if alert.status is AlertStatus.NEW:
            await set_status(session, alert, AlertStatus.INVESTIGATING, actor=actor)
        if moved_from is not None:
            await audit.record(
                session,
                "case.alert_removed",
                actor=actor,
                target_type="case",
                target_id=moved_from,
                details={"alert_id": alert.id, "moved_to": case.id},
            )
        linked.append(alert.id)
    if linked:
        await _record(session, case, "case.alerts_added", actor, {"alert_ids": linked})
        _touch(case)
        await session.flush()
    return linked


async def add_alerts(
    session: AsyncSession, case: Case, alert_ids: Sequence[int], *, actor: User | None
) -> list[int]:
    """Link alerts to a case; returns the IDs that were not linked already. Flushes."""
    return await _link(session, case, await _load_alerts(session, alert_ids), actor)


async def remove_alert(
    session: AsyncSession, case: Case, alert_id: int, *, actor: User | None
) -> bool:
    """Unlink an alert from the case. Returns ``False`` if it was not linked. Flushes."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.case_id != case.id:
        return False
    alert.case_id = None
    await _record(session, case, "case.alert_removed", actor, {"alert_id": alert_id})
    _touch(case)
    await session.flush()
    return True


def _apply_status(case: Case, status: CaseStatus) -> None:
    now = datetime.now(UTC)
    case.status = status
    if status is CaseStatus.RESOLVED:
        case.resolved_at = case.resolved_at or now
        case.closed_at = None
    elif status is CaseStatus.CLOSED:
        case.resolved_at = case.resolved_at or now
        case.closed_at = now
    elif status in _REOPENED:
        case.resolved_at = None
        case.closed_at = None


async def set_case_status(
    session: AsyncSession, case: Case, status: CaseStatus, *, actor: User | None
) -> bool:
    """Move a case to a new status. Returns ``False`` if it already had it. Flushes."""
    previous = case.status
    if previous is status:
        return False
    _apply_status(case, status)
    await _record(
        session, case, "case.status_changed", actor, {"from": previous.value, "to": status.value}
    )
    await session.flush()
    return True


async def assign_case(
    session: AsyncSession, case: Case, assignee: User | None, *, actor: User | None
) -> bool:
    """Give the case to an analyst (or nobody). Returns ``False`` if unchanged. Flushes."""
    new_id = assignee.id if assignee else None
    if case.assignee_id == new_id:
        return False
    previous = case.assignee_id
    case.assignee_id = new_id
    await _record(
        session,
        case,
        "case.assigned",
        actor,
        {"from": previous, "to": new_id, "assignee": assignee.username if assignee else None},
    )
    await session.flush()
    return True


async def edit_case(
    session: AsyncSession,
    case: Case,
    *,
    title: str | None = None,
    description: str | None = None,
    severity: Severity | None = None,
    resolution: str | None = None,
    clear_resolution: bool = False,
    actor: User | None,
) -> list[str]:
    """Change descriptive fields; returns the names of those that changed. Flushes."""
    changes: dict[str, object] = {}
    if title is not None and title.strip() != case.title:
        changes["title"] = title.strip()
    if description is not None and description.strip() != case.description:
        changes["description"] = description.strip()
    if severity is not None and severity is not case.severity:
        changes["severity"] = severity
    if clear_resolution and case.resolution is not None:
        changes["resolution"] = None
    elif resolution is not None and resolution.strip() != (case.resolution or ""):
        changes["resolution"] = resolution.strip() or None
    if not changes:
        return []
    details: dict[str, object] = {"fields": sorted(changes)}
    if "severity" in changes:
        details["severity"] = {
            "from": case.severity.value,
            "to": severity.value if severity else None,
        }
    for name, value in changes.items():
        setattr(case, name, value)
    await _record(session, case, "case.updated", actor, details)
    await session.flush()
    return sorted(changes)


async def add_note(session: AsyncSession, case: Case, body: str, *, actor: User | None) -> CaseNote:
    """Append a note to the case. Flushes."""
    note = CaseNote(case_id=case.id, author_id=actor.id if actor else None, body=body.strip())
    session.add(note)
    await session.flush()
    await _record(session, case, "case.note_added", actor, {"note_id": note.id})
    _touch(case)
    await session.flush()
    return note


async def add_evidence(
    session: AsyncSession,
    case: Case,
    event_id: int,
    note: str | None = None,
    *,
    actor: User | None,
) -> CaseEvidence:
    """Pin an event to the case as evidence. Flushes.

    Raises:
        CaseError: if the event does not exist.
        DuplicateEvidenceError: if it is already pinned to this case.
    """
    if await session.get(Event, event_id) is None:
        msg = f"no event with id {event_id}"
        raise CaseError(msg)
    duplicate = await session.scalar(
        select(CaseEvidence.id).where(
            CaseEvidence.case_id == case.id, CaseEvidence.event_id == event_id
        )
    )
    if duplicate is not None:
        msg = f"event {event_id} is already evidence in this case"
        raise DuplicateEvidenceError(msg)
    evidence = CaseEvidence(
        case_id=case.id,
        event_id=event_id,
        note=note.strip() if note and note.strip() else None,
        added_by_id=actor.id if actor else None,
    )
    session.add(evidence)
    await session.flush()
    await _record(session, case, "case.evidence_added", actor, {"event_id": event_id})
    _touch(case)
    await session.flush()
    return evidence


async def remove_evidence(
    session: AsyncSession, case: Case, evidence_id: int, *, actor: User | None
) -> bool:
    """Unpin an evidence item. Returns ``False`` if it is not part of this case. Flushes."""
    evidence = await session.get(CaseEvidence, evidence_id)
    if evidence is None or evidence.case_id != case.id:
        return False
    event_id = evidence.event_id
    await session.delete(evidence)
    await _record(session, case, "case.evidence_removed", actor, {"event_id": event_id})
    _touch(case)
    await session.flush()
    return True
