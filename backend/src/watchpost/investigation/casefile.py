"""Everything about one case, loaded together for the case page and reports."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from watchpost import audit
from watchpost.db.models import (
    OPEN_ALERT_STATUSES,
    Alert,
    AuditLog,
    Case,
    CaseEvidence,
    CaseNote,
    Event,
    User,
)


@dataclass(frozen=True, slots=True)
class NoteEntry:
    note: CaseNote
    author: str | None


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    evidence: CaseEvidence
    event: Event
    added_by: str | None


@dataclass(slots=True)
class CaseFile:
    case: Case
    assignee: User | None
    created_by: User | None
    alerts: list[Alert] = field(default_factory=list)
    notes: list[NoteEntry] = field(default_factory=list)
    evidence: list[EvidenceEntry] = field(default_factory=list)
    activity: Sequence[AuditLog] = ()

    @property
    def techniques(self) -> list[str]:
        return sorted({technique for alert in self.alerts for technique in alert.mitre_techniques})

    @property
    def tactics(self) -> list[str]:
        return sorted({tactic for alert in self.alerts for tactic in alert.mitre_tactics})

    @property
    def entities(self) -> dict[str, list[str]]:
        """Hosts, IP addresses and users seen in the alerts and evidence."""
        hosts: set[str] = set()
        ips: set[str] = set()
        users: set[str] = set()
        for alert in self.alerts:
            hosts.update(filter(None, [alert.host_name]))
            ips.update(filter(None, [alert.source_ip]))
            users.update(filter(None, [alert.user_name]))
        for entry in self.evidence:
            event = entry.event
            hosts.update(filter(None, [event.host_name]))
            ips.update(filter(None, [event.source_ip, event.destination_ip]))
            users.update(filter(None, [event.user_name]))
        return {"hosts": sorted(hosts), "ips": sorted(ips), "users": sorted(users)}


async def load_case_file(session: AsyncSession, case_id: int) -> CaseFile | None:
    """The case with its people, alerts, notes, evidence and history; ``None`` if missing."""
    case = await session.get(Case, case_id)
    if case is None:
        return None
    people = {
        user.id: user
        for user in await session.scalars(
            select(User).where(
                User.id.in_([i for i in (case.assignee_id, case.created_by_id) if i])
            )
        )
    }
    alerts = list(
        await session.scalars(
            select(Alert).where(Alert.case_id == case_id).order_by(Alert.first_seen, Alert.id)
        )
    )
    author = aliased(User)
    notes = [
        NoteEntry(note, username)
        for note, username in await session.execute(
            select(CaseNote, author.username)
            .outerjoin(author, author.id == CaseNote.author_id)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at, CaseNote.id)
        )
    ]
    adder = aliased(User)
    evidence = [
        EvidenceEntry(item, event, username)
        for item, event, username in await session.execute(
            select(CaseEvidence, Event, adder.username)
            .join(Event, Event.id == CaseEvidence.event_id)
            .outerjoin(adder, adder.id == CaseEvidence.added_by_id)
            .where(CaseEvidence.case_id == case_id)
            .order_by(Event.timestamp, Event.id)
        )
    ]
    return CaseFile(
        case=case,
        assignee=people.get(case.assignee_id) if case.assignee_id else None,
        created_by=people.get(case.created_by_id) if case.created_by_id else None,
        alerts=alerts,
        notes=notes,
        evidence=evidence,
        activity=await audit.history(session, "case", case_id),
    )


@dataclass(frozen=True, slots=True)
class CaseCounts:
    alerts: int = 0
    open_alerts: int = 0
    notes: int = 0
    evidence: int = 0


async def case_counts(session: AsyncSession, case_ids: Sequence[int]) -> dict[int, CaseCounts]:
    """Alert, note and evidence counts for several cases at once."""
    if not case_ids:
        return {}
    alert_counts = {
        case_id: (total, open_)
        for case_id, total, open_ in await session.execute(
            select(
                Alert.case_id,
                func.count(),
                func.count().filter(Alert.status.in_(OPEN_ALERT_STATUSES)),
            )
            .where(Alert.case_id.in_(case_ids))
            .group_by(Alert.case_id)
        )
    }
    note_counts: dict[int, int] = dict(
        (
            await session.execute(
                select(CaseNote.case_id, func.count())
                .where(CaseNote.case_id.in_(case_ids))
                .group_by(CaseNote.case_id)
            )
        ).all()
    )
    evidence_counts: dict[int, int] = dict(
        (
            await session.execute(
                select(CaseEvidence.case_id, func.count())
                .where(CaseEvidence.case_id.in_(case_ids))
                .group_by(CaseEvidence.case_id)
            )
        ).all()
    )
    return {
        case_id: CaseCounts(
            alerts=alert_counts.get(case_id, (0, 0))[0],
            open_alerts=alert_counts.get(case_id, (0, 0))[1],
            notes=note_counts.get(case_id, 0),
            evidence=evidence_counts.get(case_id, 0),
        )
        for case_id in case_ids
    }
