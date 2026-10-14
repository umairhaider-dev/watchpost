"""Case management: open cases, link alerts, write notes, pin evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import ColumnElement, func, select

from watchpost.accounts import AccountError, assignable_user
from watchpost.api.deps import ActorDep, SessionDep
from watchpost.api.routes.alerts import ActivityOut, AlertOut
from watchpost.api.routes.events import EventOut
from watchpost.db.models import OPEN_ALERT_STATUSES, Case, CaseStatus, Event, Severity, User
from watchpost.investigation.casefile import CaseFile, case_counts, load_case_file
from watchpost.investigation.cases import (
    CaseError,
    DuplicateEvidenceError,
    add_alerts,
    add_evidence,
    add_note,
    assign_case,
    create_case,
    edit_case,
    remove_alert,
    remove_evidence,
    set_case_status,
)

router = APIRouter(prefix="/cases", tags=["cases"])

MAX_ALERTS_PER_REQUEST = 500
MAX_TEXT = 20_000


class UserRef(BaseModel):
    id: int
    username: str
    full_name: str | None


class CaseSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    severity: Severity
    status: CaseStatus
    assignee_id: int | None
    created_by_id: int | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    closed_at: datetime | None
    alert_count: int = 0
    open_alert_count: int = 0
    note_count: int = 0
    evidence_count: int = 0


class CasePage(BaseModel):
    items: list[CaseSummary]
    total: int


class NoteOut(BaseModel):
    id: int
    body: str
    author: str | None
    created_at: datetime


class EvidenceOut(BaseModel):
    id: int
    note: str | None
    added_by: str | None
    created_at: datetime
    event: EventOut


class CaseDetail(CaseSummary):
    description: str
    resolution: str | None
    assignee: UserRef | None
    created_by: UserRef | None
    alerts: list[AlertOut]
    notes: list[NoteOut]
    evidence: list[EvidenceOut]
    activity: list[ActivityOut]
    tactics: list[str]
    techniques: list[str]
    entities: dict[str, list[str]]


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=MAX_TEXT)
    severity: Severity | None = Field(
        default=None, description="Defaults to the highest severity among the alerts"
    )
    assignee_id: int | None = None
    alert_ids: list[int] = Field(default_factory=list, max_length=MAX_ALERTS_PER_REQUEST)


class CaseUpdate(BaseModel):
    """Fields to change; ``assignee_id`` and ``resolution`` accept null to clear them."""

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=MAX_TEXT)
    severity: Severity | None = None
    status: CaseStatus | None = None
    assignee_id: int | None = None
    resolution: str | None = Field(default=None, max_length=MAX_TEXT)

    @model_validator(mode="after")
    def _not_null(self) -> CaseUpdate:
        for name in ("title", "description", "severity", "status"):
            if name in self.model_fields_set and getattr(self, name) is None:
                msg = f"{name} cannot be null"
                raise ValueError(msg)
        return self


class AlertIds(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=MAX_ALERTS_PER_REQUEST)


class LinkedAlerts(BaseModel):
    added: list[int]


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=MAX_TEXT)


class EvidenceCreate(BaseModel):
    event_id: int
    note: str | None = Field(default=None, max_length=MAX_TEXT)


def _user_ref(user: User | None) -> dict[str, Any] | None:
    if user is None:
        return None
    return {"id": user.id, "username": user.username, "full_name": user.full_name}


def _detail(case_file: CaseFile) -> dict[str, Any]:
    case = case_file.case
    open_alerts = sum(1 for alert in case_file.alerts if alert.status in OPEN_ALERT_STATUSES)
    return {
        **CaseSummary.model_validate(case).model_dump(),
        "alert_count": len(case_file.alerts),
        "open_alert_count": open_alerts,
        "note_count": len(case_file.notes),
        "evidence_count": len(case_file.evidence),
        "description": case.description,
        "resolution": case.resolution,
        "assignee": _user_ref(case_file.assignee),
        "created_by": _user_ref(case_file.created_by),
        "alerts": case_file.alerts,
        "notes": [
            {
                "id": entry.note.id,
                "body": entry.note.body,
                "author": entry.author,
                "created_at": entry.note.created_at,
            }
            for entry in case_file.notes
        ],
        "evidence": [
            {
                "id": entry.evidence.id,
                "note": entry.evidence.note,
                "added_by": entry.added_by,
                "created_at": entry.evidence.created_at,
                "event": entry.event,
            }
            for entry in case_file.evidence
        ],
        "activity": list(case_file.activity),
        "tactics": case_file.tactics,
        "techniques": case_file.techniques,
        "entities": case_file.entities,
    }


async def _case_file(session: SessionDep, case_id: int) -> CaseFile:
    case_file = await load_case_file(session, case_id)
    if case_file is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case_file


async def _get_case(session: SessionDep, case_id: int) -> Case:
    case = await session.get(Case, case_id)
    if case is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case


async def _assignee(session: SessionDep, assignee_id: int | None) -> User | None:
    if assignee_id is None:
        return None
    try:
        return await assignable_user(session, assignee_id)
    except AccountError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


def _unprocessable(exc: CaseError) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


@router.get("", response_model=CasePage)
async def list_cases(
    session: SessionDep,
    case_status: Annotated[list[CaseStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    assignee_id: Annotated[int | None, Query()] = None,
    unassigned: Annotated[bool, Query()] = False,
    q: Annotated[str | None, Query(max_length=200, description="Part of the title")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Cases, most recently changed first."""
    conditions: list[ColumnElement[bool]] = []
    if case_status:
        conditions.append(Case.status.in_(case_status))
    if severity:
        conditions.append(Case.severity.in_(severity))
    if assignee_id is not None:
        conditions.append(Case.assignee_id == assignee_id)
    if unassigned:
        conditions.append(Case.assignee_id.is_(None))
    if q and q.strip():
        conditions.append(Case.title.icontains(q.strip(), autoescape=True))
    cases = list(
        await session.scalars(
            select(Case)
            .where(*conditions)
            .order_by(Case.updated_at.desc(), Case.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    total = await session.scalar(select(func.count()).select_from(Case).where(*conditions))
    counts = await case_counts(session, [case.id for case in cases])
    items = []
    for case in cases:
        count = counts[case.id]
        items.append(
            CaseSummary.model_validate(case).model_copy(
                update={
                    "alert_count": count.alerts,
                    "open_alert_count": count.open_alerts,
                    "note_count": count.notes,
                    "evidence_count": count.evidence,
                }
            )
        )
    return {"items": items, "total": total or 0}


@router.post("", response_model=CaseDetail, status_code=status.HTTP_201_CREATED)
async def open_case(body: CaseCreate, session: SessionDep, actor: ActorDep) -> dict[str, Any]:
    """Open a case, optionally around alerts (new ones move to investigating)."""
    assignee = await _assignee(session, body.assignee_id)
    try:
        case = await create_case(
            session,
            title=body.title,
            description=body.description,
            severity=body.severity,
            assignee=assignee,
            alert_ids=body.alert_ids,
            actor=actor,
        )
    except CaseError as exc:
        raise _unprocessable(exc) from exc
    await session.commit()
    return _detail(await _case_file(session, case.id))


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(case_id: int, session: SessionDep) -> dict[str, Any]:
    """A case with its alerts, notes, evidence and history."""
    return _detail(await _case_file(session, case_id))


@router.patch("/{case_id}", response_model=CaseDetail)
async def update_case(
    case_id: int, body: CaseUpdate, session: SessionDep, actor: ActorDep
) -> dict[str, Any]:
    """Change a case's details, status or assignee."""
    case = await _get_case(session, case_id)
    fields = body.model_fields_set
    if "assignee_id" in fields:
        await assign_case(session, case, await _assignee(session, body.assignee_id), actor=actor)
    await edit_case(
        session,
        case,
        title=body.title,
        description=body.description,
        severity=body.severity,
        resolution=body.resolution,
        clear_resolution="resolution" in fields and body.resolution is None,
        actor=actor,
    )
    if body.status is not None:
        await set_case_status(session, case, body.status, actor=actor)
    await session.commit()
    session.expire_all()
    return _detail(await _case_file(session, case_id))


@router.post("/{case_id}/alerts", response_model=LinkedAlerts)
async def link_alerts(
    case_id: int, body: AlertIds, session: SessionDep, actor: ActorDep
) -> LinkedAlerts:
    """Add alerts to the case (moving them from another case if needed)."""
    case = await _get_case(session, case_id)
    try:
        added = await add_alerts(session, case, body.alert_ids, actor=actor)
    except CaseError as exc:
        raise _unprocessable(exc) from exc
    await session.commit()
    return LinkedAlerts(added=added)


@router.delete("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink_alert(case_id: int, alert_id: int, session: SessionDep, actor: ActorDep) -> None:
    """Take an alert out of the case."""
    case = await _get_case(session, case_id)
    if not await remove_alert(session, case, alert_id, actor=actor):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "that alert is not part of this case")
    await session.commit()


@router.post("/{case_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
async def write_note(
    case_id: int, body: NoteCreate, session: SessionDep, actor: ActorDep
) -> dict[str, Any]:
    """Append a note to the case."""
    case = await _get_case(session, case_id)
    note = await add_note(session, case, body.body, actor=actor)
    await session.commit()
    await session.refresh(note)
    return {
        "id": note.id,
        "body": note.body,
        "author": actor.username if actor else None,
        "created_at": note.created_at,
    }


@router.post(
    "/{case_id}/evidence",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "The event is already evidence in this case"}},
)
async def pin_evidence(
    case_id: int, body: EvidenceCreate, session: SessionDep, actor: ActorDep
) -> dict[str, Any]:
    """Pin an event to the case as evidence, with an optional note."""
    case = await _get_case(session, case_id)
    try:
        evidence = await add_evidence(session, case, body.event_id, body.note, actor=actor)
    except DuplicateEvidenceError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except CaseError as exc:
        raise _unprocessable(exc) from exc
    await session.commit()
    await session.refresh(evidence)
    return {
        "id": evidence.id,
        "note": evidence.note,
        "added_by": actor.username if actor else None,
        "created_at": evidence.created_at,
        "event": await session.get(Event, evidence.event_id),
    }


@router.delete("/{case_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unpin_evidence(
    case_id: int, evidence_id: int, session: SessionDep, actor: ActorDep
) -> None:
    """Remove an evidence item from the case (the event itself is kept)."""
    case = await _get_case(session, case_id)
    if not await remove_evidence(session, case, evidence_id, actor=actor):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "that evidence is not part of this case")
    await session.commit()
