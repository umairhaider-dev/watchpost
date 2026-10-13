"""Read-only metadata about the platform, used by the UI."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from watchpost.detection.mitre import TACTICS, TECHNIQUES
from watchpost.events.fields import FIELDS, FieldKind

router = APIRouter(prefix="/meta", tags=["meta"])


class FieldInfo(BaseModel):
    name: str
    kind: FieldKind
    description: str


@router.get("/fields", response_model=list[FieldInfo])
async def list_event_fields() -> list[FieldInfo]:
    """List the normalised event fields usable in rules and search queries."""
    return [
        FieldInfo(name=spec.name, kind=spec.kind, description=spec.description) for spec in FIELDS
    ]


class MitreItem(BaseModel):
    id: str
    name: str


class MitreReference(BaseModel):
    tactics: list[MitreItem]
    techniques: list[MitreItem]


@router.get("/mitre", response_model=MitreReference)
async def mitre_reference() -> MitreReference:
    """ATT&CK tactics in matrix order and the technique names the platform knows."""
    return MitreReference(
        tactics=[MitreItem(id=key, name=name) for key, name in TACTICS.items()],
        techniques=[MitreItem(id=key, name=name) for key, name in sorted(TECHNIQUES.items())],
    )
