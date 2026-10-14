"""The MITRE ATT&CK matrix of rule coverage and detections."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel

from watchpost.api.deps import SessionDep
from watchpost.investigation.attack_matrix import attack_matrix

router = APIRouter(prefix="/mitre", tags=["investigation"])


class TechniqueCellOut(BaseModel):
    id: str
    name: str | None
    rules: list[str]
    enabled_rules: int
    alerts: int
    open_alerts: int
    last_seen: datetime | None


class TacticColumnOut(BaseModel):
    id: str
    name: str
    techniques: list[TechniqueCellOut]


class AttackMatrixOut(BaseModel):
    tactics: list[TacticColumnOut]
    techniques_covered: int
    techniques_detected: int


@router.get("/matrix", response_model=AttackMatrixOut)
async def matrix(
    session: SessionDep,
    since: Annotated[datetime | None, Query(description="Count alerts active at or after")] = None,
    until: Annotated[datetime | None, Query(description="Count alerts active at or before")] = None,
) -> dict[str, Any]:
    """Techniques by tactic: how many rules cover each and how many alerts it raised."""
    return asdict(await attack_matrix(session, since=since, until=until))
