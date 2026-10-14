"""The MITRE ATT&CK matrix: which techniques the rules cover and which were detected.

Each tactic column lists the techniques that enabled or disabled rules map
to, or that alerts in the chosen period were raised for. A technique sits
under the tactics ATT&CK lists for it; one that the reference data does not
know goes under the tactics its rules and alerts declare.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import OPEN_ALERT_STATUSES, Alert, Rule
from watchpost.detection.mitre import TACTICS, technique_name, technique_tactics


@dataclass(slots=True)
class TechniqueCell:
    id: str
    name: str | None
    rules: list[str] = field(default_factory=list)
    enabled_rules: int = 0
    alerts: int = 0
    open_alerts: int = 0
    last_seen: datetime | None = None


@dataclass(slots=True)
class TacticColumn:
    id: str
    name: str
    techniques: list[TechniqueCell] = field(default_factory=list)


@dataclass(slots=True)
class AttackMatrix:
    tactics: list[TacticColumn]
    techniques_covered: int
    techniques_detected: int


async def attack_matrix(
    session: AsyncSession, *, since: datetime | None = None, until: datetime | None = None
) -> AttackMatrix:
    """Rule coverage and alert counts per technique, laid out by tactic."""
    cells: dict[str, TechniqueCell] = {}
    declared: dict[str, set[str]] = defaultdict(set)

    def cell(technique: str) -> TechniqueCell:
        if technique not in cells:
            cells[technique] = TechniqueCell(technique, technique_name(technique))
        return cells[technique]

    rules = await session.execute(
        select(Rule.id, Rule.enabled, Rule.mitre_tactics, Rule.mitre_techniques)
    )
    for rule_id, enabled, tactics, techniques in rules:
        for technique in techniques:
            entry = cell(technique)
            entry.rules.append(rule_id)
            entry.enabled_rules += int(enabled)
            declared[technique].update(tactics)

    period: list[ColumnElement[bool]] = []
    if since is not None:
        period.append(Alert.last_seen >= since)
    if until is not None:
        period.append(Alert.first_seen <= until)
    unnested = func.unnest(Alert.mitre_techniques).label("technique")
    detected = (
        select(
            unnested,
            func.count(),
            func.count().filter(Alert.status.in_(OPEN_ALERT_STATUSES)),
            func.max(Alert.last_seen),
            func.array_agg(func.distinct(func.array_to_string(Alert.mitre_tactics, ","))),
        )
        .where(*period)
        .group_by(unnested)
    )
    for technique_id, total, open_, last_seen, tactic_lists in await session.execute(detected):
        entry = cell(technique_id)
        entry.alerts, entry.open_alerts, entry.last_seen = total, open_, last_seen
        for joined in tactic_lists:
            declared[technique_id].update(filter(None, joined.split(",")))

    columns = {tactic_id: TacticColumn(tactic_id, name) for tactic_id, name in TACTICS.items()}
    for technique_id in sorted(cells):
        for tactic_id in technique_tactics(technique_id) or sorted(declared[technique_id]):
            if tactic_id in columns:
                columns[tactic_id].techniques.append(cells[technique_id])
    for column in columns.values():
        column.techniques.sort(key=lambda entry: (-entry.alerts, entry.id))
    return AttackMatrix(
        tactics=list(columns.values()),
        techniques_covered=sum(1 for entry in cells.values() if entry.enabled_rules),
        techniques_detected=sum(1 for entry in cells.values() if entry.alerts),
    )
