"""Detection rule management: list, inspect, enable/disable, edit, create and test."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func, select

from watchpost.api.deps import SessionDep
from watchpost.db.models import OPEN_ALERT_STATUSES, Alert, Rule, RuleOrigin, RuleType, Severity
from watchpost.detection.compiler import compile_rule
from watchpost.detection.errors import RuleError
from watchpost.detection.fields import EventRow
from watchpost.detection.mitre import TACTICS, technique_name
from watchpost.detection.runner import alert_title
from watchpost.detection.sandbox import try_rule_on_sample
from watchpost.detection.schema import MAX_RULE_YAML_BYTES, RuleDefinition, load_rule
from watchpost.detection.store import load_compiled_rules, rule_columns
from watchpost.ingestion.errors import FormatDetectionError
from watchpost.ingestion.parsers import AUTO, PARSERS, is_valid_parser_choice

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rules", tags=["rules"])

RuleId = Annotated[str, Path(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")]
RULE_TEST_PATH = "/api/rules/test"
MAX_SAMPLE_CHARS = 1_000_000
# Request body limit for the sandbox: once JSON-encoded, a sample at the
# character limit can take several bytes per character (UTF-8, escapes).
RULE_TEST_MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_MATCHED_EVENTS = 200


class MitreRef(BaseModel):
    id: str
    name: str | None


class RuleSummary(BaseModel):
    id: str
    title: str
    severity: Severity
    rule_type: RuleType
    origin: RuleOrigin
    enabled: bool
    modified: bool
    version: int
    tactics: list[MitreRef]
    techniques: list[MitreRef]
    open_alerts: int
    total_alerts: int
    last_alert_at: datetime | None
    updated_at: datetime


class RuleDetail(RuleSummary):
    description: str
    false_positives: list[str]
    references: list[str]
    source_yaml: str
    group_by: list[str]
    log_sources: list[str]


class RuleToggle(BaseModel):
    enabled: bool


class RuleSource(BaseModel):
    source_yaml: str = Field(min_length=1, max_length=MAX_RULE_YAML_BYTES)


class RuleValidation(BaseModel):
    valid: bool
    error: str | None = None
    id: str | None = None
    title: str | None = None
    rule_type: RuleType | None = None


class RuleTestRequest(BaseModel):
    sample: str = Field(min_length=1, max_length=MAX_SAMPLE_CHARS)
    parser: str = AUTO
    source_yaml: str | None = Field(default=None, max_length=MAX_RULE_YAML_BYTES)
    rule_id: str | None = None

    @model_validator(mode="after")
    def _one_rule(self) -> RuleTestRequest:
        if (self.source_yaml is None) == (self.rule_id is None):
            msg = "give either source_yaml or rule_id"
            raise ValueError(msg)
        if not is_valid_parser_choice(self.parser):
            msg = f"unknown parser {self.parser!r}; expected 'auto' or one of: {', '.join(PARSERS)}"
            raise ValueError(msg)
        return self


class SampleLine(BaseModel):
    line: int
    reason: str
    excerpt: str


class SampleHit(BaseModel):
    title: str
    group: dict[str, str | None]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    lines: list[int]


class SampleEvent(BaseModel):
    line: int
    timestamp: datetime
    event_action: str | None
    event_outcome: str | None
    host_name: str | None
    user_name: str | None
    source_ip: str | None
    message: str | None


class RuleTestResponse(BaseModel):
    parser: str
    events_parsed: int
    truncated: bool
    malformed_count: int
    malformed: list[SampleLine]
    hits: list[SampleHit]
    matched_events: list[SampleEvent]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


async def _alert_stats(
    session: SessionDep, rule_ids: Sequence[str] | None = None
) -> dict[str, tuple[int, int, datetime | None]]:
    query = select(
        Alert.rule_id,
        func.count(),
        func.count().filter(Alert.status.in_(OPEN_ALERT_STATUSES)),
        func.max(Alert.last_seen),
    ).group_by(Alert.rule_id)
    if rule_ids is not None:
        query = query.where(Alert.rule_id.in_(rule_ids))
    rows = await session.execute(query)
    return {rule_id: (total, open_, last) for rule_id, total, open_, last in rows if rule_id}


def _summary(rule: Rule, stats: tuple[int, int, datetime | None] | None) -> dict[str, Any]:
    total, open_, last = stats or (0, 0, None)
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "rule_type": rule.rule_type,
        "origin": rule.origin,
        "enabled": rule.enabled,
        "modified": rule.modified,
        "version": rule.version,
        "tactics": [{"id": tactic, "name": TACTICS.get(tactic)} for tactic in rule.mitre_tactics],
        "techniques": [
            {"id": technique, "name": technique_name(technique)}
            for technique in rule.mitre_techniques
        ],
        "open_alerts": open_,
        "total_alerts": total,
        "last_alert_at": last,
        "updated_at": rule.updated_at,
    }


async def _detail(session: SessionDep, rule: Rule) -> RuleDetail:
    stats = (await _alert_stats(session, [rule.id])).get(rule.id)
    definition = rule.definition
    sources = definition.get("logsource", {}).get("source", [])
    return RuleDetail(
        **_summary(rule, stats),
        description=rule.description,
        false_positives=rule.false_positives,
        references=rule.references,
        source_yaml=rule.source_yaml,
        group_by=definition.get("group_by", []),
        log_sources=sources,
    )


async def _get_rule(session: SessionDep, rule_id: str) -> Rule:
    rule = await session.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"rule {rule_id!r} not found")
    return rule


def _parse(source_yaml: str) -> RuleDefinition:
    """Validate and compile rule YAML, turning errors into 422 responses."""
    try:
        definition = load_rule(source_yaml)
        compile_rule(definition)
    except RuleError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return definition


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@router.get("", response_model=list[RuleSummary])
async def list_rules(session: SessionDep) -> list[dict[str, Any]]:
    """Every rule, with how many alerts it has raised."""
    rules = await session.scalars(select(Rule).order_by(Rule.title))
    stats = await _alert_stats(session)
    return [_summary(rule, stats.get(rule.id)) for rule in rules]


@router.post("/validate", response_model=RuleValidation)
async def validate_rule(body: RuleSource) -> RuleValidation:
    """Check rule YAML without saving it."""
    try:
        definition = load_rule(body.source_yaml)
        compile_rule(definition)
    except RuleError as exc:
        return RuleValidation(valid=False, error=str(exc))
    return RuleValidation(
        valid=True, id=definition.id, title=definition.title, rule_type=definition.type
    )


@router.post("/test", response_model=RuleTestResponse)
async def run_rule_test(body: RuleTestRequest, session: SessionDep) -> RuleTestResponse:
    """Run a rule (saved or draft) over pasted sample logs. Nothing is stored."""
    if body.rule_id is not None:
        loaded = await load_compiled_rules(session, [body.rule_id], enabled_only=False)
        if not loaded.rules:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"rule {body.rule_id!r} not found")
        compiled = loaded.rules[0]
    else:
        compiled = compile_rule(_parse(body.source_yaml or ""))
    try:
        # Parsing and evaluating up to a megabyte of logs is CPU work; keep the loop free.
        result = await asyncio.to_thread(try_rule_on_sample, compiled, body.sample, body.parser)
    except FormatDetectionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    matched_lines = sorted({line for hit in result.hits for line in hit.event_ids})
    return RuleTestResponse(
        parser=result.parser,
        events_parsed=result.events_parsed,
        truncated=result.truncated,
        malformed_count=result.malformed_count,
        malformed=[
            SampleLine(line=s.line, reason=s.reason, excerpt=s.excerpt) for s in result.malformed
        ],
        hits=[
            SampleHit(
                title=alert_title(compiled, hit),
                group=dict(hit.group),
                event_count=hit.event_count,
                first_seen=hit.first_seen,
                last_seen=hit.last_seen,
                lines=sorted(hit.event_ids),
            )
            for hit in result.hits
        ],
        matched_events=[
            _sample_event(line, result.rows[line]) for line in matched_lines[:MAX_MATCHED_EVENTS]
        ],
    )


def _sample_event(line: int, row: EventRow) -> SampleEvent:
    return SampleEvent(
        line=line,
        timestamp=row["timestamp"],
        event_action=row.get("event_action"),
        event_outcome=row.get("event_outcome"),
        host_name=row.get("host_name"),
        user_name=row.get("user_name"),
        source_ip=row.get("source_ip"),
        message=row.get("message"),
    )


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleSource, session: SessionDep) -> RuleDetail:
    """Add a custom rule."""
    definition = _parse(body.source_yaml)
    if await session.get(Rule, definition.id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"a rule with id {definition.id!r} exists")
    rule = Rule(
        id=definition.id,
        origin=RuleOrigin.CUSTOM,
        enabled=definition.enabled,
        **rule_columns(definition, body.source_yaml),
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    logger.info("Created custom rule %s", rule.id)
    return await _detail(session, rule)


@router.get("/{rule_id}", response_model=RuleDetail)
async def get_rule(rule_id: RuleId, session: SessionDep) -> RuleDetail:
    return await _detail(session, await _get_rule(session, rule_id))


@router.patch("/{rule_id}", response_model=RuleDetail)
async def toggle_rule(rule_id: RuleId, body: RuleToggle, session: SessionDep) -> RuleDetail:
    """Enable or disable a rule."""
    rule = await _get_rule(session, rule_id)
    rule.enabled = body.enabled
    await session.commit()
    await session.refresh(rule)
    logger.info("Rule %s %s", rule.id, "enabled" if rule.enabled else "disabled")
    return await _detail(session, rule)


@router.put("/{rule_id}", response_model=RuleDetail)
async def update_rule(rule_id: RuleId, body: RuleSource, session: SessionDep) -> RuleDetail:
    """Replace a rule's YAML. Edited built-in rules are no longer updated by rule sync."""
    rule = await _get_rule(session, rule_id)
    definition = _parse(body.source_yaml)
    if definition.id != rule_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"the YAML id {definition.id!r} does not match the rule being edited ({rule_id!r})",
        )
    if body.source_yaml == rule.source_yaml:
        return await _detail(session, rule)
    for column, value in rule_columns(definition, body.source_yaml).items():
        setattr(rule, column, value)
    rule.version += 1
    if rule.origin is RuleOrigin.BUILTIN:
        rule.modified = True
    await session.commit()
    await session.refresh(rule)
    logger.info("Rule %s updated to version %d", rule.id, rule.version)
    return await _detail(session, rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: RuleId, session: SessionDep) -> Response:
    """Delete a custom rule. Built-in rules can only be disabled."""
    rule = await _get_rule(session, rule_id)
    if rule.origin is RuleOrigin.BUILTIN:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "built-in rules cannot be deleted; disable them instead"
        )
    await session.delete(rule)
    await session.commit()
    logger.info("Deleted custom rule %s", rule_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
