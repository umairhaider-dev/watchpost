"""Rule files on disk and the ``rules`` table.

Built-in rules ship as YAML files under ``rules/``. :func:`sync_builtin_rules`
loads them into the database:

* new rule files are inserted, enabled or not as the file says;
* changed files update their rule and bump its version, keeping whatever
  enabled/disabled state an analyst chose;
* rules an analyst edited through the API (``modified``) and custom rules
  are never overwritten.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Rule, RuleOrigin
from watchpost.detection.compiler import CompiledRule, compile_rule, compile_rule_text
from watchpost.detection.errors import RuleError
from watchpost.detection.schema import RuleDefinition, load_rule

logger = logging.getLogger(__name__)

RULE_FILE_PATTERNS = ("*.yml", "*.yaml")


@dataclass(frozen=True, slots=True)
class RuleFile:
    path: Path
    text: str
    definition: RuleDefinition


def load_rule_files(directory: Path) -> list[RuleFile]:
    """Load and fully validate every rule file under ``directory``.

    Raises:
        RuleError: naming the file, if any rule is invalid or two share an ID.
    """
    paths = sorted({path for pattern in RULE_FILE_PATTERNS for path in directory.rglob(pattern)})
    files: list[RuleFile] = []
    seen: dict[str, Path] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        try:
            compiled = compile_rule_text(text)
        except RuleError as exc:
            msg = f"{path.relative_to(directory).as_posix()}: {exc}"
            raise RuleError(msg) from exc
        rule_id = compiled.id
        if rule_id in seen:
            msg = f"rule id {rule_id!r} is used by both {seen[rule_id].name} and {path.name}"
            raise RuleError(msg)
        seen[rule_id] = path
        files.append(RuleFile(path=path, text=text, definition=compiled.definition))
    return files


def rule_columns(definition: RuleDefinition, text: str) -> dict[str, Any]:
    """Column values for a rule row, derived from its YAML."""
    return {
        "title": definition.title,
        "description": definition.description.strip(),
        "severity": definition.severity,
        "rule_type": definition.type,
        "mitre_tactics": definition.tactics,
        "mitre_techniques": definition.techniques,
        "false_positives": [item.strip() for item in definition.falsepositives],
        "references": definition.references,
        "definition": definition.model_dump(mode="json", exclude_none=True),
        "source_yaml": text,
    }


@dataclass(slots=True)
class SyncResult:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


async def sync_builtin_rules(session: AsyncSession, directory: Path) -> SyncResult:
    """Bring the built-in rules in the database in line with the files. Flushes, does not commit."""
    files = await asyncio.to_thread(load_rule_files, directory)
    ids = [rule_file.definition.id for rule_file in files]
    existing = {
        rule.id: rule for rule in await session.scalars(select(Rule).where(Rule.id.in_(ids)))
    }

    result = SyncResult()
    for rule_file in files:
        definition = rule_file.definition
        current = existing.get(definition.id)
        if current is None:
            session.add(
                Rule(
                    id=definition.id,
                    origin=RuleOrigin.BUILTIN,
                    enabled=definition.enabled,
                    **rule_columns(definition, rule_file.text),
                )
            )
            result.created.append(definition.id)
        elif current.origin is RuleOrigin.CUSTOM or current.modified:
            reason = (
                "a custom rule uses this id"
                if current.origin is RuleOrigin.CUSTOM
                else "edited locally"
            )
            logger.info(
                "Not updating rule %s from %s: %s", definition.id, rule_file.path.name, reason
            )
            result.skipped.append(definition.id)
        elif current.source_yaml == rule_file.text:
            result.unchanged.append(definition.id)
        else:
            for column, value in rule_columns(definition, rule_file.text).items():
                setattr(current, column, value)
            current.version += 1
            result.updated.append(definition.id)
    await session.flush()
    logger.info(
        "Rule sync: %d created, %d updated, %d unchanged, %d skipped",
        len(result.created),
        len(result.updated),
        len(result.unchanged),
        len(result.skipped),
    )
    return result


@dataclass(slots=True)
class LoadedRules:
    rules: list[CompiledRule]
    broken: list[str]


async def load_compiled_rules(
    session: AsyncSession,
    rule_ids: Sequence[str] | None = None,
    *,
    enabled_only: bool = True,
) -> LoadedRules:
    """Compile rules from the database, skipping (and reporting) any that fail."""
    query = select(Rule).order_by(Rule.id)
    if enabled_only:
        query = query.where(Rule.enabled.is_(True))
    if rule_ids is not None:
        query = query.where(Rule.id.in_(rule_ids))
    loaded = LoadedRules(rules=[], broken=[])
    for rule in await session.scalars(query):
        try:
            loaded.rules.append(compile_rule(load_rule(rule.source_yaml)))
        except RuleError as exc:
            logger.error("Rule %s cannot be compiled and is skipped: %s", rule.id, exc)
            loaded.broken.append(rule.id)
    return loaded
