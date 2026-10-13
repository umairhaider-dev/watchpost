from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from watchpost.cli import main
from watchpost.core.config import Settings
from watchpost.db.models import Rule, RuleOrigin, RuleType, Severity
from watchpost.detection.errors import RuleError
from watchpost.detection.store import (
    load_compiled_rules,
    load_rule_files,
    sync_builtin_rules,
)

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"

SIMPLE_RULE = """\
id: {rule_id}
title: Simple test rule
description: Matches failed SSH logins for testing.
severity: low
detection:
  selection:
    event.action: ssh_login
  condition: selection
mitre:
  tactics: [TA0006]
  techniques: [T1110]
"""


def copy_rules(target: Path) -> Path:
    shutil.copytree(RULES_DIR, target)
    return target


async def all_rules(session: AsyncSession) -> dict[str, Rule]:
    return {rule.id: rule for rule in await session.scalars(select(Rule))}


async def test_sync_inserts_every_builtin_rule(db_session: AsyncSession) -> None:
    result = await sync_builtin_rules(db_session, RULES_DIR)

    rules = await all_rules(db_session)
    assert len(result.created) == len(rules) == 20
    brute_force = rules["ssh-brute-force"]
    assert brute_force.origin is RuleOrigin.BUILTIN
    assert brute_force.rule_type is RuleType.THRESHOLD
    assert brute_force.severity is Severity.MEDIUM
    assert brute_force.mitre_techniques == ["T1110.001"]
    assert brute_force.enabled is True
    assert brute_force.definition["threshold"]["count"] == 10
    assert brute_force.source_yaml.startswith("id: ssh-brute-force")


async def test_second_sync_changes_nothing(db_session: AsyncSession) -> None:
    await sync_builtin_rules(db_session, RULES_DIR)

    result = await sync_builtin_rules(db_session, RULES_DIR)

    assert result.created == result.updated == []
    assert len(result.unchanged) == 20


async def test_changed_file_updates_rule_but_keeps_enabled_state(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    rules_dir = copy_rules(tmp_path / "rules")
    await sync_builtin_rules(db_session, rules_dir)
    rule = (await all_rules(db_session))["web-scanner-user-agent"]
    rule.enabled = False
    await db_session.flush()

    path = rules_dir / "web" / "scanner-user-agent.yml"
    path.write_text(path.read_text().replace("severity: medium", "severity: high"))
    result = await sync_builtin_rules(db_session, rules_dir)

    await db_session.refresh(rule)
    assert result.updated == ["web-scanner-user-agent"]
    assert rule.severity is Severity.HIGH
    assert rule.version == 2
    assert rule.enabled is False


async def test_locally_modified_and_custom_rules_are_left_alone(
    db_session: AsyncSession, tmp_path: Path
) -> None:
    rules_dir = copy_rules(tmp_path / "rules")
    await sync_builtin_rules(db_session, rules_dir)
    rules = await all_rules(db_session)
    rules["web-sql-injection"].modified = True
    rules["web-path-traversal"].origin = RuleOrigin.CUSTOM
    await db_session.flush()
    for name in ("sql-injection.yml", "path-traversal.yml"):
        path = rules_dir / "web" / name
        path.write_text(path.read_text().replace("severity: high", "severity: low"))

    result = await sync_builtin_rules(db_session, rules_dir)

    assert sorted(result.skipped) == ["web-path-traversal", "web-sql-injection"]
    assert rules["web-sql-injection"].severity is Severity.HIGH


def test_invalid_rule_file_is_reported_with_its_name(tmp_path: Path) -> None:
    (tmp_path / "linux").mkdir()
    (tmp_path / "linux" / "broken.yml").write_text("id: broken\ntitle: Broken\n")

    with pytest.raises(RuleError, match=r"linux/broken\.yml"):
        load_rule_files(tmp_path)


def test_duplicate_rule_ids_are_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(SIMPLE_RULE.format(rule_id="same-id"))
    (tmp_path / "b.yaml").write_text(SIMPLE_RULE.format(rule_id="same-id"))

    with pytest.raises(RuleError, match="used by both"):
        load_rule_files(tmp_path)


async def test_load_compiled_rules_filters_and_reports_broken_rules(
    db_session: AsyncSession,
) -> None:
    await sync_builtin_rules(db_session, RULES_DIR)
    rules = await all_rules(db_session)
    rules["ssh-brute-force"].enabled = False
    rules["web-sql-injection"].source_yaml = "id: web-sql-injection\n"  # corrupted
    await db_session.flush()

    enabled = await load_compiled_rules(db_session)
    chosen = await load_compiled_rules(
        db_session, ["ssh-brute-force", "linux-user-created"], enabled_only=False
    )

    assert "ssh-brute-force" not in {rule.id for rule in enabled.rules}
    assert enabled.broken == ["web-sql-injection"]
    assert len(enabled.rules) == 18
    assert sorted(rule.id for rule in chosen.rules) == ["linux-user-created", "ssh-brute-force"]


async def test_cli_sync_rules(
    settings: Settings, engine: AsyncEngine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "cli.yml").write_text(SIMPLE_RULE.format(rule_id="cli-test-rule"))
    monkeypatch.setattr("watchpost.cli.get_settings", lambda: settings)

    try:
        # The CLI starts its own event loop, as it would from a shell.
        assert await asyncio.to_thread(main, ["sync-rules", "--rules-dir", str(tmp_path)]) == 0
        async with engine.connect() as conn:
            found = await conn.scalar(select(Rule.id).where(Rule.id == "cli-test-rule"))
        assert found == "cli-test-rule"
    finally:
        async with engine.begin() as conn:
            await conn.execute(delete(Rule).where(Rule.id == "cli-test-rule"))


def test_cli_reports_invalid_rules(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bad.yml").write_text("id: bad\n")
    monkeypatch.setattr("watchpost.cli.get_settings", lambda: settings)

    assert main(["sync-rules", "--rules-dir", str(tmp_path)]) == 1
