from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Alert, AlertStatus, Rule, RuleOrigin, Severity
from watchpost.detection.store import sync_builtin_rules

ROOT = Path(__file__).resolve().parents[3]
RULES_DIR = ROOT / "backend" / "rules"
AUTH_SAMPLE = (ROOT / "samples" / "auth.log").read_text()

CUSTOM_RULE = """\
id: custom-root-login
title: Successful root login over SSH
description: Root should never log in directly over SSH on our servers.
severity: high
mitre:
  tactics: [TA0001]
  techniques: [T1078]
logsource:
  source: linux_auth
detection:
  selection:
    event.action: ssh_login
    event.outcome: success
    user.name: root
  condition: selection
falsepositives:
  - Break-glass access during an outage
references:
  - https://attack.mitre.org/techniques/T1078/
"""


@pytest.fixture(autouse=True)
async def builtin_rules(db_session: AsyncSession) -> None:
    await sync_builtin_rules(db_session, RULES_DIR)


async def test_list_rules_with_alert_counts(client: AsyncClient, db_session: AsyncSession) -> None:
    for alert_status in (AlertStatus.NEW, AlertStatus.CLOSED):
        db_session.add(
            Alert(
                rule_id="ssh-brute-force",
                title="SSH brute force",
                severity=Severity.MEDIUM,
                status=alert_status,
                group_key=f"ssh-brute-force|{alert_status}",
                first_seen=datetime(2026, 10, 12, 9, 0, tzinfo=UTC),
                last_seen=datetime(2026, 10, 12, 9, 5, tzinfo=UTC),
            )
        )
    await db_session.flush()

    rules = {rule["id"]: rule for rule in (await client.get("/api/rules")).json()}

    assert len(rules) == 21
    brute_force = rules["ssh-brute-force"]
    assert brute_force["total_alerts"] == 2
    assert brute_force["open_alerts"] == 1
    assert brute_force["last_alert_at"].startswith("2026-10-12T09:05")
    assert brute_force["techniques"] == [
        {"id": "T1110.001", "name": "Brute Force: Password Guessing"}
    ]
    assert brute_force["tactics"] == [{"id": "TA0006", "name": "Credential Access"}]
    assert rules["linux-user-created"]["total_alerts"] == 0


async def test_rule_detail(client: AsyncClient) -> None:
    response = await client.get("/api/rules/login-from-new-source-ip")

    body = response.json()
    assert response.status_code == 200
    assert body["rule_type"] == "new_value"
    assert body["origin"] == "builtin"
    assert body["group_by"] == ["user.name"]
    assert body["log_sources"] == ["linux_auth", "windows_security", "json"]
    assert body["false_positives"]
    assert body["source_yaml"].startswith("id: login-from-new-source-ip")


async def test_unknown_rule_is_404(client: AsyncClient) -> None:
    assert (await client.get("/api/rules/no-such-rule")).status_code == 404
    assert (await client.get("/api/rules/BAD_ID")).status_code == 422


async def test_enable_and_disable(client: AsyncClient) -> None:
    disabled = await client.patch("/api/rules/ssh-brute-force", json={"enabled": False})
    enabled = await client.patch("/api/rules/ssh-brute-force", json={"enabled": True})

    assert disabled.json()["enabled"] is False
    assert enabled.json()["enabled"] is True


async def test_editing_a_builtin_rule_marks_it_modified(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    original = (await client.get("/api/rules/web-scanner-user-agent")).json()["source_yaml"]
    edited = original.replace("severity: medium", "severity: high")

    response = await client.put("/api/rules/web-scanner-user-agent", json={"source_yaml": edited})
    unchanged = await client.put("/api/rules/web-scanner-user-agent", json={"source_yaml": edited})

    body = response.json()
    assert body["severity"] == "high"
    assert body["modified"] is True
    assert body["version"] == 2
    assert unchanged.json()["version"] == 2
    result = await sync_builtin_rules(db_session, RULES_DIR)
    assert "web-scanner-user-agent" in result.skipped


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("id: [broken", "invalid YAML"),
        (CUSTOM_RULE.replace("id: custom-root-login", "id: other-id"), "does not match"),
        (CUSTOM_RULE.replace("condition: selection", "condition: missing"), "unknown selection"),
    ],
)
async def test_invalid_edits_are_rejected(client: AsyncClient, source: str, message: str) -> None:
    await client.post("/api/rules", json={"source_yaml": CUSTOM_RULE})

    response = await client.put("/api/rules/custom-root-login", json={"source_yaml": source})

    assert response.status_code == 422
    assert message in response.json()["detail"]


async def test_custom_rule_lifecycle(client: AsyncClient, db_session: AsyncSession) -> None:
    created = await client.post("/api/rules", json={"source_yaml": CUSTOM_RULE})
    duplicate = await client.post("/api/rules", json={"source_yaml": CUSTOM_RULE})

    assert created.status_code == 201
    assert created.json()["origin"] == "custom"
    assert duplicate.status_code == 409

    deleted = await client.delete("/api/rules/custom-root-login")
    assert deleted.status_code == 204
    assert await db_session.get(Rule, "custom-root-login") is None


async def test_builtin_rules_cannot_be_deleted(client: AsyncClient) -> None:
    response = await client.delete("/api/rules/ssh-brute-force")

    assert response.status_code == 409
    assert "disable" in response.json()["detail"]


async def test_validate(client: AsyncClient) -> None:
    good = (await client.post("/api/rules/validate", json={"source_yaml": CUSTOM_RULE})).json()
    bad = (
        await client.post("/api/rules/validate", json={"source_yaml": "id: x\ntitle: y\n"})
    ).json()

    assert good == {
        "valid": True,
        "error": None,
        "id": "custom-root-login",
        "title": "Successful root login over SSH",
        "rule_type": "match",
    }
    assert bad["valid"] is False
    assert bad["error"]


async def test_test_saved_rule_against_sample(client: AsyncClient) -> None:
    response = await client.post(
        "/api/rules/test", json={"rule_id": "ssh-brute-force-then-success", "sample": AUTH_SAMPLE}
    )

    body = response.json()
    assert response.status_code == 200
    assert body["parser"] == "linux_auth"
    assert body["events_parsed"] == 46
    [hit] = body["hits"]
    assert hit["title"] == "SSH brute force followed by a successful login: 203.0.113.45"
    assert hit["group"] == {"source.ip": "203.0.113.45"}
    assert hit["event_count"] == 6
    assert [event["line"] for event in body["matched_events"]] == hit["lines"]
    assert body["matched_events"][-1]["event_outcome"] == "success"


async def test_test_draft_rule_against_sample(client: AsyncClient) -> None:
    sample = (
        "Oct 12 10:00:00 web-01 sshd[1]: Accepted password for root from 10.0.0.5 port 22 ssh2\n"
    )
    response = await client.post(
        "/api/rules/test",
        json={"source_yaml": CUSTOM_RULE, "sample": sample, "parser": "linux_auth"},
    )

    assert response.json()["hits"][0]["lines"] == [1]


async def test_samples_up_to_the_character_limit_fit_in_the_request(
    client: AsyncClient,
) -> None:
    # Under the 1,000,000 character limit, but well over 1 MiB once JSON-encoded.
    user = "é" * 60
    line = f"Oct 12 10:00:00 web-01 sshd[1]: Invalid user {user} from 10.0.0.5 port 22\n"
    sample = line * (900_000 // len(line))
    payload = {"source_yaml": CUSTOM_RULE, "sample": sample, "parser": "linux_auth"}
    assert len(sample) < 1_000_000
    assert len(json.dumps(payload, ensure_ascii=False).encode()) > 1024 * 1024

    response = await client.post("/api/rules/test", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["events_parsed"] + body["malformed_count"] == sample.count("\n")


@pytest.mark.parametrize(
    ("payload", "status_code"),
    [
        ({"sample": "x"}, 422),  # no rule given
        ({"sample": "x", "rule_id": "ssh-brute-force", "source_yaml": CUSTOM_RULE}, 422),
        ({"sample": "x", "rule_id": "ssh-brute-force", "parser": "syslog"}, 422),
        ({"sample": "notes\nmore notes\n", "rule_id": "ssh-brute-force"}, 422),  # unknown format
        ({"sample": "x", "rule_id": "no-such-rule"}, 404),
        ({"sample": "x", "source_yaml": "id: [broken"}, 422),
    ],
)
async def test_test_endpoint_errors(
    client: AsyncClient, payload: dict[str, str], status_code: int
) -> None:
    response = await client.post("/api/rules/test", json=payload)

    assert response.status_code == status_code


async def test_mitre_reference(client: AsyncClient) -> None:
    body = (await client.get("/api/meta/mitre")).json()

    assert body["tactics"][0] == {"id": "TA0043", "name": "Reconnaissance"}
    assert len(body["tactics"]) == 14
    assert {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"} in body["techniques"]


async def test_rule_origin_values(db_session: AsyncSession) -> None:
    rule = await db_session.get(Rule, "ssh-brute-force")
    assert rule is not None and rule.origin is RuleOrigin.BUILTIN
