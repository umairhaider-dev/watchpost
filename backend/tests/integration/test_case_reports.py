from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_alert, make_event, store_events
from watchpost.accounts import create_user
from watchpost.db.models import AuditLog, Severity, UserRole
from watchpost.investigation.report import describe_activity, pdf_text

PASSWORD = "correct-horse-battery"
ARROW = chr(0x2192)
EM_DASH = chr(0x2014)
SNOWMAN = chr(0x2603)


async def build_case(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    owner = await create_user(
        db_session, username="analyst.one", password=PASSWORD, role=UserRole.ANALYST
    )
    alert = make_alert(
        title="Encoded PowerShell | ws-fin-07",
        severity=Severity.HIGH,
        mitre_tactics=["TA0002"],
        mitre_techniques=["T1059.001"],
    )
    db_session.add(alert)
    await db_session.flush()
    [event_id] = await store_events(
        db_session,
        make_event(
            "powershell",
            host={"name": "ws-fin-07"},
            user={"name": "carol"},
            process={"name": "powershell.exe", "command_line": "powershell -enc ```SQBFAFgA```"},
        ),
    )
    response = await client.post(
        "/api/cases",
        json={
            "title": f"Loader on ws-fin-07 {EM_DASH} caf{chr(0xE9)}",
            "description": f"Word {ARROW} PowerShell {ARROW} C2 beacon.",
            "assignee_id": owner.id,
            "alert_ids": [alert.id],
        },
    )
    case: dict[str, Any] = response.json()
    url = f"/api/cases/{case['id']}"
    await client.post(f"{url}/evidence", json={"event_id": event_id, "note": "Decoded payload"})
    await client.post(f"{url}/notes", json={"body": "Isolated the host.\nReimaged it."})
    await client.patch(url, json={"status": "resolved", "resolution": "Host rebuilt."})
    return case


async def test_markdown_report(client: AsyncClient, db_session: AsyncSession) -> None:
    case = await build_case(client, db_session)

    response = await client.get(f"/api/cases/{case['id']}/report")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="case-{case["id"]}-report.md"'
    )
    text = response.text
    assert text.startswith(f"# Case #{case['id']}: Loader on ws-fin-07 {EM_DASH} caf{chr(0xE9)}\n")
    assert "| Status | Resolved |" in text
    assert "| Assignee | analyst.one |" in text
    assert f"Word {ARROW} PowerShell {ARROW} C2 beacon." in text
    assert "## Resolution\n\nHost rebuilt." in text
    assert "- T1059.001 Command and Scripting Interpreter: PowerShell (Execution)" in text
    assert "- Hosts: web-01, ws-fin-07" in text
    # A pipe in a title must not break the table.
    assert "| Encoded PowerShell \\| ws-fin-07 | High | Investigating |" in text
    # The fence is longer than any run of backticks in the content.
    assert "````\npowershell -enc ```SQBFAFgA```\n````" in text
    assert "> Decoded payload" in text
    assert "> Isolated the host.\n> Reimaged it." in text
    assert "unattributed opened the case" in text
    assert "unattributed assigned the case to analyst.one" in text
    assert "unattributed changed the status from open to resolved" in text


async def test_pdf_report(client: AsyncClient, db_session: AsyncSession) -> None:
    case = await build_case(client, db_session)

    response = await client.get(f"/api/cases/{case['id']}/report", params={"format": "pdf"})

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"].endswith(f'case-{case["id"]}-report.pdf"')
    assert response.content.startswith(b"%PDF-")
    assert response.content.rstrip().endswith(b"%%EOF")
    assert b"/Title" in response.content


async def test_report_errors(client: AsyncClient) -> None:
    assert (await client.get("/api/cases/999999/report")).status_code == 404
    created = (await client.post("/api/cases", json={"title": "Empty"})).json()
    bad = await client.get(f"/api/cases/{created['id']}/report", params={"format": "docx"})
    assert bad.status_code == 422
    empty = (await client.get(f"/api/cases/{created['id']}/report")).text
    assert "_No alerts linked._" in empty
    assert "_No evidence pinned._" in empty
    pdf = await client.get(f"/api/cases/{created['id']}/report", params={"format": "pdf"})
    assert pdf.content.startswith(b"%PDF-")


def test_pdf_text_keeps_latin1_and_replaces_the_rest() -> None:
    assert pdf_text(f"caf{chr(0xE9)} {EM_DASH} a {ARROW} b") == f"caf{chr(0xE9)} - a -> b"
    assert pdf_text(f"snow {SNOWMAN}") == "snow ?"
    assert pdf_text(f"{chr(0xFB01)}le") == "file"  # the "fi" ligature is normalised


def test_unknown_activity_falls_back_to_the_action_name() -> None:
    entry = AuditLog(action="case.archived", details={}, occurred_at=datetime.now(UTC))
    assert describe_activity(entry) == "case.archived"
    removed = AuditLog(action="case.alert_removed", details={"alert_id": 4, "moved_to": 9})
    assert describe_activity(removed) == "removed alert #4 (moved to case #9)"
    edited = AuditLog(action="case.updated", details={"fields": ["severity", "title"]})
    assert describe_activity(edited) == "edited the severity, title"
    moved = AuditLog(action="case.status_changed", details={"from": "in_progress", "to": "closed"})
    assert describe_activity(moved) == "changed the status from in progress to closed"
