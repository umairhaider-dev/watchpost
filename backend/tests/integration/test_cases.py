from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_alert, make_event, store_events
from watchpost.accounts import create_user
from watchpost.db.models import Alert, AlertStatus, Severity, User, UserRole

PASSWORD = "correct-horse-battery"


async def add_alerts(session: AsyncSession, *alerts: Alert) -> list[int]:
    session.add_all(alerts)
    await session.flush()
    return [alert.id for alert in alerts]


async def make_user(session: AsyncSession, name: str, role: UserRole = UserRole.ANALYST) -> User:
    return await create_user(session, username=name, password=PASSWORD, role=role)


async def open_case(client: AsyncClient, **payload: Any) -> dict[str, Any]:
    response = await client.post("/api/cases", json={"title": "Investigation", **payload})
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def actions(case: dict[str, Any]) -> list[str]:
    return [entry["action"] for entry in case["activity"]]


async def test_open_a_case_around_alerts(client: AsyncClient, db_session: AsyncSession) -> None:
    owner = await make_user(db_session, "analyst.one")
    new, triaged = await add_alerts(
        db_session,
        make_alert(severity=Severity.MEDIUM),
        make_alert(
            severity=Severity.CRITICAL,
            status=AlertStatus.INVESTIGATING,
            host_name="ws-fin-07",
            mitre_tactics=["TA0006"],
            mitre_techniques=["T1003.001"],
        ),
    )

    case = await open_case(
        client,
        title="  Credential theft on ws-fin-07 ",
        description="Started from the LSASS alert.",
        assignee_id=owner.id,
        alert_ids=[new, triaged],
    )

    assert case["title"] == "Credential theft on ws-fin-07"
    assert case["severity"] == "critical"  # the highest among its alerts
    assert case["status"] == "open"
    assert case["assignee"] == {"id": owner.id, "username": "analyst.one", "full_name": None}
    assert (case["alert_count"], case["open_alert_count"]) == (2, 2)
    assert {alert["id"]: alert["status"] for alert in case["alerts"]} == {
        new: "investigating",  # linking moves new alerts on
        triaged: "investigating",
    }
    assert case["techniques"] == ["T1003.001", "T1110.001"]
    assert case["entities"]["hosts"] == ["web-01", "ws-fin-07"]
    assert actions(case) == ["case.created", "case.assigned", "case.alerts_added"]


async def test_case_defaults_and_validation(client: AsyncClient, db_session: AsyncSession) -> None:
    viewer = await make_user(db_session, "viewer.one", UserRole.VIEWER)

    empty = await open_case(client)
    assert (empty["severity"], empty["alert_count"]) == ("medium", 0)

    for payload, message in (
        ({"title": ""}, "at least 1 character"),
        ({"title": "x", "alert_ids": [999_999]}, "no alert with id 999999"),
        ({"title": "x", "assignee_id": viewer.id}, "viewer"),
    ):
        response = await client.post("/api/cases", json=payload)
        assert response.status_code == 422
        assert message in response.text


async def test_status_changes_track_timestamps(client: AsyncClient) -> None:
    case = await open_case(client)
    url = f"/api/cases/{case['id']}"

    working = (await client.patch(url, json={"status": "in_progress"})).json()
    assert working["resolved_at"] is None

    resolved = (
        await client.patch(url, json={"status": "resolved", "resolution": "Password reset."})
    ).json()
    assert resolved["resolved_at"] is not None
    assert resolved["closed_at"] is None
    assert resolved["resolution"] == "Password reset."

    closed = (await client.patch(url, json={"status": "closed"})).json()
    assert closed["closed_at"] is not None
    assert closed["resolved_at"] == resolved["resolved_at"]

    reopened = (await client.patch(url, json={"status": "open", "resolution": None})).json()
    assert (reopened["resolved_at"], reopened["closed_at"], reopened["resolution"]) == (
        None,
        None,
        None,
    )
    changes = [
        entry["details"]
        for entry in reopened["activity"]
        if entry["action"] == "case.status_changed"
    ]
    assert [(c["from"], c["to"]) for c in changes] == [
        ("open", "in_progress"),
        ("in_progress", "resolved"),
        ("resolved", "closed"),
        ("closed", "open"),
    ]


async def test_edit_details_and_assignee(client: AsyncClient, db_session: AsyncSession) -> None:
    owner = await make_user(db_session, "analyst.one")
    case = await open_case(client, assignee_id=owner.id)
    url = f"/api/cases/{case['id']}"

    edited = (
        await client.patch(
            url,
            json={"title": "Renamed", "severity": "high", "description": "More detail"},
        )
    ).json()
    assert (edited["title"], edited["severity"], edited["description"]) == (
        "Renamed",
        "high",
        "More detail",
    )
    update = edited["activity"][-1]
    assert update["action"] == "case.updated"
    assert update["details"]["fields"] == ["description", "severity", "title"]
    assert update["details"]["severity"] == {"from": "medium", "to": "high"}

    unchanged = (await client.patch(url, json={"title": "Renamed"})).json()
    assert len(unchanged["activity"]) == len(edited["activity"])

    unassigned = (await client.patch(url, json={"assignee_id": None})).json()
    assert unassigned["assignee"] is None

    for payload in ({"title": None}, {"status": None}, {"status": "done"}):
        assert (await client.patch(url, json=payload)).status_code == 422
    assert (await client.patch("/api/cases/999999", json={"title": "x"})).status_code == 404


async def test_link_move_and_unlink_alerts(client: AsyncClient, db_session: AsyncSession) -> None:
    alert_id, other_id = await add_alerts(db_session, make_alert(), make_alert())
    first = await open_case(client, alert_ids=[alert_id])
    second = await open_case(client, title="Second")

    moved = await client.post(
        f"/api/cases/{second['id']}/alerts", json={"alert_ids": [alert_id, other_id]}
    )
    assert moved.json() == {"added": [alert_id, other_id]}
    again = await client.post(f"/api/cases/{second['id']}/alerts", json={"alert_ids": [alert_id]})
    assert again.json() == {"added": []}

    first_now = (await client.get(f"/api/cases/{first['id']}")).json()
    assert first_now["alert_count"] == 0
    assert first_now["activity"][-1]["details"] == {"alert_id": alert_id, "moved_to": second["id"]}

    removed = await client.delete(f"/api/cases/{second['id']}/alerts/{alert_id}")
    assert removed.status_code == 204
    gone = await client.delete(f"/api/cases/{second['id']}/alerts/{alert_id}")
    assert gone.status_code == 404
    bad = await client.post(f"/api/cases/{second['id']}/alerts", json={"alert_ids": [999_999]})
    assert bad.status_code == 422


async def test_notes(client: AsyncClient) -> None:
    case = await open_case(client)
    url = f"/api/cases/{case['id']}/notes"

    first = await client.post(url, json={"body": "  Checked the VPN logs: nothing.  "})
    await client.post(url, json={"body": "Reset the backup account password."})

    assert first.status_code == 201
    assert first.json()["body"] == "Checked the VPN logs: nothing."
    assert first.json()["author"] is None  # no sign-in yet
    detail = (await client.get(f"/api/cases/{case['id']}")).json()
    assert [note["body"] for note in detail["notes"]] == [
        "Checked the VPN logs: nothing.",
        "Reset the backup account password.",
    ]
    assert detail["note_count"] == 2
    assert (await client.post(url, json={"body": ""})).status_code == 422
    assert (await client.post("/api/cases/999999/notes", json={"body": "x"})).status_code == 404


async def test_evidence(client: AsyncClient, db_session: AsyncSession) -> None:
    [event_id] = await store_events(
        db_session, make_event("Accepted password for backup from 203.0.113.45")
    )
    case = await open_case(client)
    url = f"/api/cases/{case['id']}/evidence"

    pinned = await client.post(url, json={"event_id": event_id, "note": "First success"})
    assert pinned.status_code == 201
    evidence = pinned.json()
    assert evidence["note"] == "First success"
    assert evidence["event"]["id"] == event_id
    assert evidence["event"]["source_ip"] == "203.0.113.45"

    duplicate = await client.post(url, json={"event_id": event_id})
    assert duplicate.status_code == 409
    missing = await client.post(url, json={"event_id": 999_999})
    assert missing.status_code == 422

    detail = (await client.get(f"/api/cases/{case['id']}")).json()
    assert detail["evidence_count"] == 1
    assert detail["entities"]["ips"] == ["203.0.113.45"]

    removed = await client.delete(f"{url}/{evidence['id']}")
    assert removed.status_code == 204
    assert (await client.delete(f"{url}/{evidence['id']}")).status_code == 404
    final = (await client.get(f"/api/cases/{case['id']}")).json()
    assert actions(final)[-2:] == ["case.evidence_added", "case.evidence_removed"]


async def test_list_cases_with_filters_and_counts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await make_user(db_session, "analyst.one")
    [alert_id] = await add_alerts(db_session, make_alert())
    phishing = await open_case(client, title="Phishing wave", alert_ids=[alert_id])
    brute = await open_case(client, title="SSH brute force", assignee_id=owner.id)
    await client.patch(f"/api/cases/{brute['id']}", json={"status": "closed"})
    await client.post(f"/api/cases/{phishing['id']}/notes", json={"body": "note"})

    async def titles(**params: str | int | bool | list[str]) -> list[str]:
        response = await client.get("/api/cases", params=params)
        assert response.status_code == 200
        return [item["title"] for item in response.json()["items"]]

    assert await titles() == ["Phishing wave", "SSH brute force"]  # most recently changed first
    assert await titles(status=["closed"]) == ["SSH brute force"]
    assert await titles(assignee_id=owner.id) == ["SSH brute force"]
    assert await titles(unassigned=True) == ["Phishing wave"]
    assert await titles(q="phish") == ["Phishing wave"]
    assert await titles(severity=["critical"]) == []

    [summary] = (await client.get("/api/cases", params={"q": "phish"})).json()["items"]
    assert (summary["alert_count"], summary["open_alert_count"], summary["note_count"]) == (
        1,
        1,
        1,
    )


@pytest.mark.parametrize("path", ["", "/notes", "/evidence", "/alerts"])
async def test_missing_case_is_404(client: AsyncClient, path: str) -> None:
    if path:
        payload = {
            "/notes": {"body": "x"},
            "/evidence": {"event_id": 1},
            "/alerts": {"alert_ids": [1]},
        }
        response = await client.post(f"/api/cases/999999{path}", json=payload[path])
    else:
        response = await client.get("/api/cases/999999")
    assert response.status_code == 404
