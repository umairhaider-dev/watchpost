from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import DEFAULT_TIME, make_alert
from watchpost.accounts import create_user
from watchpost.db.models import Alert, AlertStatus, Severity, User, UserRole
from watchpost.investigation.triage import ReopenConflictError, assign, set_status

PASSWORD = "correct-horse-battery"


async def add_alerts(session: AsyncSession, *alerts: Alert) -> list[Alert]:
    session.add_all(alerts)
    await session.flush()
    return list(alerts)


async def analyst(session: AsyncSession, name: str = "analyst.one") -> User:
    return await create_user(session, username=name, password=PASSWORD, role=UserRole.ANALYST)


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------


async def test_resolving_and_reopening_track_resolved_at(db_session: AsyncSession) -> None:
    [alert] = await add_alerts(db_session, make_alert())

    assert await set_status(db_session, alert, AlertStatus.TRUE_POSITIVE, actor=None)
    resolved_at = alert.resolved_at
    assert resolved_at is not None

    # Moving between end states keeps the original resolution time.
    assert await set_status(db_session, alert, AlertStatus.CLOSED, actor=None)
    assert alert.resolved_at == resolved_at
    assert not await set_status(db_session, alert, AlertStatus.CLOSED, actor=None)

    assert await set_status(db_session, alert, AlertStatus.INVESTIGATING, actor=None)
    assert alert.resolved_at is None


async def test_reopening_refuses_a_second_open_alert(db_session: AsyncSession) -> None:
    closed, newer = await add_alerts(
        db_session,
        make_alert(group_key="ssh|203.0.113.45", status=AlertStatus.CLOSED),
        make_alert(group_key="ssh|203.0.113.45"),
    )

    with pytest.raises(ReopenConflictError) as caught:
        await set_status(db_session, closed, AlertStatus.NEW, actor=None)

    assert caught.value.open_alert_id == newer.id
    assert closed.status is AlertStatus.CLOSED


async def test_assignment_is_recorded(db_session: AsyncSession) -> None:
    [alert] = await add_alerts(db_session, make_alert())
    owner = await analyst(db_session)

    assert await assign(db_session, alert, owner, actor=None)
    assert not await assign(db_session, alert, owner, actor=None)
    assert alert.assignee_id == owner.id
    assert await assign(db_session, alert, None, actor=None)
    assert alert.assignee_id is None


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


async def test_filters(client: AsyncClient, db_session: AsyncSession) -> None:
    owner = await analyst(db_session)
    day = timedelta(days=1)
    alerts = await add_alerts(
        db_session,
        make_alert(title="SSH brute force", severity=Severity.MEDIUM, host_name="WEB-01"),
        make_alert(
            title="LSASS memory read",
            severity=Severity.CRITICAL,
            host_name="ws-fin-07",
            source_ip=None,
            user_name="carol",
            mitre_techniques=["T1003.001"],
            assignee_id=owner.id,
            first_seen=DEFAULT_TIME + day,
            last_seen=DEFAULT_TIME + day,
        ),
        make_alert(
            title="SQL injection attempt",
            severity=Severity.HIGH,
            host_name="shop-01",
            source_ip="198.51.100.23",
            status=AlertStatus.FALSE_POSITIVE,
            first_seen=DEFAULT_TIME + 2 * day,
            last_seen=DEFAULT_TIME + 2 * day,
        ),
    )
    brute, lsass, sqli = (alert.id for alert in alerts)

    async def ids(**params: str | int | bool | list[str]) -> list[int]:
        response = await client.get("/api/alerts", params=params)
        assert response.status_code == 200, response.text
        return [item["id"] for item in response.json()["items"]]

    assert await ids(host="web-01") == [brute]  # host names are case-insensitive
    assert await ids(source_ip="198.51.100.23") == [sqli]
    assert await ids(user="carol") == [lsass]
    assert await ids(technique="t1003.001") == [lsass]
    assert await ids(assignee_id=owner.id) == [lsass]
    assert sorted(await ids(unassigned=True)) == sorted([brute, sqli])
    assert sorted(await ids(status=["new"])) == sorted([brute, lsass])
    assert await ids(q="injection") == [sqli]
    assert await ids(since=(DEFAULT_TIME + 2 * day).isoformat()) == [sqli]
    assert await ids(until=(DEFAULT_TIME + timedelta(hours=1)).isoformat()) == [brute]
    assert await ids(sort="severity") == [lsass, sqli, brute]
    assert await ids(sort="first_seen") == [sqli, lsass, brute]
    bad = await client.get("/api/alerts", params={"source_ip": "not-an-ip"})
    assert bad.status_code == 422


async def test_update_status_and_assignee(client: AsyncClient, db_session: AsyncSession) -> None:
    [alert] = await add_alerts(db_session, make_alert())
    owner = await analyst(db_session)
    url = f"/api/alerts/{alert.id}"

    taken = await client.patch(url, json={"status": "investigating", "assignee_id": owner.id})
    assert taken.status_code == 200
    assert (taken.json()["status"], taken.json()["assignee_id"]) == ("investigating", owner.id)

    resolved = (await client.patch(url, json={"status": "true_positive"})).json()
    assert resolved["resolved_at"] is not None
    assert resolved["assignee_id"] == owner.id  # untouched when not given

    unassigned = (await client.patch(url, json={"assignee_id": None})).json()
    assert unassigned["assignee_id"] is None

    detail = (await client.get(url)).json()
    assert [entry["action"] for entry in detail["activity"]] == [
        "alert.assigned",
        "alert.status_changed",
        "alert.status_changed",
        "alert.assigned",
    ]
    assert detail["activity"][1]["details"] == {"from": "new", "to": "investigating"}


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "give a status or an assignee_id"),
        ({"status": None}, "status cannot be null"),
        ({"status": "done"}, "Input should be"),
        ({"assignee_id": 999_999}, "no active user"),
    ],
)
async def test_invalid_updates(
    client: AsyncClient, db_session: AsyncSession, payload: dict[str, object], message: str
) -> None:
    [alert] = await add_alerts(db_session, make_alert())

    response = await client.patch(f"/api/alerts/{alert.id}", json=payload)

    assert response.status_code == 422
    assert message in response.text


async def test_reopen_conflict_is_409(client: AsyncClient, db_session: AsyncSession) -> None:
    closed, newer = await add_alerts(
        db_session,
        make_alert(group_key="dup", status=AlertStatus.CLOSED),
        make_alert(group_key="dup"),
    )

    response = await client.patch(f"/api/alerts/{closed.id}", json={"status": "new"})

    assert response.status_code == 409
    assert f"alert {newer.id} is already open" in response.json()["detail"]
    assert (await client.patch("/api/alerts/999999", json={"status": "new"})).status_code == 404


async def test_bulk_update(client: AsyncClient, db_session: AsyncSession) -> None:
    owner = await analyst(db_session)
    first, second, closed, _newer = await add_alerts(
        db_session,
        make_alert(),
        make_alert(status=AlertStatus.INVESTIGATING, assignee_id=owner.id),
        make_alert(group_key="dup", status=AlertStatus.CLOSED),
        make_alert(group_key="dup"),
    )

    response = await client.post(
        "/api/alerts/bulk",
        json={
            "alert_ids": [first.id, second.id, closed.id, 999_999, first.id],
            "status": "investigating",
            "assignee_id": owner.id,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["updated"] == [first.id]
    assert body["unchanged"] == [second.id]
    assert body["missing"] == [999_999]
    assert body["conflicts"] == [{"alert_id": closed.id, "open_alert_id": _newer.id}]
    first_id, second_id, owner_id = first.id, second.id, owner.id
    db_session.expire_all()
    refreshed = await db_session.get(Alert, first_id)
    assert refreshed is not None
    assert (refreshed.status, refreshed.assignee_id) == (AlertStatus.INVESTIGATING, owner_id)

    resolved = await client.post(
        "/api/alerts/bulk", json={"alert_ids": [first_id, second_id], "status": "false_positive"}
    )
    assert resolved.json()["updated"] == [first_id, second_id]
    too_many = await client.post(
        "/api/alerts/bulk", json={"alert_ids": list(range(1, 502)), "status": "closed"}
    )
    assert too_many.status_code == 422
    assert (await client.post("/api/alerts/bulk", json={"alert_ids": [1]})).status_code == 422


async def test_resolved_time_is_reported(client: AsyncClient, db_session: AsyncSession) -> None:
    [alert] = await add_alerts(db_session, make_alert())
    before = datetime.now(UTC)

    body = (await client.patch(f"/api/alerts/{alert.id}", json={"status": "closed"})).json()

    assert datetime.fromisoformat(body["resolved_at"]) >= before - timedelta(seconds=5)
