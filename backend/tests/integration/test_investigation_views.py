from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_alert, make_event, store_events
from tests.integration.helpers import import_sample_feed
from watchpost.db.models import Alert, AlertStatus, Case, Rule, Severity, alert_events

START = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)


def at(minutes: float) -> datetime:
    return START + timedelta(minutes=minutes)


async def seed(session: AsyncSession) -> dict[str, int]:
    """A small story: a brute force on web-01, then the attacker logs in as backup."""
    events = {
        "fail_1": make_event("fail 1", timestamp=at(0), user={"name": "root"}),
        "fail_2": make_event("fail 2", timestamp=at(1), user={"name": "root"}),
        "success": make_event(
            "success",
            timestamp=at(5),
            user={"name": "backup"},
            event={"category": "authentication", "action": "ssh_login", "outcome": "success"},
        ),
        "sudo": make_event(
            "sudo",
            timestamp=at(8),
            source={},
            user={"name": "backup"},
            event={"category": "process", "action": "sudo", "outcome": "success"},
        ),
        "outbound": make_event(
            "outbound",
            timestamp=at(20),
            host={"name": "ws-fin-07"},
            source={"ip": "10.0.5.21"},
            destination={"ip": "203.0.113.45", "port": 443},
            user={"name": "carol"},
        ),
        "much_later": make_event("much later", timestamp=at(60 * 30), user={"name": "root"}),
        "other_host": make_event(
            "other host", timestamp=at(2), host={"name": "db-01"}, source={}, user={"name": "pg"}
        ),
    }
    ids = await store_events(session, *events.values())
    return dict(zip(events, ids, strict=True))


async def add_alert(session: AsyncSession, evidence: Sequence[int] = (), **fields: Any) -> int:
    alert = make_alert(**fields)
    session.add(alert)
    await session.flush()
    if evidence:
        await session.execute(
            insert(alert_events), [{"alert_id": alert.id, "event_id": e} for e in evidence]
        )
    return alert.id


# --------------------------------------------------------------------------
# Entities
# --------------------------------------------------------------------------


async def test_ip_profile(client: AsyncClient, db_session: AsyncSession) -> None:
    await seed(db_session)
    await import_sample_feed(db_session)
    alert_id = await add_alert(db_session, first_seen=at(0), last_seen=at(1))
    case = Case(title="Brute force", severity=Severity.MEDIUM)
    db_session.add(case)
    await db_session.flush()
    await db_session.execute(update(Alert).where(Alert.id == alert_id).values(case_id=case.id))

    response = await client.get("/api/entities/ip", params={"value": "203.0.113.45"})

    assert response.status_code == 200
    body = response.json()
    assert body["query"] == "ip:203.0.113.45"
    # The source of four events and the destination of one.
    assert body["event_count"] == 5
    assert body["first_seen"].startswith("2026-10-12T09:00")
    assert body["last_seen"].startswith("2026-10-13T")
    assert body["log_sources"] == [{"value": "linux_auth", "count": 5}]
    # One entry per day with activity.
    assert [day["count"] for day in body["activity"]] == [4, 1]
    assert body["related"]["users"][0] == {"value": "root", "count": 3}
    assert {item["value"] for item in body["related"]["hosts"]} == {"web-01", "ws-fin-07"}
    assert (body["alert_count"], body["open_alert_count"]) == (1, 1)
    assert [case["title"] for case in body["cases"]] == ["Brute force"]
    assert [ioc["value"] for ioc in body["intel"]] == ["203.0.113.45"]


async def test_user_and_host_profiles(client: AsyncClient, db_session: AsyncSession) -> None:
    await seed(db_session)
    await add_alert(db_session, host_name="WEB-01", user_name="backup")

    user = (await client.get("/api/entities/user", params={"value": "backup"})).json()
    assert user["query"] == 'user.name:"backup"'
    assert user["event_count"] == 2
    assert user["related"]["ips"] == [{"value": "203.0.113.45", "count": 1}]
    assert user["alert_count"] == 1

    host = (await client.get("/api/entities/host", params={"value": "web-01"})).json()
    assert host["event_count"] == 5  # events store the host as logged
    assert host["alert_count"] == 1  # alert host names match case-insensitively
    assert host["related"]["users"][0] == {"value": "root", "count": 3}


async def test_unknown_entity_is_empty(client: AsyncClient) -> None:
    body = (await client.get("/api/entities/user", params={"value": 'svc "odd"'})).json()

    assert body["event_count"] == 0
    assert body["first_seen"] is None
    assert body["activity"] == []
    assert body["related"] == {}
    assert body["query"] == 'user.name:"svc \\"odd\\""'


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/entities/ip", {"value": "not-an-ip"}),
        ("/api/entities/ip", {"value": "  "}),
        ("/api/entities/process", {"value": "x"}),
        ("/api/entities/user", {}),
    ],
)
async def test_invalid_entities(client: AsyncClient, path: str, params: dict[str, str]) -> None:
    assert (await client.get(path, params=params)).status_code == 422


# --------------------------------------------------------------------------
# Timeline
# --------------------------------------------------------------------------


async def test_alert_timeline(client: AsyncClient, db_session: AsyncSession) -> None:
    ids = await seed(db_session)
    alert_id = await add_alert(
        db_session,
        evidence=[ids["fail_1"], ids["fail_2"]],
        first_seen=at(0),
        last_seen=at(1),
        user_name="root",
    )

    body = (await client.get(f"/api/alerts/{alert_id}/timeline")).json()

    assert body["window_minutes"] == 30
    assert body["entities"] == {
        "host.name": "web-01",
        "source.ip": "203.0.113.45",
        "user.name": "root",
    }
    names = {event_id: name for name, event_id in ids.items()}
    timeline = [(names[event["id"]], event["is_evidence"]) for event in body["events"]]
    assert timeline == [
        ("fail_1", True),
        ("fail_2", True),
        ("success", False),
        ("sudo", False),
        ("outbound", False),  # the attacker's address as the destination
    ]
    assert body["truncated"] is False

    narrow = (
        await client.get(f"/api/alerts/{alert_id}/timeline", params={"window_minutes": 2})
    ).json()
    assert [names[event["id"]] for event in narrow["events"]] == ["fail_1", "fail_2"]


async def test_timeline_limits(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    ids = await seed(db_session)
    alert_id = await add_alert(db_session, first_seen=at(0), last_seen=at(1))
    lonely = await add_alert(
        db_session,
        evidence=[ids["other_host"]],
        host_name=None,
        source_ip=None,
        user_name=None,
        first_seen=at(2),
        last_seen=at(2),
    )
    monkeypatch.setattr("watchpost.investigation.timeline.MAX_TIMELINE_EVENTS", 2)

    capped = (await client.get(f"/api/alerts/{alert_id}/timeline")).json()
    assert len(capped["events"]) == 2
    assert capped["truncated"] is True

    only_evidence = (await client.get(f"/api/alerts/{lonely}/timeline")).json()
    assert only_evidence["entities"] == {}
    assert [event["id"] for event in only_evidence["events"]] == [ids["other_host"]]

    too_wide = await client.get(f"/api/alerts/{alert_id}/timeline", params={"window_minutes": 9999})
    assert too_wide.status_code == 422
    assert (await client.get("/api/alerts/999999/timeline")).status_code == 404


# --------------------------------------------------------------------------
# ATT&CK matrix
# --------------------------------------------------------------------------


def technique(body: dict[str, Any], tactic_id: str, technique_id: str) -> dict[str, Any] | None:
    [column] = [column for column in body["tactics"] if column["id"] == tactic_id]
    found = [cell for cell in column["techniques"] if cell["id"] == technique_id]
    return found[0] if found else None


@pytest.mark.usefixtures("rules")
async def test_attack_matrix(client: AsyncClient, db_session: AsyncSession) -> None:
    await add_alert(db_session, last_seen=at(5))
    await add_alert(db_session, status=AlertStatus.CLOSED, first_seen=at(-60 * 24 * 10))
    await add_alert(
        db_session,
        mitre_tactics=["TA0040"],
        mitre_techniques=["T1486"],  # in no rule and not in the reference data
        first_seen=at(-60 * 24 * 10),
        last_seen=at(-60 * 24 * 10),
    )
    await db_session.execute(
        update(Rule).where(Rule.id == "ssh-password-spraying").values(enabled=False)
    )

    body = (await client.get("/api/mitre/matrix")).json()

    assert [column["name"] for column in body["tactics"]][:3] == [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
    ]
    guessing = technique(body, "TA0006", "T1110.001")
    assert guessing is not None
    assert guessing["name"] == "Brute Force: Password Guessing"
    assert (guessing["alerts"], guessing["open_alerts"]) == (2, 1)
    assert "ssh-brute-force" in guessing["rules"]
    spraying = technique(body, "TA0006", "T1110.003")
    assert spraying is not None
    assert (spraying["enabled_rules"], spraying["alerts"]) == (0, 0)
    # Valid Accounts serves four tactics and appears under each.
    assert all(
        technique(body, tactic, "T1078") for tactic in ("TA0001", "TA0003", "TA0004", "TA0005")
    )
    unknown = technique(body, "TA0040", "T1486")
    assert unknown is not None
    assert (unknown["name"], unknown["alerts"], unknown["rules"]) == (None, 1, [])
    assert body["techniques_detected"] == 2
    assert body["techniques_covered"] >= 15

    recent = (await client.get("/api/mitre/matrix", params={"since": at(-60).isoformat()})).json()
    recent_guessing = technique(recent, "TA0006", "T1110.001")
    assert recent_guessing is not None
    assert recent_guessing["alerts"] == 1
    assert technique(recent, "TA0040", "T1486") is None
    assert recent["techniques_detected"] == 1
