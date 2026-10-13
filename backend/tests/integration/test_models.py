from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tests.factories import make_event
from watchpost.db.base import Base
from watchpost.db.models import (
    OPEN_ALERT_STATUSES,
    Alert,
    AlertStatus,
    AuditLog,
    Case,
    CaseNote,
    CaseStatus,
    Event,
    Ioc,
    IocType,
    Rule,
    RuleType,
    Severity,
    User,
    UserRole,
    alert_events,
)

NOW = datetime(2026, 3, 14, 10, 0, tzinfo=UTC)


async def _user(session: AsyncSession, username: str = "analyst1") -> User:
    user = User(username=username, password_hash="hash", role=UserRole.ANALYST)
    session.add(user)
    await session.flush()
    return user


async def _rule(session: AsyncSession, rule_id: str = "ssh-brute-force") -> Rule:
    rule = Rule(
        id=rule_id,
        title="SSH brute force",
        severity=Severity.HIGH,
        rule_type=RuleType.THRESHOLD,
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1110.001"],
        definition={"threshold": {"count": 10}},
        source_yaml="id: ssh-brute-force\n",
    )
    session.add(rule)
    await session.flush()
    return rule


async def _alert(session: AsyncSession, group_key: str = "ssh:203.0.113.45", **kw: object) -> Alert:
    alert = Alert(
        title="SSH brute force from 203.0.113.45",
        severity=Severity.HIGH,
        group_key=group_key,
        first_seen=NOW,
        last_seen=NOW,
        **kw,
    )
    session.add(alert)
    await session.flush()
    return alert


async def test_user_defaults(db_session: AsyncSession) -> None:
    user = User(username="viewer1", password_hash="hash")
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    assert user.role is UserRole.VIEWER
    assert user.is_active is True
    assert user.created_at is not None
    assert user.last_login_at is None


async def test_username_is_unique(db_session: AsyncSession) -> None:
    await _user(db_session, "dup")
    db_session.add(User(username="dup", password_hash="hash"))

    with pytest.raises(IntegrityError):
        await db_session.flush()


async def test_role_check_constraint_rejects_unknown_values(db_session: AsyncSession) -> None:
    with pytest.raises(IntegrityError, match="ck_users_user_role"):
        await db_session.execute(
            text("INSERT INTO users (username, password_hash, role) VALUES ('x', 'h', 'root')")
        )


async def test_event_round_trip_preserves_values(db_session: AsyncSession) -> None:
    normalized = make_event(
        raw_line="roundtrip",
        destination={"ip": "2001:db8::10", "port": 22},
        raw_event={"line": "roundtrip", "nested": {"pid": 4120, "tags": ["a", "b"]}},
    )
    await db_session.execute(insert(Event), [normalized.to_row()])

    stored = await db_session.scalar(select(Event).where(Event.event_hash == normalized.event_hash))

    assert stored is not None
    assert stored.source_ip == "203.0.113.45"
    assert stored.destination_ip == "2001:db8::10"
    assert stored.timestamp == normalized.timestamp
    assert stored.raw_event == {"line": "roundtrip", "nested": {"pid": 4120, "tags": ["a", "b"]}}
    assert stored.ioc_matched is False
    assert stored.ingested_at is not None


async def test_duplicate_event_hash_is_skipped_with_on_conflict(db_session: AsyncSession) -> None:
    rows = [make_event(raw_line="same").to_row(), make_event(raw_line="same").to_row()]
    stmt = pg_insert(Event).on_conflict_do_nothing(index_elements=["event_hash"])

    await db_session.execute(stmt, rows[:1])
    await db_session.execute(stmt, rows[1:])

    count = await db_session.scalar(
        select(text("count(*)")).select_from(Event).where(Event.event_hash == rows[0]["event_hash"])
    )
    assert count == 1


async def test_alert_links_to_rule_case_and_events(db_session: AsyncSession) -> None:
    rule = await _rule(db_session)
    owner = await _user(db_session)
    case = Case(title="Brute force on web-01", severity=Severity.HIGH, assignee_id=owner.id)
    db_session.add(case)
    await db_session.flush()
    alert = await _alert(db_session, rule_id=rule.id, case_id=case.id, assignee_id=owner.id)

    event_ids = list(
        (
            await db_session.scalars(
                insert(Event).returning(Event.id),
                [make_event(raw_line=f"line {n}").to_row() for n in range(3)],
            )
        ).all()
    )
    await db_session.execute(
        insert(alert_events), [{"alert_id": alert.id, "event_id": eid} for eid in event_ids]
    )

    loaded = await db_session.scalar(
        select(Alert)
        .where(Alert.id == alert.id)
        .options(selectinload(Alert.events), selectinload(Alert.rule), selectinload(Alert.case))
    )

    assert loaded is not None
    assert loaded.status is AlertStatus.NEW
    assert loaded.rule is not None and loaded.rule.mitre_techniques == ["T1110.001"]
    assert loaded.case is not None and loaded.case.title == "Brute force on web-01"
    assert sorted(event.id for event in loaded.events) == sorted(event_ids)
    assert loaded.enrichment == {}


async def test_only_one_open_alert_per_group_key(db_session: AsyncSession) -> None:
    await _alert(db_session, group_key="dup-key")

    with pytest.raises(IntegrityError, match="uq_alerts_open_group_key"):
        async with db_session.begin_nested():
            await _alert(db_session, group_key="dup-key")


async def test_closed_alert_allows_new_alert_for_same_group(db_session: AsyncSession) -> None:
    first = await _alert(db_session, group_key="reopen-key")
    first.status = AlertStatus.CLOSED
    await db_session.flush()

    second = await _alert(db_session, group_key="reopen-key")

    assert second.id != first.id


def test_open_status_tuple_matches_partial_index() -> None:
    assert set(OPEN_ALERT_STATUSES) == {status for status in AlertStatus if status.is_open}
    alerts_table = Base.metadata.tables["alerts"]
    index = next(ix for ix in alerts_table.indexes if ix.name == "uq_alerts_open_group_key")
    where = str(index.dialect_options["postgresql"]["where"])
    for status in OPEN_ALERT_STATUSES:
        assert f"'{status.value}'" in where


async def test_deleting_rule_keeps_alert(db_session: AsyncSession) -> None:
    rule = await _rule(db_session, "to-delete")
    alert = await _alert(db_session, group_key="orphan", rule_id=rule.id)

    await db_session.delete(rule)
    await db_session.flush()
    await db_session.refresh(alert)

    assert alert.rule_id is None


async def test_deleting_case_removes_notes_and_unlinks_alerts(db_session: AsyncSession) -> None:
    author = await _user(db_session)
    case = Case(title="Phishing", severity=Severity.MEDIUM, created_by_id=author.id)
    db_session.add(case)
    await db_session.flush()
    db_session.add(CaseNote(case_id=case.id, author_id=author.id, body="Initial triage"))
    alert = await _alert(db_session, group_key="case-delete", case_id=case.id)
    await db_session.flush()

    await db_session.execute(text("DELETE FROM cases WHERE id = :id"), {"id": case.id})
    await db_session.refresh(alert)
    notes = await db_session.scalar(
        select(text("count(*)")).select_from(CaseNote).where(CaseNote.case_id == case.id)
    )

    assert alert.case_id is None
    assert notes == 0


async def test_case_notes_are_ordered_by_creation(db_session: AsyncSession) -> None:
    case = Case(title="Ordering", severity=Severity.LOW)
    db_session.add(case)
    await db_session.flush()
    for body in ("first", "second"):
        db_session.add(CaseNote(case_id=case.id, body=body))
        await db_session.flush()

    loaded = await db_session.scalar(
        select(Case).where(Case.id == case.id).options(selectinload(Case.notes))
    )

    assert loaded is not None
    assert loaded.status is CaseStatus.OPEN
    assert [note.body for note in loaded.notes] == ["first", "second"]


async def test_ioc_type_and_value_are_unique(db_session: AsyncSession) -> None:
    db_session.add(Ioc(ioc_type=IocType.IP, value="198.51.100.7", tags=["scanner"]))
    await db_session.flush()
    db_session.add(Ioc(ioc_type=IocType.IP, value="198.51.100.7"))

    with pytest.raises(IntegrityError, match="uq_iocs_ioc_type_value"):
        await db_session.flush()


async def test_same_value_allowed_for_different_ioc_types(db_session: AsyncSession) -> None:
    db_session.add_all(
        [
            Ioc(ioc_type=IocType.DOMAIN, value="evil.example"),
            Ioc(ioc_type=IocType.IP, value="evil.example"),
        ]
    )
    await db_session.flush()


async def test_ioc_confidence_must_be_a_percentage(db_session: AsyncSession) -> None:
    db_session.add(Ioc(ioc_type=IocType.SHA256, value="a" * 64, confidence=150))

    with pytest.raises(IntegrityError, match="ck_iocs_confidence_range"):
        await db_session.flush()


async def test_audit_log_survives_user_deletion(db_session: AsyncSession) -> None:
    user = await _user(db_session, "leaver")
    entry = AuditLog(
        user_id=user.id,
        username=user.username,
        action="alert.status_change",
        target_type="alert",
        target_id="42",
        details={"from": "new", "to": "investigating"},
        ip_address="192.168.10.5",
    )
    db_session.add(entry)
    await db_session.flush()

    await db_session.delete(user)
    await db_session.flush()
    await db_session.refresh(entry)

    assert entry.user_id is None
    assert entry.username == "leaver"
    assert entry.ip_address == "192.168.10.5"
    assert entry.details == {"from": "new", "to": "investigating"}
    assert entry.occurred_at is not None


async def test_rule_array_columns_default_to_empty(db_session: AsyncSession) -> None:
    rule = Rule(
        id="minimal",
        title="Minimal",
        severity=Severity.LOW,
        rule_type=RuleType.MATCH,
        definition={},
        source_yaml="id: minimal\n",
    )
    db_session.add(rule)
    await db_session.flush()
    await db_session.refresh(rule)

    assert rule.false_positives == []
    assert rule.references == []
    assert rule.enabled is True
    assert rule.version == 1


async def test_reprs_are_informative(db_session: AsyncSession) -> None:
    rule = await _rule(db_session, "repr-rule")
    user = await _user(db_session, "repr-user")
    alert = await _alert(db_session, group_key="repr")
    case = Case(title="Repr", severity=Severity.LOW)
    db_session.add(case)
    await db_session.flush()
    note = CaseNote(case_id=case.id, body="x")
    ioc = Ioc(ioc_type=IocType.MD5, value="d41d8cd98f00b204e9800998ecf8427e")
    audit = AuditLog(action="auth.login", username="repr-user")
    db_session.add_all([note, ioc, audit])
    await db_session.flush()
    await db_session.execute(insert(Event), [make_event(raw_line="repr").to_row()])
    event = await db_session.scalar(select(Event).limit(1))

    assert "repr-rule" in repr(rule)
    assert "repr-user" in repr(user)
    assert "status=new" in repr(alert)
    assert "Repr" in repr(case)
    assert f"case_id={case.id}" in repr(note)
    assert "d41d8cd98f00b204e9800998ecf8427e" in repr(ioc)
    assert "auth.login" in repr(audit)
    assert event is not None and "linux_auth" in repr(event)
