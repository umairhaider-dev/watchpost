from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from watchpost.events import NormalizedEvent
from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.parsers import ParseContext, WindowsEventParser
from watchpost.ingestion.parsers.windows_events import extract_windows_event
from watchpost.ingestion.readers import Sample

BS = chr(92)


def win(*parts: str) -> str:
    """Build a Windows path without backslash escapes in the test source."""
    return BS.join(parts)


SYSTEM32 = win("C:", "Windows", "System32")
TIME = "2026-10-12T09:15:10.5000000Z"
EXPECTED_TIME = datetime(2026, 10, 12, 9, 15, 10, 500000, tzinfo=UTC)


def parse(record: dict[str, Any], context: ParseContext) -> NormalizedEvent:
    return WindowsEventParser(context).parse_record(record)


def flat_record(event_id: int, data: dict[str, Any], **extra: Any) -> dict[str, Any]:
    record = {
        "EventID": event_id,
        "TimeCreated": TIME,
        "Computer": "DC01.corp.example.local",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventData": data,
    }
    record.update(extra)
    return record


FAILED_LOGON_DATA = {
    "TargetUserName": "administrator",
    "TargetDomainName": "CORP",
    "LogonType": "3",
    "IpAddress": "203.0.113.80",
    "IpPort": "51234",
    "Status": "0xc000006d",
}


# ------------------------------------------------------------- export shapes


def test_flat_export_with_event_data(context: ParseContext) -> None:
    event = parse(flat_record(4625, FAILED_LOGON_DATA), context)
    flat = event.flatten()

    assert event.log_source == "windows_security"
    assert event.timestamp == EXPECTED_TIME
    assert flat["host.name"] == "DC01.corp.example.local"
    assert flat["event.code"] == "4625"
    assert flat["event.category"] == "authentication"
    assert flat["event.action"] == "logon"
    assert flat["event.outcome"] == "failure"
    assert flat["user.name"] == "administrator"
    assert flat["source.ip"] == "203.0.113.80"
    assert flat["source.port"] == 51234
    assert event.raw_event["event_data"]["LogonType"] == "3"
    assert event.raw_event["channel"] == "Security"


def test_winlogbeat_shape(context: ParseContext) -> None:
    record = {
        "@timestamp": TIME,
        "message": "An account failed to log on.",
        "event": {"code": "4625", "provider": "Microsoft-Windows-Security-Auditing"},
        "host": {"name": "dc01"},
        "winlog": {
            "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "event_id": "4625",
            "computer_name": "DC01.corp.example.local",
            "keywords": ["Audit Failure"],
            "event_data": FAILED_LOGON_DATA,
        },
    }

    event = parse(record, context)

    assert event.event.code == "4625"
    assert event.message == "An account failed to log on."
    assert event.flatten()["user.name"] == "administrator"
    assert event.raw_event["original"] == record


def test_evtx_json_shape_with_attributes(context: ParseContext) -> None:
    record = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": 4624,
                "TimeCreated": {"#attributes": {"SystemTime": TIME}},
                "Channel": "Security",
                "Computer": "DC01",
                "Keywords": "0x8020000000000000",
            },
            "EventData": {
                "TargetUserName": "jsmith",
                "IpAddress": "::ffff:10.0.5.21",
                "LogonType": 3,
            },
        }
    }

    event = parse(record, context)

    assert event.flatten()["event.outcome"] == "success"
    assert event.flatten()["source.ip"] == "10.0.5.21"
    assert event.host.name == "DC01"


def test_xmltodict_shape_with_data_list(context: ParseContext) -> None:
    record = {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"},
            "EventID": {"#text": "4720", "@Qualifiers": ""},
            "TimeCreated": {"@SystemTime": TIME},
            "Channel": "Security",
            "Computer": "DC01",
        },
        "EventData": {
            "Data": [
                {"@Name": "TargetUserName", "#text": "helpdesk-svc"},
                {"@Name": "SubjectUserName", "#text": "administrator"},
                {"#text": "unnamed value"},
            ]
        },
    }

    event = parse(record, context)

    assert event.flatten()["event.action"] == "user_created"
    assert event.flatten()["user.name"] == "helpdesk-svc"
    assert event.raw_event["event_data"]["Data2"] == "unnamed value"


def test_powershell_export_with_dotnet_date_and_top_level_data(context: ParseContext) -> None:
    record = {
        "Id": 4688,
        "TimeCreated": "/Date(1791798060000)/",
        "MachineName": "WS-FIN-07",
        "LogName": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "KeywordsDisplayNames": ["Audit Success"],
        "Message": "A new process has been created.",
        "Properties": [{"Value": "ignored"}],
        "SubjectUserName": "jsmith",
        "NewProcessName": win(SYSTEM32, "cmd.exe"),
        "NewProcessId": "0x1a2c",
        "ProcessId": "0x0f10",
        "CommandLine": "cmd.exe /c whoami",
        "ParentProcessName": win("C:", "Windows", "explorer.exe"),
    }

    event = parse(record, context)
    flat = event.flatten()

    assert event.timestamp == datetime(2026, 10, 12, 9, 41, tzinfo=UTC)
    assert flat["process.name"] == "cmd.exe"
    assert flat["process.pid"] == 0x1A2C
    assert flat["process.parent.name"] == "explorer.exe"
    assert flat["process.parent.pid"] == 0x0F10
    assert flat["process.command_line"] == "cmd.exe /c whoami"
    assert flat["user.name"] == "jsmith"
    assert "Properties" not in event.raw_event["event_data"]


def test_userdata_is_unwrapped_for_log_cleared(context: ParseContext) -> None:
    record = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Eventlog"}},
                "EventID": 1102,
                "TimeCreated": {"#attributes": {"SystemTime": TIME}},
                "Channel": "Security",
                "Computer": "DC01",
            },
            "UserData": {"LogFileCleared": {"SubjectUserName": "administrator"}},
        }
    }

    event = parse(record, context)

    assert event.flatten()["event.action"] == "audit_log_cleared"
    assert event.flatten()["user.name"] == "administrator"


@pytest.mark.parametrize(
    "record",
    [
        {"hello": "world"},
        {"EventID": "abc", "TimeCreated": TIME},
        {"EventID": 4625},
        {"EventID": 4625, "TimeCreated": "not a time"},
        {"winlog": {"channel": "Security"}, "@timestamp": TIME},
        {"Event": {"System": {"EventID": 1}}},
    ],
)
def test_unusable_records_raise(record: dict[str, Any], context: ParseContext) -> None:
    with pytest.raises(ParseError):
        parse(record, context)


# ------------------------------------------------------------- Security mapping


@pytest.mark.parametrize(
    ("event_id", "data", "action", "category", "user"),
    [
        (4624, {"TargetUserName": "jsmith"}, "logon", "authentication", "jsmith"),
        (4634, {"TargetUserName": "jsmith"}, "logoff", "authentication", "jsmith"),
        (
            4648,
            {"SubjectUserName": "svc", "TargetUserName": "x"},
            "explicit_credential_logon",
            "authentication",
            "svc",
        ),
        (
            4672,
            {"SubjectUserName": "administrator"},
            "special_privileges_assigned",
            "iam",
            "administrator",
        ),
        (4720, {"TargetUserName": "new", "SubjectUserName": "admin"}, "user_created", "iam", "new"),
        (4726, {"TargetUserName": "old"}, "user_deleted", "iam", "old"),
        (4740, {"TargetUserName": "jsmith"}, "account_locked_out", "iam", "jsmith"),
        (
            4732,
            {"MemberName": "-", "MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators"},
            "user_added_to_group",
            "iam",
            "S-1-5-21-1",
        ),
        (
            4728,
            {"MemberName": "CN=Eve,DC=corp", "TargetUserName": "Domain Admins"},
            "user_added_to_group",
            "iam",
            "CN=Eve,DC=corp",
        ),
        (
            4698,
            {"SubjectUserName": "administrator", "TaskName": win("", "Updater")},
            "scheduled_task_created",
            "configuration",
            "administrator",
        ),
        (
            4697,
            {"SubjectUserName": "administrator", "ServiceName": "x"},
            "service_installed",
            "configuration",
            "administrator",
        ),
        (
            7045,
            {"ServiceName": "PSEXESVC", "ImagePath": "x"},
            "service_installed",
            "configuration",
            None,
        ),
        (
            1102,
            {"SubjectUserName": "administrator"},
            "audit_log_cleared",
            "configuration",
            "administrator",
        ),
        (
            4719,
            {"SubjectUserName": "administrator"},
            "audit_policy_changed",
            "configuration",
            "administrator",
        ),
    ],
)
def test_security_event_mapping(
    event_id: int,
    data: dict[str, Any],
    action: str,
    category: str,
    user: str | None,
    context: ParseContext,
) -> None:
    flat = parse(flat_record(event_id, data), context).flatten()

    assert flat["event.action"] == action
    assert flat["event.category"] == category
    assert flat.get("user.name") == user


@pytest.mark.parametrize(
    ("event_id", "status", "outcome"),
    [
        (4768, "0x0", "success"),
        (4768, "0x6", "failure"),
        (4776, "0xc000006a", "failure"),
        (4769, "0", "success"),
    ],
)
def test_status_based_outcome(
    event_id: int, status: str, outcome: str, context: ParseContext
) -> None:
    flat = parse(
        flat_record(event_id, {"TargetUserName": "jsmith", "Status": status}), context
    ).flatten()

    assert flat["event.outcome"] == outcome


def test_audit_keyword_overrides_default_outcome(context: ParseContext) -> None:
    record = flat_record(4624, {"TargetUserName": "jsmith"}, Keywords=["Audit Failure"])

    assert parse(record, context).flatten()["event.outcome"] == "failure"


def test_process_terminated(context: ParseContext) -> None:
    record = flat_record(
        4689,
        {
            "SubjectUserName": "jsmith",
            "ProcessName": win(SYSTEM32, "notepad.exe"),
            "ProcessId": "0x10",
        },
    )

    flat = parse(record, context).flatten()

    assert flat["process.name"] == "notepad.exe"
    assert flat["process.pid"] == 16


def test_unknown_event_id_keeps_basics(context: ParseContext) -> None:
    event = parse(flat_record(5156, {"SubjectUserName": "svc"}), context)
    flat = event.flatten()

    assert flat["event.code"] == "5156"
    assert "event.action" not in flat
    assert flat["user.name"] == "svc"
    assert event.message == "Windows event 5156"


def test_default_message_describes_the_action(context: ParseContext) -> None:
    event = parse(flat_record(4720, {"TargetUserName": "x"}), context)

    assert event.message == "user created (event 4720)"


def test_default_host_used_when_computer_missing() -> None:
    context = ParseContext(reference_time=datetime(2026, 10, 13, tzinfo=UTC), default_host="dc02")
    record = flat_record(4624, {"TargetUserName": "x"})
    del record["Computer"]

    assert parse(record, context).host.name == "dc02"


# ------------------------------------------------------------- Sysmon


def sysmon(event_id: int, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}},
                "EventID": event_id,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-10-12T09:31:40.250Z"}},
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "Computer": "WS-FIN-07",
            },
            "EventData": data,
        }
    }


POWERSHELL = win(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")


def test_sysmon_process_create(context: ParseContext) -> None:
    event = parse(
        sysmon(
            1,
            {
                "ProcessId": 4412,
                "Image": POWERSHELL,
                "CommandLine": "powershell.exe -enc SQBFAFgA",
                "User": win("CORP", "jsmith"),
                "ParentProcessId": 3020,
                "ParentImage": win("C:", "Program Files", "Office", "WINWORD.EXE"),
            },
        ),
        context,
    )
    flat = event.flatten()

    assert event.log_source == "sysmon"
    assert flat["event.action"] == "process_created"
    assert flat["event.category"] == "process"
    assert flat["process.name"] == "powershell.exe"
    assert flat["process.executable"] == POWERSHELL
    assert flat["process.pid"] == 4412
    assert flat["process.parent.name"] == "WINWORD.EXE"
    assert flat["process.parent.pid"] == 3020
    assert flat["user.name"] == "jsmith"
    assert "event.outcome" not in flat


def test_sysmon_network_connection(context: ParseContext) -> None:
    flat = parse(
        sysmon(
            3,
            {
                "Image": POWERSHELL,
                "ProcessId": "4412",
                "SourceIp": "10.0.5.21",
                "SourcePort": "52811",
                "DestinationIp": "203.0.113.99",
                "DestinationPort": "443",
            },
        ),
        context,
    ).flatten()

    assert flat["event.action"] == "network_connection"
    assert flat["source.ip"] == "10.0.5.21"
    assert flat["destination.ip"] == "203.0.113.99"
    assert flat["destination.port"] == 443


def test_sysmon_process_access_maps_source_as_actor(context: ParseContext) -> None:
    lsass = win(SYSTEM32, "lsass.exe")
    event = parse(
        sysmon(
            10,
            {
                "SourceImage": win("C:", "Temp", "m.exe"),
                "SourceProcessId": 5120,
                "TargetImage": lsass,
                "GrantedAccess": "0x1010",
                "SourceUser": win("CORP", "jsmith"),
            },
        ),
        context,
    )
    flat = event.flatten()

    assert flat["event.action"] == "process_access"
    assert flat["process.name"] == "m.exe"
    assert flat["process.pid"] == 5120
    assert flat["user.name"] == "jsmith"
    assert event.raw_event["event_data"]["TargetImage"] == lsass


@pytest.mark.parametrize(
    ("event_id", "action", "category"),
    [
        (11, "file_created", "file"),
        (13, "registry_value_set", "registry"),
        (22, "dns_query", "network"),
        (8, "remote_thread_created", "process"),
        (6, "driver_loaded", "driver"),
    ],
)
def test_sysmon_event_types(
    event_id: int, action: str, category: str, context: ParseContext
) -> None:
    flat = parse(sysmon(event_id, {"Image": POWERSHELL}), context).flatten()

    assert flat["event.action"] == action
    assert flat["event.category"] == category


def test_unknown_sysmon_event(context: ParseContext) -> None:
    event = parse(sysmon(255, {}), context)

    assert event.log_source == "sysmon"
    assert "event.action" not in event.flatten()


def test_sysmon_detected_by_channel_only() -> None:
    record = {"EventID": 1, "TimeCreated": TIME, "Channel": "Microsoft-Windows-Sysmon/Operational"}

    assert extract_windows_event(record).is_sysmon


def test_sniff_prefers_windows_records() -> None:
    windows = Sample(lines=[], records=[flat_record(4624, {})] * 4)
    other = Sample(lines=[], records=[{"timestamp": TIME, "msg": "hi"}])

    assert WindowsEventParser.sniff(windows) == pytest.approx(0.95)
    assert WindowsEventParser.sniff(other) == 0
    assert WindowsEventParser.sniff(Sample(lines=[], records=[])) == 0
