"""Reading Windows event log records exported as JSON.

Different tools export the same event in very different shapes. This module
recognises the common ones and reduces them to a single :class:`WindowsEvent`:

* **Winlogbeat / Elastic Agent**: ``{"@timestamp": ..., "winlog": {"event_id": ...,
  "channel": ..., "event_data": {...}}}``
* **EVTX converted to JSON** (``evtx_dump``, ``python-evtx`` + xmltodict):
  ``{"Event": {"System": {...}, "EventData": {...}}}``, with or without the
  outer ``Event`` key, and with ``Data`` lists of ``{"@Name", "#text"}``.
* **Flat exports** (NXLog, PowerShell ``Get-WinEvent`` piped to
  ``ConvertTo-Json``): ``EventID``/``Id``, ``TimeCreated``, ``Computer`` or
  ``MachineName`` at the top level, with event data either in an
  ``EventData`` object or as further top-level keys.

The mapping from event IDs to normalised fields lives in
:mod:`windows_security` and :mod:`sysmon`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from watchpost.ingestion.errors import ParseError
from watchpost.ingestion.values import clean_int, clean_str, parse_timestamp

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
SYSMON_PROVIDER = "microsoft-windows-sysmon"

_FLAT_ID_KEYS = ("EventID", "EventId", "event_id", "Id", "ID")
_FLAT_TIME_KEYS = (
    "TimeCreated",
    "EventTime",
    "TimeGenerated",
    "SystemTime",
    "@timestamp",
    "timestamp",
    "UtcTime",
)
_FLAT_COMPUTER_KEYS = ("Computer", "MachineName", "Hostname", "ComputerName", "host")
_FLAT_CHANNEL_KEYS = ("Channel", "LogName", "channel")
_FLAT_PROVIDER_KEYS = ("ProviderName", "SourceName", "Provider", "provider")
_FLAT_MESSAGE_KEYS = ("Message", "message")
_FLAT_KEYWORD_KEYS = ("KeywordsDisplayNames", "Keywords", "EventType")
# Keys that describe the record rather than the event, excluded when the
# event data is spread over the top level of a flat export.
_FLAT_SYSTEM_KEYS = frozenset(
    _FLAT_ID_KEYS
    + _FLAT_TIME_KEYS
    + _FLAT_COMPUTER_KEYS
    + _FLAT_CHANNEL_KEYS
    + _FLAT_PROVIDER_KEYS
    + _FLAT_MESSAGE_KEYS
    + _FLAT_KEYWORD_KEYS
    + (
        "Level",
        "LevelDisplayName",
        "Task",
        "TaskDisplayName",
        "Opcode",
        "OpcodeDisplayName",
        "RecordId",
        "RecordNumber",
        # NXLog's PID of the event log service. Not "ProcessId", which is event
        # data in 4688 (the creator process).
        "ProcessID",
        "ThreadID",
        "Version",
        "Qualifiers",
        "Properties",
        "ContainerLog",
        "MatchedQueryIds",
        "Bookmark",
        "ActivityId",
        "RelatedActivityId",
        "UserId",
        "Severity",
        "SeverityValue",
        "EventReceivedTime",
        "SourceModuleName",
        "SourceModuleType",
    )
)


@dataclass(frozen=True, slots=True)
class WindowsEvent:
    """The parts of a Windows event the mappings need, whatever the export shape."""

    event_id: int
    timestamp: datetime
    computer: str | None
    channel: str | None
    provider: str | None
    data: dict[str, Any]
    message: str | None
    keywords: tuple[str, ...]

    @property
    def is_sysmon(self) -> bool:
        return (self.channel or "").lower() == SYSMON_CHANNEL or (
            self.provider or ""
        ).lower() == SYSMON_PROVIDER

    @property
    def audit_outcome(self) -> str | None:
        """``success``/``failure`` from the Audit Success/Failure keyword, if present."""
        joined = " ".join(self.keywords).lower()
        if "audit failure" in joined:
            return "failure"
        if "audit success" in joined:
            return "success"
        return None

    def get(self, key: str) -> str | None:
        """An event data value as clean text."""
        return clean_str(self.data.get(key))


def extract_windows_event(record: dict[str, Any]) -> WindowsEvent:
    """Reduce any supported export shape to a :class:`WindowsEvent`.

    Raises:
        ParseError: if the record is not a recognisable Windows event.
    """
    winlog = record.get("winlog")
    if isinstance(winlog, dict):
        return _from_winlogbeat(record, winlog)
    event = record.get("Event")
    if isinstance(event, dict) and isinstance(event.get("System"), dict):
        return _from_xml_shape(event)
    if isinstance(record.get("System"), dict):
        return _from_xml_shape(record)
    if any(key in record for key in _FLAT_ID_KEYS):
        return _from_flat(record)
    msg = "not a Windows event (no winlog, Event.System or EventID field)"
    raise ParseError(msg)


def looks_like_windows_event(record: dict[str, Any]) -> bool:
    """Cheap check used for format detection."""
    try:
        extract_windows_event(record)
    except ParseError:
        return False
    return True


# --------------------------------------------------------------------------
# Shapes
# --------------------------------------------------------------------------


def _from_winlogbeat(record: dict[str, Any], winlog: dict[str, Any]) -> WindowsEvent:
    event_section = _section(record, "event")
    host_section = _section(record, "host")
    data: dict[str, Any] = {}
    for key in ("event_data", "user_data"):
        section = winlog.get(key)
        if isinstance(section, dict):
            data.update(section)
    keywords = winlog.get("keywords")
    return WindowsEvent(
        event_id=_event_id(winlog.get("event_id", event_section.get("code"))),
        timestamp=_timestamp(record.get("@timestamp")),
        computer=clean_str(winlog.get("computer_name")) or clean_str(host_section.get("name")),
        channel=clean_str(winlog.get("channel")),
        provider=clean_str(winlog.get("provider_name")),
        data=data,
        message=clean_str(record.get("message")),
        keywords=_keywords(keywords),
    )


def _from_xml_shape(event: dict[str, Any]) -> WindowsEvent:
    system: dict[str, Any] = event["System"]
    data: dict[str, Any] = {}
    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        data.update(_flatten_event_data(event_data))
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        # UserData wraps its fields in one element named after the event,
        # e.g. {"LogFileCleared": {"SubjectUserName": ...}}.
        inner = list(user_data.values())
        if len(inner) == 1 and isinstance(inner[0], dict):
            user_data = inner[0]
        data.update(_flatten_event_data(user_data))
    rendering = event.get("RenderingInfo")
    message = rendering.get("Message") if isinstance(rendering, dict) else None
    return WindowsEvent(
        event_id=_event_id(system.get("EventID")),
        timestamp=_timestamp(_attribute(system.get("TimeCreated"), "SystemTime")),
        computer=clean_str(system.get("Computer")),
        channel=clean_str(system.get("Channel")),
        provider=clean_str(_attribute(system.get("Provider"), "Name")),
        data=data,
        message=clean_str(message) or clean_str(event.get("Message")),
        keywords=_keywords(system.get("Keywords")),
    )


def _from_flat(record: dict[str, Any]) -> WindowsEvent:
    explicit = record.get("EventData")
    if isinstance(explicit, dict):
        data = _flatten_event_data(explicit)
    else:
        data = {
            key: value
            for key, value in record.items()
            if key not in _FLAT_SYSTEM_KEYS and not isinstance(value, dict | list)
        }
    return WindowsEvent(
        event_id=_event_id(_first(record, _FLAT_ID_KEYS)),
        timestamp=_timestamp(_first(record, _FLAT_TIME_KEYS)),
        computer=clean_str(_first(record, _FLAT_COMPUTER_KEYS)),
        channel=clean_str(_first(record, _FLAT_CHANNEL_KEYS)),
        provider=clean_str(_first(record, _FLAT_PROVIDER_KEYS)),
        data=data,
        message=clean_str(_first(record, _FLAT_MESSAGE_KEYS)),
        keywords=_keywords(_first(record, _FLAT_KEYWORD_KEYS)),
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _section(record: dict[str, Any], key: str) -> dict[str, Any]:
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


def _attribute(node: Any, name: str) -> Any:
    """Read an XML attribute in any of the JSON conventions converters use."""
    if not isinstance(node, dict):
        return node
    attributes = node.get("#attributes")
    if isinstance(attributes, dict) and name in attributes:
        return attributes[name]
    for key in (f"@{name}", name):
        if key in node:
            return node[key]
    return None


def _event_id(value: Any) -> int:
    if isinstance(value, dict):  # {"#text": 4625, "@Qualifiers": ""}
        value = value.get("#text", value.get("Value"))
    event_id = clean_int(value, maximum=65535)
    if event_id is None:
        msg = f"missing or invalid event ID: {value!r}"
        raise ParseError(msg)
    return event_id


def _timestamp(value: Any) -> datetime:
    if isinstance(value, dict):
        value = _attribute(value, "SystemTime")
    try:
        return parse_timestamp(value)
    except ValueError as exc:
        msg = f"missing or invalid event time: {value!r}"
        raise ParseError(msg) from exc


def _keywords(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, str):
        return (value,)
    return ()


def _flatten_event_data(section: dict[str, Any]) -> dict[str, Any]:
    """Turn ``{"Data": [{"@Name": "X", "#text": "v"}]}`` into ``{"X": "v"}``."""
    data = section.get("Data")
    if data is None:
        return {key: value for key, value in section.items() if not key.startswith(("@", "#"))}
    items = data if isinstance(data, list) else [data]
    flattened: dict[str, Any] = {}
    for position, item in enumerate(items):
        if isinstance(item, dict):
            name = item.get("@Name") or item.get("Name") or _attribute(item, "Name")
            value = item.get("#text", item.get("Value"))
            flattened[str(name) if name else f"Data{position}"] = value
        else:
            flattened[f"Data{position}"] = item
    return flattened
