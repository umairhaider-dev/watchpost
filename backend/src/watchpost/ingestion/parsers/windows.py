"""Parser for Windows event logs exported as JSON (Security, System and Sysmon).

One parser handles every channel because real exports are often mixed
(Winlogbeat ships Security and Sysmon in the same stream). Each record is
routed by its channel/provider: Sysmon events get ``log_source = sysmon``
and the Sysmon mapping, everything else ``windows_security``.
"""

from __future__ import annotations

from typing import Any, ClassVar

from watchpost.db.models import LogSource
from watchpost.events import NormalizedEvent
from watchpost.ingestion.parsers.base import JsonParser, build_event, canonical_json
from watchpost.ingestion.parsers.sysmon import map_sysmon_event
from watchpost.ingestion.parsers.windows_events import (
    extract_windows_event,
    looks_like_windows_event,
)
from watchpost.ingestion.parsers.windows_security import map_security_event
from watchpost.ingestion.readers import Sample


class WindowsEventParser(JsonParser):
    """Windows Security/System/Sysmon events in JSON (any common export shape)."""

    name: ClassVar[str] = "windows"
    label: ClassVar[str] = "Windows event log (JSON)"
    description: ClassVar[str] = (
        "Security, System and Sysmon events exported as JSON by Winlogbeat, "
        "EVTX converters, NXLog or PowerShell."
    )

    def parse_record(self, record: dict[str, Any]) -> NormalizedEvent:
        event = extract_windows_event(record)
        if event.is_sysmon:
            log_source = LogSource.SYSMON
            fields = map_sysmon_event(event)
        else:
            log_source = LogSource.WINDOWS_SECURITY
            fields = map_security_event(event)

        action = fields.get("event.action")
        fields["host.name"] = event.computer or self.context.default_host
        fields["event.code"] = str(event.event_id)
        fields["message"] = event.message or (
            f"{str(action).replace('_', ' ')} (event {event.event_id})"
            if action
            else f"Windows event {event.event_id}"
        )
        # Event data is stored under a fixed key so rules can reference fields
        # like TargetImage regardless of which tool produced the export.
        raw_event: dict[str, Any] = {
            "original": record,
            "event_data": event.data,
            "channel": event.channel,
            "provider": event.provider,
        }
        return build_event(
            timestamp=event.timestamp,
            log_source=log_source,
            raw_line=canonical_json(record),
            raw_event=raw_event,
            fields=fields,
        )

    @classmethod
    def sniff(cls, sample: Sample) -> float:
        if not sample.records:
            return 0.0
        hits = sum(1 for record in sample.records if looks_like_windows_event(record))
        return 0.95 * hits / len(sample.records)
