"""Normalised fields for Sysmon (Microsoft-Windows-Sysmon/Operational) events.

For events with a source and a target process (CreateRemoteThread,
ProcessAccess), the *source* is mapped to ``process.*`` because that is the
actor; the target (for example ``lsass.exe``) stays in the event data as
``TargetImage``, which is where detection rules look for it.
"""

from __future__ import annotations

from typing import Any

from watchpost.db.models import EventCategory
from watchpost.ingestion.parsers.windows_events import WindowsEvent
from watchpost.ingestion.values import basename, clean_int, clean_ip, clean_port, split_account

_ACTIONS: dict[int, tuple[EventCategory, str]] = {
    1: (EventCategory.PROCESS, "process_created"),
    2: (EventCategory.FILE, "file_creation_time_changed"),
    3: (EventCategory.NETWORK, "network_connection"),
    5: (EventCategory.PROCESS, "process_terminated"),
    6: (EventCategory.DRIVER, "driver_loaded"),
    7: (EventCategory.PROCESS, "image_loaded"),
    8: (EventCategory.PROCESS, "remote_thread_created"),
    9: (EventCategory.FILE, "raw_disk_access"),
    10: (EventCategory.PROCESS, "process_access"),
    11: (EventCategory.FILE, "file_created"),
    12: (EventCategory.REGISTRY, "registry_key_created_or_deleted"),
    13: (EventCategory.REGISTRY, "registry_value_set"),
    14: (EventCategory.REGISTRY, "registry_key_renamed"),
    15: (EventCategory.FILE, "file_stream_created"),
    17: (EventCategory.FILE, "pipe_created"),
    18: (EventCategory.FILE, "pipe_connected"),
    22: (EventCategory.NETWORK, "dns_query"),
    23: (EventCategory.FILE, "file_deleted"),
    25: (EventCategory.PROCESS, "process_tampering"),
    26: (EventCategory.FILE, "file_delete_logged"),
}

# Events whose acting process is described by SourceImage/SourceProcessId.
_SOURCE_PROCESS_EVENTS = frozenset({8, 10})


def map_sysmon_event(event: WindowsEvent) -> dict[str, Any]:
    """Normalised fields for a Sysmon event."""
    category, action = _ACTIONS.get(event.event_id, (None, None))
    user, _domain = split_account(event.data.get("User") or event.data.get("SourceUser"))
    fields: dict[str, Any] = {
        "event.category": category,
        "event.action": action,
        "user.name": user,
    }

    if event.event_id in _SOURCE_PROCESS_EVENTS:
        image = event.get("SourceImage")
        fields["process.pid"] = clean_int(event.data.get("SourceProcessId"))
    else:
        image = event.get("Image")
        fields["process.pid"] = clean_int(event.data.get("ProcessId"))
    fields["process.executable"] = image
    fields["process.name"] = basename(image)

    if event.event_id == 1:
        fields["process.command_line"] = event.get("CommandLine")
        fields["process.parent.name"] = basename(event.get("ParentImage"))
        fields["process.parent.pid"] = clean_int(event.data.get("ParentProcessId"))
    elif event.event_id == 3:
        fields["source.ip"] = clean_ip(event.data.get("SourceIp"))
        fields["source.port"] = clean_port(event.data.get("SourcePort"))
        fields["destination.ip"] = clean_ip(event.data.get("DestinationIp"))
        fields["destination.port"] = clean_port(event.data.get("DestinationPort"))
    return fields
