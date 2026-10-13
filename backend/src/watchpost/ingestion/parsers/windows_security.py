"""Normalised fields for Windows Security (and a few System) log events.

``user.name`` is the account the event is *about*: the account logging on
for logon events, the new or changed account for account management, the
added member for group changes, and the acting account (``SubjectUserName``)
for process creation, task, service and audit events. The other account is
always still available in the stored event data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from watchpost.db.models import EventCategory, EventOutcome
from watchpost.ingestion.parsers.windows_events import WindowsEvent
from watchpost.ingestion.values import basename, clean_int, clean_ip, clean_port

UserRole = Literal["target", "subject", "member", "none"]

_AUTH = EventCategory.AUTHENTICATION
_IAM = EventCategory.IAM
_CONFIG = EventCategory.CONFIGURATION
_PROCESS = EventCategory.PROCESS
_SUCCESS = EventOutcome.SUCCESS
_FAILURE = EventOutcome.FAILURE


@dataclass(frozen=True, slots=True)
class _Spec:
    category: EventCategory
    action: str
    outcome: EventOutcome | None
    user: UserRole
    has_source_ip: bool = False
    status_outcome: bool = False  # outcome comes from the Status field (0x0 = success)


_SPECS: dict[int, _Spec] = {
    # Logon / logoff
    4624: _Spec(_AUTH, "logon", _SUCCESS, "target", has_source_ip=True),
    4625: _Spec(_AUTH, "logon", _FAILURE, "target", has_source_ip=True),
    4634: _Spec(_AUTH, "logoff", _SUCCESS, "target"),
    4647: _Spec(_AUTH, "logoff", _SUCCESS, "target"),
    4648: _Spec(_AUTH, "explicit_credential_logon", _SUCCESS, "subject", has_source_ip=True),
    4672: _Spec(_IAM, "special_privileges_assigned", _SUCCESS, "subject"),
    # Kerberos / NTLM
    4768: _Spec(_AUTH, "kerberos_tgt_request", None, "target", True, status_outcome=True),
    4769: _Spec(
        _AUTH, "kerberos_service_ticket_request", None, "target", True, status_outcome=True
    ),
    4771: _Spec(_AUTH, "kerberos_preauth_failed", _FAILURE, "target", has_source_ip=True),
    4776: _Spec(_AUTH, "ntlm_credential_validation", None, "target", status_outcome=True),
    # Account management
    4720: _Spec(_IAM, "user_created", _SUCCESS, "target"),
    4722: _Spec(_IAM, "user_enabled", _SUCCESS, "target"),
    4723: _Spec(_IAM, "password_change_attempt", None, "target"),
    4724: _Spec(_IAM, "password_reset", None, "target"),
    4725: _Spec(_IAM, "user_disabled", _SUCCESS, "target"),
    4726: _Spec(_IAM, "user_deleted", _SUCCESS, "target"),
    4738: _Spec(_IAM, "user_changed", _SUCCESS, "target"),
    4740: _Spec(_IAM, "account_locked_out", _SUCCESS, "target"),
    4767: _Spec(_IAM, "account_unlocked", _SUCCESS, "target"),
    4728: _Spec(_IAM, "user_added_to_group", _SUCCESS, "member"),
    4732: _Spec(_IAM, "user_added_to_group", _SUCCESS, "member"),
    4756: _Spec(_IAM, "user_added_to_group", _SUCCESS, "member"),
    4729: _Spec(_IAM, "user_removed_from_group", _SUCCESS, "member"),
    4733: _Spec(_IAM, "user_removed_from_group", _SUCCESS, "member"),
    4757: _Spec(_IAM, "user_removed_from_group", _SUCCESS, "member"),
    # Processes, services, tasks
    4688: _Spec(_PROCESS, "process_created", _SUCCESS, "subject"),
    4689: _Spec(_PROCESS, "process_terminated", _SUCCESS, "subject"),
    4697: _Spec(_CONFIG, "service_installed", _SUCCESS, "subject"),
    7045: _Spec(_CONFIG, "service_installed", _SUCCESS, "none"),
    4698: _Spec(_CONFIG, "scheduled_task_created", _SUCCESS, "subject"),
    4699: _Spec(_CONFIG, "scheduled_task_deleted", _SUCCESS, "subject"),
    4700: _Spec(_CONFIG, "scheduled_task_enabled", _SUCCESS, "subject"),
    4701: _Spec(_CONFIG, "scheduled_task_disabled", _SUCCESS, "subject"),
    4702: _Spec(_CONFIG, "scheduled_task_updated", _SUCCESS, "subject"),
    # Audit and policy
    1102: _Spec(_CONFIG, "audit_log_cleared", _SUCCESS, "subject"),
    104: _Spec(_CONFIG, "log_cleared", _SUCCESS, "subject"),
    4719: _Spec(_CONFIG, "audit_policy_changed", _SUCCESS, "subject"),
    4657: _Spec(EventCategory.REGISTRY, "registry_value_modified", _SUCCESS, "subject"),
    4663: _Spec(EventCategory.FILE, "object_access_attempt", _SUCCESS, "subject"),
    5140: _Spec(EventCategory.NETWORK, "network_share_accessed", _SUCCESS, "subject", True),
    5145: _Spec(EventCategory.NETWORK, "network_share_checked", None, "subject", True),
}


def map_security_event(event: WindowsEvent) -> dict[str, Any]:
    """Normalised fields for a Security/System channel event."""
    spec = _SPECS.get(event.event_id)
    if spec is None:
        # Unknown event ID: keep whichever account is present.
        return {"user.name": event.get("TargetUserName") or event.get("SubjectUserName")}

    fields: dict[str, Any] = {
        "event.category": spec.category,
        "event.action": spec.action,
        "event.outcome": _outcome(event, spec),
        "user.name": _user(event, spec.user),
    }
    if spec.has_source_ip:
        fields["source.ip"] = clean_ip(event.data.get("IpAddress"))
        fields["source.port"] = clean_port(event.data.get("IpPort"))
    if event.event_id == 4688:
        fields.update(_process_creation(event))
    elif event.event_id == 4689:
        executable = event.get("ProcessName")
        fields["process.executable"] = executable
        fields["process.name"] = basename(executable)
        fields["process.pid"] = clean_int(event.data.get("ProcessId"))
    return fields


def _outcome(event: WindowsEvent, spec: _Spec) -> EventOutcome | None:
    audit = event.audit_outcome
    if audit is not None:
        return EventOutcome(audit)
    if spec.status_outcome:
        status = (event.get("Status") or "").lower()
        if status:
            return _SUCCESS if status in {"0x0", "0"} else _FAILURE
    return spec.outcome


def _user(event: WindowsEvent, role: UserRole) -> str | None:
    if role == "target":
        return event.get("TargetUserName")
    if role == "subject":
        return event.get("SubjectUserName")
    if role == "member":
        return event.get("MemberName") or event.get("MemberSid")
    return None


def _process_creation(event: WindowsEvent) -> dict[str, Any]:
    executable = event.get("NewProcessName")
    return {
        "process.executable": executable,
        "process.name": basename(executable),
        "process.pid": clean_int(event.data.get("NewProcessId")),
        "process.command_line": event.get("CommandLine"),
        "process.parent.name": basename(event.get("ParentProcessName")),
        "process.parent.pid": clean_int(event.data.get("ProcessId")),
    }
