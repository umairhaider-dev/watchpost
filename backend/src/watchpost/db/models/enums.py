"""Enumerations shared by models, API schemas and the detection engine."""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    """Access level of a platform user.

    Viewers read everything; analysts also triage, investigate, ingest and
    manage threat intel; admins also edit rules and manage users.
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @property
    def rank(self) -> int:
        return {UserRole.VIEWER: 0, UserRole.ANALYST: 1, UserRole.ADMIN: 2}[self]

    def allows(self, required: UserRole) -> bool:
        """Whether this role includes everything ``required`` may do."""
        return self.rank >= required.rank


class Severity(StrEnum):
    """Severity scale shared by rules, alerts and cases (Sigma levels)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric ordering, higher is more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RuleType(StrEnum):
    """How a detection rule evaluates events."""

    MATCH = "match"  # single-event Sigma-style selection
    THRESHOLD = "threshold"  # N matching events within a window, grouped by a field
    SEQUENCE = "sequence"  # event A followed by event B from the same entity
    NEW_VALUE = "new_value"  # a value not seen for this entity during a lookback period


class RuleOrigin(StrEnum):
    """Where a rule came from."""

    BUILTIN = "builtin"  # shipped with the platform as a YAML file
    CUSTOM = "custom"  # created through the API or UI


class DetectionTrigger(StrEnum):
    """Why a detection run was started."""

    INGESTION = "ingestion"  # new events arrived from an ingestion job
    MANUAL = "manual"  # an analyst asked to scan a time range
    INTEL = "intel"  # new indicators matched events that were already stored


class DetectionStatus(StrEnum):
    """Lifecycle of a detection run."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertStatus(StrEnum):
    """Triage state of an alert."""

    NEW = "new"
    INVESTIGATING = "investigating"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"

    @property
    def is_open(self) -> bool:
        """Open alerts still absorb new hits for the same group key."""
        return self in {AlertStatus.NEW, AlertStatus.INVESTIGATING}


class CaseStatus(StrEnum):
    """Lifecycle state of an investigation case."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IocType(StrEnum):
    """Kinds of indicators of compromise kept in the local store."""

    IP = "ip"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class EnrichmentStatus(StrEnum):
    """Outcome of an external enrichment lookup, as cached."""

    OK = "ok"
    NOT_FOUND = "not_found"  # the provider has no record of the indicator
    ERROR = "error"


class IngestOrigin(StrEnum):
    """How a file reached the ingestion pipeline."""

    UPLOAD = "upload"
    WATCH_FOLDER = "watch_folder"


class IngestStatus(StrEnum):
    """Lifecycle of an ingestion job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    @property
    def is_finished(self) -> bool:
        """True once the job will not change any more."""
        return self in {IngestStatus.COMPLETED, IngestStatus.FAILED}


class LogSource(StrEnum):
    """Parser that produced an event."""

    LINUX_AUTH = "linux_auth"
    WINDOWS_SECURITY = "windows_security"
    SYSMON = "sysmon"
    WEB_ACCESS = "web_access"
    JSON = "json"


class EventOutcome(StrEnum):
    """ECS ``event.outcome`` values."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class EventCategory(StrEnum):
    """Subset of ECS ``event.category`` values relevant to the supported sources."""

    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    DRIVER = "driver"
    FILE = "file"
    HOST = "host"
    IAM = "iam"
    INTRUSION_DETECTION = "intrusion_detection"
    MALWARE = "malware"
    NETWORK = "network"
    PROCESS = "process"
    REGISTRY = "registry"
    SESSION = "session"
    WEB = "web"
