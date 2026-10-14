"""ORM models. Importing this package registers every table on ``Base.metadata``."""

from watchpost.db.models.alert import OPEN_ALERT_STATUSES, Alert, alert_events
from watchpost.db.models.audit import AuditLog
from watchpost.db.models.case import Case, CaseEvidence, CaseNote
from watchpost.db.models.detection import DetectionRun
from watchpost.db.models.enums import (
    AlertStatus,
    CaseStatus,
    DetectionStatus,
    DetectionTrigger,
    EnrichmentStatus,
    EventCategory,
    EventOutcome,
    IngestOrigin,
    IngestStatus,
    IocType,
    LogSource,
    RuleOrigin,
    RuleType,
    Severity,
    UserRole,
)
from watchpost.db.models.event import Event
from watchpost.db.models.ingestion import IngestionJob
from watchpost.db.models.intel import EnrichmentCache, event_ioc_matches
from watchpost.db.models.ioc import Ioc
from watchpost.db.models.rule import Rule
from watchpost.db.models.user import User

__all__ = [
    "OPEN_ALERT_STATUSES",
    "Alert",
    "AlertStatus",
    "AuditLog",
    "Case",
    "CaseEvidence",
    "CaseNote",
    "CaseStatus",
    "DetectionRun",
    "DetectionStatus",
    "DetectionTrigger",
    "EnrichmentCache",
    "EnrichmentStatus",
    "Event",
    "EventCategory",
    "EventOutcome",
    "IngestOrigin",
    "IngestStatus",
    "IngestionJob",
    "Ioc",
    "IocType",
    "LogSource",
    "Rule",
    "RuleOrigin",
    "RuleType",
    "Severity",
    "User",
    "UserRole",
    "alert_events",
    "event_ioc_matches",
]
