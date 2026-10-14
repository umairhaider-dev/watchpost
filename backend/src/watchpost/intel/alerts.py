"""Enriching alerts with what is known about their indicators.

The indicators of an alert are its source IP plus the IPs, domains and
hashes found in its evidence events. Each is checked against the local
indicator store and, when providers are configured and the indicator is
public, looked up online. The outcome is stored on the alert::

    {
      "enriched_at": "2026-10-14T09:00:00+00:00",
      "verdict": "malicious",
      "pending": false,
      "indicators": [
        {"type": "ip", "value": "203.0.113.45", "fields": ["source.ip"],
         "verdict": "malicious", "shared": false,
         "intel": [{"id": 1, "source": "...", "confidence": 85, ...}],
         "providers": [{"provider": "abuseipdb", "status": "ok", ...}]}
      ]
    }

``pending`` is true when a lookup was postponed by a rate limit; the
``enrich_pending`` worker job retries those alerts later.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import OPEN_ALERT_STATUSES, Alert, Event, Ioc, IocType, alert_events
from watchpost.intel.enrichment import Enricher, LookupStatus
from watchpost.intel.indicators import parent_domains
from watchpost.intel.matching import Observed, extract_indicators
from watchpost.intel.providers import Verdict, shareable, worst

logger = logging.getLogger(__name__)

MAX_INDICATORS_PER_ALERT = 10
MAX_EVIDENCE_SCANNED = 50
# A local indicator below this confidence only makes an indicator suspicious.
CONFIDENT_INTEL = 50

_EVENTS = Event.__table__
Key = tuple[IocType, str]


async def alert_indicators(session: AsyncSession, alert: Alert) -> dict[Key, list[str]]:
    """Indicators involved in an alert, with the fields they were seen in."""
    found: dict[Key, list[str]] = {}

    def add(observed: Observed) -> None:
        fields = found.setdefault((observed.ioc_type, observed.value), [])
        if observed.field not in fields:
            fields.append(observed.field)

    if alert.source_ip:
        add(Observed(IocType.IP, str(alert.source_ip), "source.ip"))
    rows = await session.execute(
        select(_EVENTS)
        .join(alert_events, alert_events.c.event_id == _EVENTS.c.id)
        .where(alert_events.c.alert_id == alert.id)
        .order_by(_EVENTS.c.timestamp)
        .limit(MAX_EVIDENCE_SCANNED)
    )
    for row in rows.mappings():
        for observed in extract_indicators(dict(row)):
            add(observed)
    return found


def intel_summary(ioc: Ioc) -> dict[str, Any]:
    """The parts of a local indicator worth showing next to an alert."""
    return {
        "id": ioc.id,
        "type": ioc.ioc_type.value,
        "value": ioc.value,
        "source": ioc.source,
        "description": ioc.description,
        "confidence": ioc.confidence,
        "tags": list(ioc.tags),
    }


def intel_verdict(ioc: Ioc) -> Verdict:
    if ioc.confidence is not None and ioc.confidence < CONFIDENT_INTEL:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


async def local_intel(session: AsyncSession, keys: Iterable[Key]) -> dict[Key, list[Ioc]]:
    """Active local indicators matching each key (a domain also matches its parents)."""
    wanted: dict[Key, list[Key]] = {}
    for ioc_type, value in keys:
        if ioc_type is IocType.DOMAIN:
            wanted[ioc_type, value] = [(IocType.DOMAIN, d) for d in parent_domains(value)]
        else:
            wanted[ioc_type, value] = [(ioc_type, value)]
    by_type: dict[IocType, set[str]] = {}
    for candidates in wanted.values():
        for ioc_type, value in candidates:
            by_type.setdefault(ioc_type, set()).add(value)
    if not by_type:
        return {}

    iocs = await session.scalars(
        select(Ioc).where(
            Ioc.is_active.is_(True),
            or_(Ioc.expires_at.is_(None), Ioc.expires_at > datetime.now(UTC)),
            or_(
                *(
                    and_(Ioc.ioc_type == ioc_type, Ioc.value.in_(sorted(values)))
                    for ioc_type, values in by_type.items()
                )
            ),
        )
    )
    stored = {(ioc.ioc_type, ioc.value): ioc for ioc in iocs}
    return {
        key: [stored[candidate] for candidate in candidates if candidate in stored]
        for key, candidates in wanted.items()
    }


def prioritised(found: dict[Key, list[str]], intel: dict[Key, list[Ioc]]) -> list[Key]:
    """Known-bad indicators first, then the source IP, then the rest in the order seen."""
    keys = list(found)
    keys.sort(key=lambda key: (not intel.get(key), "source.ip" not in found[key]))
    return keys[:MAX_INDICATORS_PER_ALERT]


async def enrich_alert(
    enricher: Enricher, alert_id: int, *, refresh: bool = False
) -> dict[str, Any] | None:
    """Build and store the enrichment for one alert; ``None`` if it does not exist."""
    async with enricher.session_factory() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            return None
        found = await alert_indicators(session, alert)
        intel = await local_intel(session, found)

    indicators = []
    indicator_verdicts = []
    pending = False
    for key in prioritised(found, intel):
        ioc_type, value = key
        lookups = await enricher.lookup(ioc_type, value, refresh=refresh)
        pending = pending or any(r.status is LookupStatus.RATE_LIMITED for r in lookups)
        matches = intel.get(key, [])
        verdicts = [intel_verdict(ioc) for ioc in matches] + [r.verdict for r in lookups]
        indicator_verdicts.append(worst(verdicts))
        indicators.append(
            {
                "type": ioc_type.value,
                "value": value,
                "fields": found[key],
                "verdict": indicator_verdicts[-1].value,
                "shared": shareable(ioc_type, value),
                "intel": [intel_summary(ioc) for ioc in matches],
                "providers": [result.as_dict() for result in lookups],
            }
        )

    enrichment = {
        "enriched_at": datetime.now(UTC).isoformat(),
        "verdict": worst(indicator_verdicts).value,
        "pending": pending,
        "online": enricher.online,
        "indicators": indicators,
    }
    async with enricher.session_factory() as session:
        await session.execute(
            update(Alert).where(Alert.id == alert_id).values(enrichment=enrichment)
        )
        await session.commit()
    return enrichment


@dataclass(slots=True)
class EnrichSummary:
    enriched: int = 0
    pending: int = 0
    missing: int = 0


async def enrich_alerts(enricher: Enricher, alert_ids: Sequence[int]) -> EnrichSummary:
    """Enrich several alerts, each in its own transactions."""
    summary = EnrichSummary()
    for alert_id in alert_ids:
        enrichment = await enrich_alert(enricher, alert_id)
        if enrichment is None:
            summary.missing += 1
            continue
        summary.enriched += 1
        if enrichment["pending"]:
            summary.pending += 1
    logger.info(
        "Enriched %d alerts (%d waiting on rate limits, %d missing)",
        summary.enriched,
        summary.pending,
        summary.missing,
    )
    return summary


async def pending_alert_ids(session: AsyncSession, limit: int = 50) -> list[int]:
    """Open alerts with lookups postponed by a rate limit, oldest first."""
    rows = await session.scalars(
        select(Alert.id)
        .where(
            Alert.enrichment["pending"].as_boolean().is_(True),
            Alert.status.in_(OPEN_ALERT_STATUSES),
        )
        .order_by(Alert.updated_at)
        .limit(limit)
    )
    return list(rows)
