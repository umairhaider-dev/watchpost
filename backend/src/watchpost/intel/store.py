"""Writing indicators to the local IOC store."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Result, func, literal_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from watchpost.db.models import Ioc
from watchpost.intel.feeds import FeedEntry

logger = logging.getLogger(__name__)

_BATCH = 1000


@dataclass(slots=True)
class ImportResult:
    created: int = 0
    updated: int = 0
    ioc_ids: list[int] = field(default_factory=list)


async def upsert_iocs(
    session: AsyncSession,
    entries: Sequence[FeedEntry],
    *,
    source: str,
    default_confidence: int | None = None,
    extra_tags: Sequence[str] = (),
    expires_at: datetime | None = None,
) -> ImportResult:
    """Insert new indicators and refresh existing ones. Flushes, does not commit.

    Re-importing a feed reactivates its indicators and replaces their
    description, confidence, tags and expiry with the feed's values (keeping
    the old description or confidence when the feed has none).
    """
    result = ImportResult()
    tags_extra = sorted({tag.strip().lower() for tag in extra_tags if tag.strip()})
    for start in range(0, len(entries), _BATCH):
        rows: list[dict[str, Any]] = [
            {
                "ioc_type": entry.ioc_type,
                "value": entry.value,
                "source": (entry.source or source)[:128],
                "description": entry.description,
                "confidence": entry.confidence
                if entry.confidence is not None
                else default_confidence,
                "tags": sorted(set(entry.tags) | set(tags_extra)),
                "is_active": True,
                "expires_at": entry.expires_at or expires_at,
            }
            for entry in entries[start : start + _BATCH]
        ]
        insert = pg_insert(Ioc).values(rows)
        upsert = insert.on_conflict_do_update(
            index_elements=[Ioc.ioc_type, Ioc.value],
            set_={
                "source": insert.excluded.source,
                "description": func.coalesce(insert.excluded.description, Ioc.description),
                "confidence": func.coalesce(insert.excluded.confidence, Ioc.confidence),
                "tags": insert.excluded.tags,
                "is_active": True,
                "expires_at": insert.excluded.expires_at,
                "updated_at": func.now(),
            },
        )
        returned: Result[int, bool] = await session.execute(
            upsert.returning(Ioc.id, literal_column("xmax = 0").label("created"))
        )
        for ioc_id, created in returned:
            result.ioc_ids.append(ioc_id)
            if created:
                result.created += 1
            else:
                result.updated += 1
    await session.flush()
    logger.info(
        "Imported %d indicators from %s: %d new, %d updated",
        len(entries),
        source,
        result.created,
        result.updated,
    )
    return result
