"""Enqueueing background jobs.

The API and the folder watcher only need "please ingest job N"; hiding arq
behind :class:`JobQueue` keeps them testable without Redis.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Protocol

from arq.connections import ArqRedis

logger = logging.getLogger(__name__)

QUEUE_NAME = "watchpost:queue"
INGEST_FILE_JOB = "ingest_file"
DETECTION_JOB = "run_detection"
ENRICH_ALERTS_JOB = "enrich_alerts"
SWEEP_IOCS_JOB = "sweep_iocs"


class JobQueue(Protocol):
    """Something that can schedule background jobs."""

    async def enqueue_ingestion(self, job_id: int) -> None: ...

    async def enqueue_detection(self, run_id: int) -> None: ...

    async def enqueue_enrichment(self, alert_ids: Sequence[int]) -> None: ...

    async def enqueue_sweep(self, ioc_ids: Sequence[int] | None) -> None: ...


class ArqJobQueue:
    """:class:`JobQueue` backed by arq/Redis."""

    def __init__(self, redis: ArqRedis, queue_name: str = QUEUE_NAME) -> None:
        self._redis = redis
        self._queue_name = queue_name

    async def enqueue_ingestion(self, job_id: int) -> None:
        # A deterministic arq job ID means a job can never be queued twice.
        job = await self._redis.enqueue_job(
            INGEST_FILE_JOB,
            job_id,
            _job_id=f"ingest:{job_id}",
            _queue_name=self._queue_name,
        )
        if job is None:
            logger.info("Ingestion job %d is already queued", job_id)

    async def enqueue_detection(self, run_id: int) -> None:
        job = await self._redis.enqueue_job(
            DETECTION_JOB,
            run_id,
            _job_id=f"detect:{run_id}",
            _queue_name=self._queue_name,
        )
        if job is None:
            logger.info("Detection run %d is already queued", run_id)

    async def enqueue_enrichment(self, alert_ids: Sequence[int]) -> None:
        if alert_ids:
            await self._redis.enqueue_job(
                ENRICH_ALERTS_JOB, list(alert_ids), _queue_name=self._queue_name
            )

    async def enqueue_sweep(self, ioc_ids: Sequence[int] | None) -> None:
        """Match stored events against new indicators (``None``: all of them)."""
        await self._redis.enqueue_job(
            SWEEP_IOCS_JOB,
            list(ioc_ids) if ioc_ids is not None else None,
            _queue_name=self._queue_name,
        )
