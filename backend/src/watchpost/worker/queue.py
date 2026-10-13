"""Enqueueing background jobs.

The API and the folder watcher only need "please ingest job N"; hiding arq
behind :class:`JobQueue` keeps them testable without Redis.
"""

from __future__ import annotations

import logging
from typing import Protocol

from arq.connections import ArqRedis

logger = logging.getLogger(__name__)

QUEUE_NAME = "watchpost:queue"
INGEST_FILE_JOB = "ingest_file"


class JobQueue(Protocol):
    """Something that can schedule ingestion jobs."""

    async def enqueue_ingestion(self, job_id: int) -> None: ...


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
