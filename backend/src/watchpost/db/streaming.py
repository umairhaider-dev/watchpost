"""Reading large result sets without loading them into memory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import Select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

DEFAULT_CHUNK_SIZE = 5_000


async def stream_rows(
    session_factory: async_sessionmaker[AsyncSession],
    query: Select[Any],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> AsyncIterator[list[dict[str, Any]]]:
    """Yield query results as lists of dicts, ``chunk_size`` rows at a time.

    Uses a server-side cursor in its own session. Callers that write while
    iterating should collect what they need and write afterwards, so the
    cursor's connection is never asked to do two things at once.
    """
    async with session_factory() as session:
        result = await session.stream(query.execution_options(yield_per=chunk_size))
        async for partition in result.partitions(chunk_size):
            yield [dict(row._mapping) for row in partition]
