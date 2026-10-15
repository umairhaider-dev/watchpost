"""Putting lines from overlapping activities into time order.

An activity (an SSH session, a shop visit) schedules several lines spread
over minutes or hours, and many activities overlap. :class:`Timeline` keeps
the scheduled lines in a heap and releases them in timestamp order once the
generator's clock has passed them, so memory stays proportional to the
number of open activities rather than the size of the file.
"""

from __future__ import annotations

import heapq
import itertools
from collections.abc import Iterator
from typing import TextIO


class Timeline:
    """Scheduled lines for one log file."""

    def __init__(self) -> None:
        self._heap: list[tuple[float, int, str, bool]] = []
        self._order = itertools.count()

    def add(self, timestamp: float, line: str, *, fixed: bool = False) -> None:
        """Schedule ``line``. Fixed lines (attack scenarios) are always written."""
        heapq.heappush(self._heap, (timestamp, next(self._order), line, fixed))

    def __len__(self) -> int:
        return len(self._heap)

    def due(self, until: float) -> Iterator[tuple[float, str, bool]]:
        """Remove and yield the lines scheduled at or before ``until``, oldest first."""
        heap = self._heap
        while heap and heap[0][0] <= until:
            timestamp, _, line, fixed = heapq.heappop(heap)
            yield timestamp, line, fixed

    def drain(self) -> Iterator[tuple[float, str, bool]]:
        """Remove and yield everything that is left, oldest first."""
        return self.due(float("inf"))


class LogWriter:
    """Writes lines to a file and counts them, dropping exact repeats.

    Two identical lines in the same second (a health check firing twice)
    would be one event after deduplication, so they are not written at all;
    that keeps the line count equal to the number of events stored.
    """

    def __init__(self, handle: TextIO) -> None:
        self._handle = handle
        self._second = -1
        self._seen: set[str] = set()
        self.count = 0
        self.last_timestamp = 0.0

    def write(self, timestamp: float, line: str) -> bool:
        second = int(timestamp)
        if second != self._second:
            self._second = second
            self._seen.clear()
        if line in self._seen:
            return False
        self._seen.add(line)
        self._handle.write(line)
        self._handle.write("\n")
        self.count += 1
        self.last_timestamp = max(self.last_timestamp, timestamp)
        return True
