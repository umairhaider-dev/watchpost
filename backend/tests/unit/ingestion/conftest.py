from __future__ import annotations

from datetime import UTC, datetime

import pytest

from watchpost.ingestion.parsers import ParseContext

REFERENCE_TIME = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


@pytest.fixture
def context() -> ParseContext:
    return ParseContext(reference_time=REFERENCE_TIME)
