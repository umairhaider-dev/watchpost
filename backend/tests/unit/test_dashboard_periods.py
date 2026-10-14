from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from watchpost.dashboard import MAX_BUCKETS, Period, bucket_for_span, floor_time

HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


@pytest.mark.parametrize(
    ("moment", "bucket", "expected"),
    [
        (datetime(2026, 10, 12, 9, 41, 7, tzinfo=UTC), HOUR, datetime(2026, 10, 12, 9, tzinfo=UTC)),
        (
            datetime(2026, 10, 12, 9, 41, tzinfo=UTC),
            6 * HOUR,
            datetime(2026, 10, 12, 6, tzinfo=UTC),
        ),
        (datetime(2026, 10, 12, 23, 59, tzinfo=UTC), DAY, datetime(2026, 10, 12, tzinfo=UTC)),
        (datetime(2026, 10, 12, tzinfo=UTC), DAY, datetime(2026, 10, 12, tzinfo=UTC)),
    ],
)
def test_floor_time_aligns_to_utc_boundaries(
    moment: datetime, bucket: timedelta, expected: datetime
) -> None:
    assert floor_time(moment, bucket) == expected


@pytest.mark.parametrize(
    ("span", "bucket"),
    [
        (12 * HOUR, HOUR),
        (2 * DAY, HOUR),
        (5 * DAY, 6 * HOUR),
        (10 * DAY, 6 * HOUR),
        (30 * DAY, DAY),
        (100 * DAY, 7 * DAY),
        (400 * DAY, 7 * DAY),
        (3000 * DAY, 30 * DAY),
        (100_000 * DAY, 30 * DAY),
    ],
)
def test_bucket_size_keeps_charts_readable(span: timedelta, bucket: timedelta) -> None:
    assert bucket_for_span(span) == bucket


def test_buckets_cover_the_period_and_keep_the_latest() -> None:
    end = datetime(2026, 10, 12, 9, 30, tzinfo=UTC)
    day = Period(start=end - DAY, end=end, bucket=HOUR, origin=end - DAY)

    buckets = day.buckets()

    assert len(buckets) == 25
    assert buckets[0] == datetime(2026, 10, 11, 9, tzinfo=UTC)
    assert buckets[-1] == datetime(2026, 10, 12, 9, tzinfo=UTC)

    long = Period(start=None, end=end, bucket=HOUR, origin=end - 300 * HOUR)
    capped = long.buckets()
    assert len(capped) == MAX_BUCKETS
    assert capped[-1] == datetime(2026, 10, 12, 9, tzinfo=UTC)
