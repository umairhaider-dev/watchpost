"""Writing a set of realistic log files with attacks hidden among normal activity.

:func:`generate` writes four log files (Linux ``auth.log``, a web
``access.log``, the Windows Security log and Sysmon, both as JSON lines), a
threat-intel feed with the attackers' infrastructure (``iocs.csv``) and a
manifest (``scenarios.json``) describing each planted attack and the rules
that should catch it.

The output is deterministic for a given seed, event count, span and end time,
and the event count is exact: every line parses into one event and no two
lines are duplicates.
"""

from __future__ import annotations

import json
import logging
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from watchpost.datagen.normal import (
    AUTH_ACTIVITIES,
    SYSMON_ACTIVITIES,
    WEB_ACTIVITIES,
    WINDOWS_ACTIVITIES,
    Activity,
    activity_level,
    admin_logon,
    nightly_backup,
)
from watchpost.datagen.scenarios import (
    ACCESS_LOG,
    AUTH_LOG,
    SYSMON_LOG,
    WINDOWS_LOG,
    Scenario,
    indicator_feed,
    plant_scenarios,
)
from watchpost.datagen.timeline import LogWriter, Timeline

logger = logging.getLogger(__name__)

MIN_EVENTS = 2_000
MAX_DAYS = 90
FEED_FILE = "iocs.csv"
MANIFEST_FILE = "scenarios.json"
# Activities stop this long before the end so that sessions they open close in time.
_TAIL_SECONDS = 75 * 60


@dataclass(frozen=True, slots=True)
class LogFileSpec:
    name: str
    parser: str
    share: float
    activities: Sequence[tuple[Activity, float]]


LOG_FILES: tuple[LogFileSpec, ...] = (
    LogFileSpec(AUTH_LOG, "linux_auth", 0.25, AUTH_ACTIVITIES),
    LogFileSpec(ACCESS_LOG, "web_access", 0.45, WEB_ACTIVITIES),
    LogFileSpec(WINDOWS_LOG, "windows", 0.20, WINDOWS_ACTIVITIES),
    LogFileSpec(SYSMON_LOG, "windows", 0.10, SYSMON_ACTIVITIES),
)


class GeneratorError(ValueError):
    """The requested data set cannot be generated (e.g. too few events for the span)."""


@dataclass(frozen=True, slots=True)
class GeneratorConfig:
    events: int = 100_000
    days: int = 7
    # Defaults to the current time, rounded down to the hour.
    end: datetime | None = None
    seed: int = 7


@dataclass(frozen=True, slots=True)
class GeneratedFile:
    name: str
    parser: str
    events: int
    size: int


@dataclass(frozen=True, slots=True)
class Manifest:
    seed: int
    start: datetime
    end: datetime
    files: list[GeneratedFile] = field(default_factory=list)
    scenarios: list[Scenario] = field(default_factory=list)

    @property
    def events(self) -> int:
        return sum(item.events for item in self.files)

    def to_json(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "events": self.events,
            "files": [
                {
                    "name": item.name,
                    "parser": item.parser,
                    "events": item.events,
                    "bytes": item.size,
                }
                for item in self.files
            ],
            "indicator_feed": FEED_FILE,
            "scenarios": [scenario.to_json() for scenario in self.scenarios],
        }


def _end_time(config: GeneratorConfig) -> datetime:
    if config.end is not None:
        return config.end.astimezone(UTC)
    return datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


def _budgets(events: int) -> dict[str, int]:
    budgets = {spec.name: int(events * spec.share) for spec in LOG_FILES}
    budgets[ACCESS_LOG] += events - sum(budgets.values())
    return budgets


def _plant_baseline(
    rng: random.Random, start: float, end: float, timelines: dict[str, Timeline]
) -> None:
    """Routine logins that give the 'new source address' rule its history.

    The backup account logs in every night and the administrator every
    morning, starting right after ``start`` so that even a one-day data set
    has the history the attacks are compared against.
    """
    nightly_backup(rng, start + 300, timelines[AUTH_LOG], fixed=True)
    admin_logon(rng, start + 600, timelines[WINDOWS_LOG], fixed=True)
    first = datetime.fromtimestamp(start, UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    day = first + timedelta(days=1)
    while day.timestamp() < end - _TAIL_SECONDS:
        midnight = day.timestamp()
        nightly_backup(
            rng, midnight + 2 * 3600 + rng.uniform(0, 600), timelines[AUTH_LOG], fixed=True
        )
        admin_logon(
            rng, midnight + 8.5 * 3600 + rng.uniform(0, 1800), timelines[WINDOWS_LOG], fixed=True
        )
        day += timedelta(days=1)


class _Pace:
    """Spacing between activities so a file's lines fill its time span.

    Activities are a Poisson process whose rate follows :func:`activity_level`
    (busy afternoons, quiet nights). The gap is recomputed before every
    activity from the time and lines that remain, so the file ends close to
    the end of the span whatever the mix of activities turns out to be.
    """

    def __init__(self, start: float, horizon: float) -> None:
        self.start = start
        self.horizon = horizon
        hours = max(int((horizon - start) // 3600), 1)
        self._sums = [0.0]
        for hour in range(hours):
            self._sums.append(self._sums[-1] + activity_level(start + hour * 3600 + 1800))

    def _average_level_after(self, clock: float) -> float:
        hours = len(self._sums) - 1
        hour = min(max(int((clock - self.start) // 3600), 0), hours - 1)
        return (self._sums[hours] - self._sums[hour]) / (hours - hour)

    def next(self, rng: random.Random, clock: float, remaining_runs: float) -> float:
        if clock >= self.horizon:
            return clock
        mean_gap = (self.horizon - clock) / max(remaining_runs, 1.0)
        level = self._average_level_after(clock) / activity_level(clock)
        return min(clock + rng.expovariate(1.0) * mean_gap * level, self.horizon)


def _write_log(
    spec: LogFileSpec,
    timeline: Timeline,
    budget: int,
    rng: random.Random,
    span: tuple[float, float],
    path: Path,
) -> int:
    """Fill ``path`` with ``budget`` lines: the fixed ones plus ordinary activity."""
    start, end = span
    pace = _Pace(start, end - _TAIL_SECONDS)
    normal_budget = budget - len(timeline)
    activities = [activity for activity, _ in spec.activities]
    weights = [weight for _, weight in spec.activities]
    clock = start
    scheduled = runs = written = dropped = 0

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = LogWriter(handle)

        def flush(until: float) -> None:
            nonlocal written, dropped
            for timestamp, line, fixed in timeline.due(until):
                if fixed:
                    writer.write(timestamp, line)
                elif written < normal_budget and timestamp <= end and writer.write(timestamp, line):
                    written += 1
                else:
                    dropped += 1  # over budget, past the end, or a duplicate

        while written < normal_budget:
            pending = scheduled - written - dropped
            if written + pending >= normal_budget:
                # Enough is scheduled: release it all. Anything dropped is made up
                # by more activity after the last line written.
                flush(float("inf"))
                clock = min(max(clock, writer.last_timestamp), end)
                continue
            lines_per_run = scheduled / runs if runs else 2.0
            clock = pace.next(rng, clock, (normal_budget - written - pending) / lines_per_run)
            before = len(timeline)
            rng.choices(activities, weights)[0](rng, clock, timeline)
            scheduled += len(timeline) - before
            runs += 1
            flush(clock)
        flush(float("inf"))
    logger.info("Wrote %s: %d events", path.name, writer.count)
    return writer.count


def generate(config: GeneratorConfig, directory: Path) -> Manifest:
    """Write the log files, indicator feed and manifest into ``directory``."""
    if not 1 <= config.days <= MAX_DAYS:
        msg = f"days must be between 1 and {MAX_DAYS}"
        raise GeneratorError(msg)
    if config.events < MIN_EVENTS:
        msg = f"generate at least {MIN_EVENTS:,} events"
        raise GeneratorError(msg)
    end_time = _end_time(config)
    start_time = end_time - timedelta(days=config.days)
    start, end = start_time.timestamp(), end_time.timestamp()

    timelines = {spec.name: Timeline() for spec in LOG_FILES}
    scenarios = plant_scenarios(random.Random(f"{config.seed}:scenarios"), start, end, timelines)
    _plant_baseline(random.Random(f"{config.seed}:baseline"), start, end, timelines)
    budgets = _budgets(config.events)
    for spec in LOG_FILES:
        if len(timelines[spec.name]) * 2 > budgets[spec.name]:
            msg = (
                f"{config.events:,} events are too few for {config.days} days of {spec.name}; "
                "use more events or fewer days"
            )
            raise GeneratorError(msg)

    directory.mkdir(parents=True, exist_ok=True)
    files: list[GeneratedFile] = []
    for spec in LOG_FILES:
        path = directory / spec.name
        count = _write_log(
            spec,
            timelines[spec.name],
            budgets[spec.name],
            random.Random(f"{config.seed}:{spec.name}"),
            (start, end),
            path,
        )
        files.append(GeneratedFile(spec.name, spec.parser, count, path.stat().st_size))

    manifest = Manifest(config.seed, start_time, end_time, files, scenarios)
    (directory / FEED_FILE).write_text(indicator_feed(), encoding="utf-8", newline="\n")
    (directory / MANIFEST_FILE).write_text(
        json.dumps(manifest.to_json(), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return manifest
