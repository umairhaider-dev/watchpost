"""Measuring ingestion, detection and search speed on a generated data set.

``watchpost benchmark --database-url postgresql+asyncpg://.../watchpost_bench``
runs these steps against a database whose name contains ``bench`` (its
schema is dropped and rebuilt first, so it must not hold anything else):

1. generate the events with :mod:`watchpost.datagen` (timed separately);
2. import the generated indicator feed;
3. ingest each file through an ordinary ingestion job, one after another,
   exactly as the worker does: parse, match indicators, insert in batches;
4. run every enabled rule over all stored events in one detection run;
5. time a set of searches through the HTTP API, in process, as a signed-in
   user: each runs once to warm up, then ``repeats`` times.

Results are written as JSON and as a Markdown table.
"""

from __future__ import annotations

import json
import logging
import math
import os
import platform
import statistics
import time
from collections.abc import Awaitable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import Connection, func, make_url, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from watchpost.accounts import create_user
from watchpost.api.app import create_app
from watchpost.auth.tokens import issue_session
from watchpost.core.config import Settings
from watchpost.datagen import GeneratorConfig, Manifest, generate
from watchpost.db.models import (
    DetectionRun,
    DetectionTrigger,
    IngestionJob,
    IngestOrigin,
    Rule,
    User,
    UserRole,
)
from watchpost.db.session import create_engine, create_session_factory
from watchpost.detection.runner import create_run, execute_run
from watchpost.detection.store import sync_builtin_rules
from watchpost.ingestion.jobs import run_ingestion_job
from watchpost.intel.feeds import parse_feed
from watchpost.intel.store import upsert_iocs

logger = logging.getLogger(__name__)

BENCH_USER = "bench.admin"
# Only used inside the benchmark database, which is rebuilt on every run.
BENCH_PASSWORD = "benchmark-only-password"  # noqa: S105


class BenchmarkError(RuntimeError):
    """The benchmark cannot run (e.g. the database name does not contain "bench")."""


@dataclass(frozen=True, slots=True)
class BenchmarkConfig:
    database_url: str
    work_dir: Path
    rules_dir: Path
    alembic_ini: Path
    events: int = 1_000_000
    days: int = 7
    seed: int = 7
    repeats: int = 20


@dataclass(frozen=True, slots=True)
class Search:
    """One search request, and what it is meant to exercise."""

    label: str
    path: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IngestTiming:
    file: str
    events: int
    seconds: float

    @property
    def events_per_second(self) -> float:
        return self.events / self.seconds if self.seconds else 0.0


@dataclass(frozen=True, slots=True)
class SearchTiming:
    label: str
    request: str
    results: int
    median_ms: float
    p95_ms: float
    max_ms: float


@dataclass(slots=True)
class BenchmarkReport:
    environment: dict[str, Any]
    generate_seconds: float = 0.0
    ingest: list[IngestTiming] = field(default_factory=list)
    detection_seconds: float = 0.0
    events_scanned: int = 0
    alerts_created: int = 0
    searches: list[SearchTiming] = field(default_factory=list)

    @property
    def events(self) -> int:
        return sum(item.events for item in self.ingest)

    @property
    def ingest_seconds(self) -> float:
        return sum(item.seconds for item in self.ingest)

    def to_json(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "generate_seconds": round(self.generate_seconds, 2),
            "ingest": [
                {**asdict(item), "events_per_second": round(item.events_per_second)}
                for item in self.ingest
            ],
            "ingest_total": {
                "events": self.events,
                "seconds": round(self.ingest_seconds, 2),
                "events_per_second": round(self.events / self.ingest_seconds)
                if self.ingest_seconds
                else 0,
            },
            "detection": {
                "seconds": round(self.detection_seconds, 2),
                "events_scanned": self.events_scanned,
                "alerts_created": self.alerts_created,
            },
            "searches": [asdict(item) for item in self.searches],
        }

    def to_markdown(self) -> str:
        env = self.environment
        lines = [
            f"Measured on {env['platform']} ({env['cpu_count']} logical CPUs), Python "
            f"{env['python']}, {env['postgres']}; {self.events:,} events over "
            f"{env['days']} days, ingestion batches of {env['batch_size']:,}.",
            "",
            "| Step | Events | Time | Throughput |",
            "| --- | ---: | ---: | ---: |",
        ]
        lines += [
            f"| Ingest `{item.file}` | {item.events:,} | {item.seconds:.1f} s | "
            f"{item.events_per_second:,.0f} events/s |"
            for item in self.ingest
        ]
        total_rate = self.events / self.ingest_seconds if self.ingest_seconds else 0
        lines += [
            f"| **Ingest, all files** | **{self.events:,}** | **{self.ingest_seconds:.1f} s** | "
            f"**{total_rate:,.0f} events/s** |",
            f"| Detection, all {env['rules']} rules over every event | {self.events_scanned:,} | "
            f"{self.detection_seconds:.1f} s | "
            f"{self.events_scanned / self.detection_seconds if self.detection_seconds else 0:,.0f}"
            f" events/s |",
            "",
            f"| Search ({env['repeats']} runs each) | Results | Median | p95 | Max |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
        lines += [
            f"| {item.label} | {item.results} | {item.median_ms:.0f} ms | "
            f"{item.p95_ms:.0f} ms | {item.max_ms:.0f} ms |"
            for item in self.searches
        ]
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------


def _upgrade(connection: Connection, alembic_ini: Path) -> None:
    config = Config(str(alembic_ini))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    command.upgrade(config, "head")


async def prepare_database(url: str, alembic_ini: Path) -> None:
    """Create the benchmark database if needed and rebuild its schema."""
    target = make_url(url)
    name = target.database or ""
    if target.drivername != "postgresql+asyncpg":
        msg = "the database URL must use the 'postgresql+asyncpg' scheme"
        raise BenchmarkError(msg)
    if "bench" not in name:
        msg = f"refusing to rebuild {name!r}: the benchmark database name must contain 'bench'"
        raise BenchmarkError(msg)
    admin = create_async_engine(
        target.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
    )
    try:
        async with admin.connect() as conn:
            exists = await conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            )
            if not exists:
                quoted = name.replace('"', '""')
                await conn.execute(text(f'CREATE DATABASE "{quoted}"'))
    finally:
        await admin.dispose()
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            await conn.run_sync(_upgrade, alembic_ini)
    finally:
        await engine.dispose()


async def _timed(step: Awaitable[object]) -> float:
    began = time.perf_counter()
    await step
    return time.perf_counter() - began


async def _ingest(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    manifest: Manifest,
    directory: Path,
) -> list[IngestTiming]:
    timings: list[IngestTiming] = []
    for item in manifest.files:
        async with session_factory() as session:
            # A watched-folder job: the runner never deletes those files.
            job = IngestionJob(
                origin=IngestOrigin.WATCH_FOLDER,
                filename=item.name,
                stored_path=str(directory / item.name),
                parser="auto",
                file_size=item.size,
            )
            session.add(job)
            await session.commit()
            job_id = job.id
        seconds = await _timed(run_ingestion_job(session_factory, settings, job_id))
        async with session_factory() as session:
            stored = await session.get(IngestionJob, job_id)
            inserted = stored.events_inserted if stored else 0
        logger.info("Ingested %s: %d events in %.1f s", item.name, inserted, seconds)
        timings.append(IngestTiming(item.name, inserted, seconds))
    return timings


def searches(manifest: Manifest) -> list[Search]:
    """The search requests timed by the benchmark."""
    last_day = (manifest.end - timedelta(days=1)).isoformat()
    return [
        Search("Newest events, no filter", "/api/events"),
        Search("One address (indexed column)", "/api/events", {"q": "source.ip:203.0.113.45"}),
        Search(
            "User and outcome",
            "/api/events",
            {"q": "user.name:backup AND event.outcome:success"},
        ),
        Search(
            "Status code outside a network",
            "/api/events",
            {"q": "status:404 AND NOT source.ip:10.0.0.0/8"},
        ),
        Search(
            "Failures in the last 24 hours",
            "/api/events",
            {"q": "outcome:failure", "start": last_day},
        ),
        Search("Free text", "/api/events", {"q": '"Failed password"'}),
        Search(
            "Substring of a command line", "/api/events", {"q": "process.command_line:sekurlsa"}
        ),
        Search(
            "Field inside the raw record",
            "/api/events",
            {"q": "raw.event_data.TargetImage:*lsass*"},
        ),
        Search("Dashboard, last 7 days", "/api/dashboard", {"range": "7d"}),
        Search("Alert queue", "/api/alerts"),
    ]


def _percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    return ordered[max(math.ceil(share * len(ordered)) - 1, 0)]


def _count_results(body: Any) -> int:
    if isinstance(body, dict):
        items = body.get("items")
        if isinstance(items, list):
            return len(items)
    return 1


async def _search(
    settings: Settings, user: User, requests: list[Search], repeats: int
) -> list[SearchTiming]:
    app = create_app(settings)
    token = issue_session(user, settings).token
    # One INFO line per request from the HTTP client would drown the results.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    timings: list[SearchTiming] = []
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://bench",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            for request in requests:
                warm = await client.get(request.path, params=request.params)
                warm.raise_for_status()
                durations: list[float] = []
                for _ in range(repeats):
                    began = time.perf_counter()
                    response = await client.get(request.path, params=request.params)
                    durations.append((time.perf_counter() - began) * 1000)
                    response.raise_for_status()
                query = request.params.get("q") or request.params.get("range") or ""
                timings.append(
                    SearchTiming(
                        label=request.label,
                        request=f"{request.path} {query}".strip(),
                        results=_count_results(warm.json()),
                        median_ms=round(statistics.median(durations), 1),
                        p95_ms=round(_percentile(durations, 0.95), 1),
                        max_ms=round(max(durations), 1),
                    )
                )
                logger.info("Search %r: median %.0f ms", request.label, timings[-1].median_ms)
    return timings


async def run_benchmark(config: BenchmarkConfig, settings: Settings) -> BenchmarkReport:
    """Run every step and return the measurements."""
    await prepare_database(config.database_url, config.alembic_ini)
    settings = settings.model_copy(
        update={"database_url": config.database_url, "upload_dir": config.work_dir / "uploads"}
    )
    engine = create_engine(settings)
    session_factory = create_session_factory(engine)
    try:
        async with session_factory() as session:
            await sync_builtin_rules(session, config.rules_dir)
            user = await create_user(
                session, username=BENCH_USER, password=BENCH_PASSWORD, role=UserRole.ADMIN
            )
            await session.commit()
            rules = await session.scalar(select(func.count()).where(Rule.enabled.is_(True)))
            postgres = str(await session.scalar(text("SHOW server_version")))

        data_dir = config.work_dir / "data"
        began = time.perf_counter()
        manifest = generate(
            GeneratorConfig(events=config.events, days=config.days, seed=config.seed), data_dir
        )
        report = BenchmarkReport(
            environment={
                "platform": platform.platform(terse=True),
                "cpu_count": os.cpu_count(),
                "python": platform.python_version(),
                "postgres": f"PostgreSQL {postgres}",
                "days": config.days,
                "batch_size": settings.ingest_batch_size,
                "rules": rules,
                "repeats": config.repeats,
                "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
            },
            generate_seconds=time.perf_counter() - began,
        )
        logger.info("Generated %d events in %.1f s", manifest.events, report.generate_seconds)

        async with session_factory() as session:
            feed = parse_feed((data_dir / "iocs.csv").read_bytes(), "iocs.csv")
            await upsert_iocs(session, feed.entries, source="iocs.csv")
            await session.commit()

        report.ingest = await _ingest(session_factory, settings, manifest, data_dir)
        async with engine.connect() as conn:
            # Planner statistics, as autovacuum would gather them shortly after a load.
            await conn.execute(text("ANALYZE"))
            await conn.commit()

        async with session_factory() as session:
            run = await create_run(session, trigger=DetectionTrigger.MANUAL)
            await session.commit()
            run_id = run.id
        report.detection_seconds = await _timed(execute_run(session_factory, run_id))
        async with session_factory() as session:
            finished = await session.scalar(select(DetectionRun).where(DetectionRun.id == run_id))
            if finished is not None:
                report.events_scanned = finished.events_scanned
                report.alerts_created = finished.alerts_created
        logger.info(
            "Detection over %d events took %.1f s (%d alerts)",
            report.events_scanned,
            report.detection_seconds,
            report.alerts_created,
        )

        report.searches = await _search(settings, user, searches(manifest), config.repeats)
    finally:
        await engine.dispose()
    return report


def save_report(report: BenchmarkReport, directory: Path) -> tuple[Path, Path]:
    """Write ``benchmark-results.json`` and ``benchmark-results.md`` into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "benchmark-results.json"
    markdown_path = directory / "benchmark-results.md"
    json_path.write_text(
        json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    markdown_path.write_text(report.to_markdown(), encoding="utf-8", newline="\n")
    return json_path, markdown_path
