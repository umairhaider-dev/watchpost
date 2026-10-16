"""The benchmark command on a small data set, against its own database."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import make_url

from tests.conftest import BACKEND_DIR, TEST_DATABASE_URL
from watchpost import cli
from watchpost.benchmark import (
    BenchmarkConfig,
    BenchmarkError,
    prepare_database,
    run_benchmark,
    save_report,
)
from watchpost.core.config import Settings

BENCH_URL = (
    make_url(TEST_DATABASE_URL)
    .set(database="watchpost_test_bench")
    .render_as_string(hide_password=False)
)


def config(tmp_path: Path) -> BenchmarkConfig:
    return BenchmarkConfig(
        database_url=BENCH_URL,
        work_dir=tmp_path,
        rules_dir=BACKEND_DIR / "rules",
        alembic_ini=BACKEND_DIR / "alembic.ini",
        events=3_000,
        days=1,
        repeats=2,
    )


async def test_measures_every_step(settings: Settings, tmp_path: Path) -> None:
    report = await run_benchmark(config(tmp_path), settings)

    assert report.events == 3_000
    assert [item.file for item in report.ingest] == [
        "auth.log",
        "access.log",
        "windows_security.jsonl",
        "sysmon.jsonl",
    ]
    assert all(item.seconds > 0 for item in report.ingest)
    assert report.events_scanned == 3_000
    assert report.alerts_created > 20
    assert len(report.searches) == 10
    assert all(item.median_ms > 0 for item in report.searches)
    assert report.environment["rules"] == 21

    json_path, markdown_path = save_report(report, tmp_path / "results")
    saved = json.loads(json_path.read_text(encoding="utf-8"))
    assert saved["ingest_total"]["events"] == 3_000
    table = markdown_path.read_text(encoding="utf-8")
    assert "| **Ingest, all files** | **3,000** |" in table
    assert "| Free text |" in table


@pytest.mark.parametrize(
    ("url", "message"),
    [
        (TEST_DATABASE_URL, "must contain 'bench'"),
        ("postgresql://watchpost:watchpost@localhost:5432/watchpost_bench", r"postgresql\+asyncpg"),
    ],
)
async def test_refuses_databases_it_should_not_touch(url: str, message: str) -> None:
    with pytest.raises(BenchmarkError, match=message):
        await prepare_database(url, BACKEND_DIR / "alembic.ini")


def test_cli_reports_failures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.main(["benchmark", "--database-url", TEST_DATABASE_URL, "--work-dir", str(tmp_path)])

    assert code == 1
    assert "Benchmark failed" in capsys.readouterr().err
