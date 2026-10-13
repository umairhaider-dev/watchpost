"""Command-line entry point: ``watchpost <command>``.

Commands:
    sync-rules   load the built-in rule files into the database
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from watchpost.core.config import Settings, get_settings
from watchpost.core.logging import configure_logging
from watchpost.db.session import create_engine, create_session_factory
from watchpost.detection.errors import RuleError
from watchpost.detection.store import sync_builtin_rules

logger = logging.getLogger("watchpost.cli")


async def sync_rules(settings: Settings, directory: Path) -> int:
    """Run the rule sync; returns a process exit code."""
    engine = create_engine(settings)
    try:
        async with create_session_factory(engine)() as session:
            await sync_builtin_rules(session, directory)
            await session.commit()
    except RuleError as exc:
        logger.error("Rule sync failed: %s", exc)
        return 1
    finally:
        await engine.dispose()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchpost", description="Watchpost administration")
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync-rules", help="load the built-in rule files into the database")
    sync.add_argument("--rules-dir", type=Path, help="folder with rule YAML files")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    if args.command == "sync-rules":
        return asyncio.run(sync_rules(settings, args.rules_dir or settings.rules_dir))
    return 2  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
