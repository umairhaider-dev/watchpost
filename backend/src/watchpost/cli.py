"""Command-line entry point: ``watchpost <command>``.

Commands:
    sync-rules      load the built-in rule files into the database
    create-user     add an analyst, admin or viewer account
    generate-logs   write realistic sample logs with attacks hidden in them
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from watchpost.accounts import AccountError, create_user
from watchpost.core.config import Settings, get_settings
from watchpost.core.logging import configure_logging
from watchpost.core.passwords import WeakPasswordError, check_password_policy
from watchpost.datagen import GeneratorConfig, GeneratorError, generate
from watchpost.db.models import UserRole
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


async def add_user(settings: Settings, args: argparse.Namespace, password: str) -> int:
    """Create one account; returns a process exit code."""
    engine = create_engine(settings)
    try:
        async with create_session_factory(engine)() as session:
            user = await create_user(
                session,
                username=args.username,
                password=password,
                role=UserRole(args.role),
                full_name=args.full_name,
                email=args.email,
            )
            await session.commit()
            logger.info("User %r (%s) created with id %d", user.username, user.role, user.id)
    except (AccountError, WeakPasswordError) as exc:
        logger.error("Could not create the user: %s", exc)
        return 1
    finally:
        await engine.dispose()
    return 0


def read_password(from_stdin: bool) -> str | None:
    """The new password, from the first line of stdin or typed twice at a prompt."""
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        logger.error("The passwords do not match")
        return None
    return first


def utc_datetime(value: str) -> datetime:
    """An ISO 8601 time from the command line; times without an offset are UTC."""
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        msg = f"not an ISO 8601 time: {value!r}"
        raise argparse.ArgumentTypeError(msg) from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def generate_logs(args: argparse.Namespace) -> int:
    """Write the synthetic data set; returns a process exit code."""
    config = GeneratorConfig(events=args.events, days=args.days, end=args.end, seed=args.seed)
    try:
        manifest = generate(config, args.output)
    except GeneratorError as exc:
        logger.error("Could not generate logs: %s", exc)
        return 1
    logger.info(
        "Wrote %d events from %s to %s into %s",
        manifest.events,
        manifest.start.isoformat(),
        manifest.end.isoformat(),
        args.output,
    )
    for scenario in manifest.scenarios:
        logger.info(
            "Planted %s at %s: %s",
            scenario.id,
            datetime.fromtimestamp(scenario.start, UTC).isoformat(timespec="seconds"),
            scenario.title,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchpost", description="Watchpost administration")
    commands = parser.add_subparsers(dest="command", required=True)

    sync = commands.add_parser("sync-rules", help="load the built-in rule files into the database")
    sync.add_argument("--rules-dir", type=Path, help="folder with rule YAML files")

    user = commands.add_parser("create-user", help="add a user account")
    user.add_argument("username", help="login name (lowercase letters, digits, . _ -)")
    user.add_argument(
        "--role", choices=[role.value for role in UserRole], default=UserRole.ANALYST.value
    )
    user.add_argument("--full-name", help="name shown in the UI")
    user.add_argument("--email")
    user.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from the first line of standard input instead of prompting",
    )

    logs = commands.add_parser(
        "generate-logs", help="write realistic sample logs with attacks hidden in them"
    )
    logs.add_argument(
        "--output",
        type=Path,
        default=Path("generated"),
        help="folder to write (created if missing)",
    )
    logs.add_argument("--events", type=int, default=100_000, help="total number of events")
    logs.add_argument("--days", type=int, default=7, help="how many days the logs cover")
    logs.add_argument("--seed", type=int, default=7, help="same seed, same logs")
    logs.add_argument(
        "--end", type=utc_datetime, help="last moment covered, ISO 8601 (default: this hour)"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    if args.command == "sync-rules":
        return asyncio.run(sync_rules(settings, args.rules_dir or settings.rules_dir))
    if args.command == "create-user":
        password = read_password(args.password_stdin)
        if password is None:
            return 1
        try:
            check_password_policy(password)
        except WeakPasswordError as exc:
            logger.error("Could not create the user: %s", exc)
            return 1
        return asyncio.run(add_user(settings, args, password))
    if args.command == "generate-logs":
        return generate_logs(args)
    return 2  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
