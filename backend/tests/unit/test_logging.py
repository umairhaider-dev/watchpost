from __future__ import annotations

import json
import logging
import sys

import pytest

from watchpost.core.logging import JsonFormatter, configure_logging


def _record(msg: str, *args: object, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("watchpost.test", logging.INFO, __file__, 10, msg, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_emits_core_fields() -> None:
    payload = json.loads(JsonFormatter().format(_record("ingested %d events", 42)))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "watchpost.test"
    assert payload["message"] == "ingested 42 events"
    assert payload["timestamp"].endswith("+00:00")
    assert "extra" not in payload


def test_json_formatter_includes_extra_fields() -> None:
    payload = json.loads(JsonFormatter().format(_record("done", job_id="abc", count=3)))

    assert payload["extra"] == {"job_id": "abc", "count": 3}


def test_json_formatter_drops_uvicorn_colour_duplicate() -> None:
    record = _record("Started", color_message="\x1b[36mStarted\x1b[0m")

    payload = json.loads(JsonFormatter().format(record))

    assert "extra" not in payload


def test_json_formatter_includes_exception() -> None:
    try:
        raise ValueError("bad line")
    except ValueError:
        record = logging.LogRecord(
            "watchpost.test", logging.ERROR, __file__, 1, "failed", None, sys.exc_info()
        )

    payload = json.loads(JsonFormatter().format(record))

    assert "ValueError: bad line" in payload["exception"]


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_configure_logging_sets_root_level_and_formatter(fmt: str) -> None:
    root = logging.getLogger()
    previous_level, previous_handlers = root.level, root.handlers[:]
    try:
        configure_logging("WARNING", fmt)  # type: ignore[arg-type]

        assert root.level == logging.WARNING
        handler = root.handlers[0]
        assert isinstance(handler.formatter, JsonFormatter) == (fmt == "json")
    finally:
        root.handlers = previous_handlers
        root.setLevel(previous_level)
