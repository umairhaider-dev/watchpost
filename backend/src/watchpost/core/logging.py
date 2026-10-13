"""Logging setup shared by the API and the worker.

Two output formats are supported: a readable single-line text format for
local development and a JSON-lines format that log shippers can parse
without extra configuration.
"""

from __future__ import annotations

import json
import logging
import logging.config
from datetime import UTC, datetime
from typing import Any, Literal

# Attributes present on every LogRecord; anything else was passed via ``extra=``.
# ``color_message`` is uvicorn's ANSI-coloured duplicate of the message.
_STANDARD_RECORD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
    | {"message", "asctime", "color_message"}
)

TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Render each record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extras = {
            key: value
            for key, value in vars(record).items()
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_")
        }
        if extras:
            payload["extra"] = extras
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: Literal["text", "json"] = "text") -> None:
    """Configure the root logger. Safe to call more than once."""
    formatter: dict[str, Any] = {"()": JsonFormatter} if fmt == "json" else {"format": TEXT_FORMAT}
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"default": formatter},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stderr",
                },
            },
            "root": {"level": level, "handlers": ["console"]},
            "loggers": {
                # Uvicorn installs its own handlers; route them through ours instead.
                "uvicorn": {"handlers": [], "propagate": True},
                "uvicorn.access": {"handlers": [], "propagate": True},
                "uvicorn.error": {"handlers": [], "propagate": True},
                "sqlalchemy.engine": {"level": "WARNING"},
                "arq": {"level": level},
            },
        }
    )
