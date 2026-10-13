"""Log format parsers and the registry used to pick one."""

from __future__ import annotations

from watchpost.ingestion.errors import FormatDetectionError
from watchpost.ingestion.parsers.base import (
    InputFormat,
    JsonParser,
    LineParser,
    ParseContext,
    Parser,
)
from watchpost.ingestion.parsers.generic_json import GenericJsonParser
from watchpost.ingestion.parsers.linux_auth import LinuxAuthParser
from watchpost.ingestion.parsers.web_access import WebAccessParser
from watchpost.ingestion.parsers.windows import WindowsEventParser
from watchpost.ingestion.readers import Sample

AUTO = "auto"

# Order matters only for ties in detection: specific formats come first.
PARSERS: dict[str, type[Parser]] = {
    parser.name: parser
    for parser in (LinuxAuthParser, WebAccessParser, WindowsEventParser, GenericJsonParser)
}

# A parser must be at least this confident before auto-detection trusts it.
MIN_DETECTION_SCORE = 0.4


def get_parser(name: str) -> type[Parser]:
    """Look up a parser by name; raises ``KeyError`` for unknown names."""
    return PARSERS[name]


def is_valid_parser_choice(name: str) -> bool:
    """True for a registered parser name or ``auto``."""
    return name == AUTO or name in PARSERS


def detect_parser(sample: Sample) -> type[Parser]:
    """Pick the parser that best matches the start of a file.

    Raises:
        FormatDetectionError: if no parser is confident enough.
    """
    scores = {parser: parser.sniff(sample) for parser in PARSERS.values()}
    best, score = max(scores.items(), key=lambda item: item[1])
    if score < MIN_DETECTION_SCORE:
        msg = (
            "could not recognise the log format automatically; "
            f"choose a parser explicitly ({', '.join(PARSERS)})"
        )
        raise FormatDetectionError(msg)
    return best


__all__ = [
    "AUTO",
    "PARSERS",
    "GenericJsonParser",
    "InputFormat",
    "JsonParser",
    "LineParser",
    "LinuxAuthParser",
    "ParseContext",
    "Parser",
    "WebAccessParser",
    "WindowsEventParser",
    "detect_parser",
    "get_parser",
    "is_valid_parser_choice",
]
