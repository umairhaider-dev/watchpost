"""Trying a rule against pasted sample logs, without storing anything.

Used by the rule editor: the analyst pastes a few log lines, picks a parser
(or lets it be detected) and sees which lines the rule would fire on. Line
numbers stand in for event IDs, so every hit points back at its lines.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import UTC, datetime

from watchpost.detection.compiler import CompiledRule
from watchpost.detection.engine import Hit, evaluate, row_with_id
from watchpost.detection.fields import EventRow
from watchpost.ingestion.parsers import AUTO, ParseContext, detect_parser, get_parser
from watchpost.ingestion.pipeline import MalformedSample, ParseStats, parse_numbered_events
from watchpost.ingestion.readers import SNIFF_BYTES, LogFile, sample_from_bytes

MAX_SAMPLE_RECORDS = 10_000


@dataclass(frozen=True, slots=True)
class SandboxResult:
    parser: str
    events_parsed: int
    malformed: list[MalformedSample]
    malformed_count: int
    truncated: bool
    hits: list[Hit]
    rows: dict[int, EventRow]


def try_rule_on_sample(
    rule: CompiledRule,
    sample: str,
    parser_name: str = AUTO,
    *,
    reference_time: datetime | None = None,
) -> SandboxResult:
    """Parse ``sample`` and evaluate ``rule`` over it.

    Raises:
        FormatDetectionError: if ``parser_name`` is ``auto`` and the format is unknown.
        KeyError: for an unknown parser name.
    """
    data = sample.encode("utf-8")
    if parser_name == AUTO:
        head = data[:SNIFF_BYTES]
        parser_cls = detect_parser(sample_from_bytes(head, complete=len(data) <= SNIFF_BYTES))
    else:
        parser_cls = get_parser(parser_name)
    parser = parser_cls(ParseContext(reference_time=reference_time or datetime.now(UTC)))

    stats = ParseStats()
    rows: dict[int, EventRow] = {}
    truncated = False
    with LogFile(io.BytesIO(data)) as log_file:
        for number, event in parse_numbered_events(log_file.stream, parser, stats):
            if len(rows) >= MAX_SAMPLE_RECORDS:
                truncated = True
                break
            rows[number] = row_with_id(event.to_row(), number)

    return SandboxResult(
        parser=parser.name,
        events_parsed=len(rows),
        malformed=stats.samples,
        malformed_count=stats.malformed,
        truncated=truncated,
        hits=evaluate(rule, list(rows.values())),
        rows=rows,
    )
