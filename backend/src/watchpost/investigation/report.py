"""Case reports in Markdown and PDF.

Both formats carry the same sections: the case summary, its resolution,
ATT&CK techniques, entities, alerts, evidence, notes and activity. The
Markdown report is the lossless one. The PDF uses the standard PDF fonts,
which only cover Latin-1, so other characters are replaced: typographic
punctuation by its ASCII form, anything else by "?".
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from fpdf import FPDF
from fpdf.enums import WrapMode, XPos, YPos

from watchpost.db.models import AuditLog, Event
from watchpost.detection.mitre import TACTICS, technique_name, technique_tactics
from watchpost.investigation.casefile import CaseFile

_TABLE_UNSAFE = re.compile(r"[\r\n]+")


def _when(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC") if moment else "-"


def _label(value: str) -> str:
    """``in_progress`` -> ``In progress``."""
    return value.replace("_", " ").capitalize()


def _person(username: str | None) -> str:
    return username or "unattributed"


def _event_summary(event: Event) -> str:
    """The most telling single line of an event."""
    if event.process_command_line:
        return event.process_command_line
    if event.url_original:
        parts = [event.http_method, event.url_original, event.http_status_code]
        return " ".join(str(part) for part in parts if part)
    return event.message or event.event_action or ""


def _words(value: object) -> str:
    """``in_progress`` -> ``in progress``."""
    return str(value).replace("_", " ")


def _assigned(details: dict[str, Any]) -> str:
    assignee = details.get("assignee")
    return f"assigned the case to {assignee}" if assignee else "unassigned the case"


def _alerts_added(details: dict[str, Any]) -> str:
    return "added alerts " + ", ".join(f"#{alert_id}" for alert_id in details.get("alert_ids", []))


def _alert_removed(details: dict[str, Any]) -> str:
    moved = details.get("moved_to")
    suffix = f" (moved to case #{moved})" if moved else ""
    return f"removed alert #{details.get('alert_id')}{suffix}"


_ACTIVITY: dict[str, Callable[[dict[str, Any]], str]] = {
    "case.created": lambda _: "opened the case",
    "case.status_changed": lambda d: (
        f"changed the status from {_words(d.get('from'))} to {_words(d.get('to'))}"
    ),
    "case.assigned": _assigned,
    "case.alerts_added": _alerts_added,
    "case.alert_removed": _alert_removed,
    "case.note_added": lambda _: "added a note",
    "case.evidence_added": lambda d: f"pinned event #{d.get('event_id')} as evidence",
    "case.evidence_removed": lambda d: f"unpinned event #{d.get('event_id')}",
    "case.updated": lambda d: "edited the " + ", ".join(d.get("fields", [])),
}


def describe_activity(entry: AuditLog) -> str:
    """A readable sentence for one case audit entry."""
    describe = _ACTIVITY.get(entry.action)
    return describe(entry.details) if describe else entry.action


def _technique_lines(case_file: CaseFile) -> list[str]:
    lines = []
    for technique in case_file.techniques:
        name = technique_name(technique) or "unknown technique"
        tactics = ", ".join(TACTICS.get(t, t) for t in technique_tactics(technique))
        lines.append(f"{technique} {name}" + (f" ({tactics})" if tactics else ""))
    return lines


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def _cell(value: object) -> str:
    """Text safe inside a Markdown table cell."""
    return _TABLE_UNSAFE.sub(" ", str(value)).replace("|", "\\|") or "-"


def _fenced(text: str) -> list[str]:
    """A fenced code block that cannot be closed early by the content."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence, text, fence]


def _quoted(text: str) -> list[str]:
    return [f"> {line}" if line else ">" for line in text.splitlines()] or [">"]


def render_markdown(case_file: CaseFile, *, generated_at: datetime) -> str:
    """The case report as Markdown."""
    case = case_file.case
    assignee = case_file.assignee
    creator = _person(case_file.created_by.username if case_file.created_by else None)
    lines = [
        f"# Case #{case.id}: {_cell(case.title)}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Status | {_label(case.status.value)} |",
        f"| Severity | {_label(case.severity.value)} |",
        f"| Assignee | {_cell(assignee.username) if assignee else 'unassigned'} |",
        f"| Opened | {_when(case.created_at)} |",
        f"| Opened by | {_cell(creator)} |",
        f"| Resolved | {_when(case.resolved_at)} |",
        f"| Closed | {_when(case.closed_at)} |",
        f"| Report generated | {_when(generated_at)} |",
        "",
        "## Summary",
        "",
        case.description or "_No description._",
        "",
    ]
    if case.resolution:
        lines += ["## Resolution", "", case.resolution, ""]

    lines += ["## ATT&CK techniques", ""]
    lines += [f"- {line}" for line in _technique_lines(case_file)] or ["_None._"]
    entities = case_file.entities
    lines += [
        "",
        "## Entities",
        "",
        f"- Hosts: {', '.join(entities['hosts']) or '-'}",
        f"- IP addresses: {', '.join(entities['ips']) or '-'}",
        f"- Users: {', '.join(entities['users']) or '-'}",
        "",
        f"## Alerts ({len(case_file.alerts)})",
        "",
    ]
    if case_file.alerts:
        lines += [
            "| # | Alert | Severity | Status | First seen | Last seen | Events |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        lines += [
            f"| {alert.id} | {_cell(alert.title)} | {_label(alert.severity.value)} "
            f"| {_label(alert.status.value)} | {_when(alert.first_seen)} "
            f"| {_when(alert.last_seen)} | {alert.event_count} |"
            for alert in case_file.alerts
        ]
    else:
        lines.append("_No alerts linked._")

    lines += ["", f"## Evidence ({len(case_file.evidence)})", ""]
    if not case_file.evidence:
        lines.append("_No evidence pinned._")
    for entry in case_file.evidence:
        event = entry.event
        lines += [
            f"### Event #{event.id}: {_when(event.timestamp)}",
            "",
            f"- Source: {event.log_source}; host {event.host_name or '-'}; "
            f"user {event.user_name or '-'}; source IP {event.source_ip or '-'}",
            f"- Action: {event.event_action or '-'} ({event.event_outcome or 'unknown outcome'})",
            f"- Pinned by {_person(entry.added_by)} at {_when(entry.evidence.created_at)}",
        ]
        if entry.evidence.note:
            lines += ["", *_quoted(entry.evidence.note)]
        summary = _event_summary(event)
        if summary:
            lines += ["", *_fenced(summary)]
        lines.append("")

    lines += ["", f"## Notes ({len(case_file.notes)})", ""]
    if not case_file.notes:
        lines.append("_No notes._")
    for note in case_file.notes:
        lines += [
            f"### {_when(note.note.created_at)}, {_person(note.author)}",
            "",
            *_quoted(note.note.body),
            "",
        ]

    lines += ["", "## Activity", ""]
    lines += [
        f"- {_when(entry.occurred_at)}: {_person(entry.username)} {describe_activity(entry)}"
        for entry in case_file.activity
    ] or ["_No recorded activity._"]
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------

# Typographic characters outside Latin-1 that have an obvious ASCII form.
_ASCII_FORMS = {
    chr(0x2010): "-",
    chr(0x2011): "-",
    chr(0x2012): "-",
    chr(0x2013): "-",
    chr(0x2014): "-",
    chr(0x2018): "'",
    chr(0x2019): "'",
    chr(0x201C): '"',
    chr(0x201D): '"',
    chr(0x2022): "*",
    chr(0x2026): "...",
    chr(0x2192): "->",
    chr(0x2190): "<-",
}


def pdf_text(text: str) -> str:
    """Text the standard PDF fonts can draw."""
    normalised = unicodedata.normalize("NFKC", text)
    replaced = "".join(_ASCII_FORMS.get(char, char) for char in normalised)
    return replaced.encode("latin-1", errors="replace").decode("latin-1")


class _ReportPdf(FPDF):
    def __init__(self, case_id: int) -> None:
        super().__init__(orientation="portrait", unit="mm", format="A4")
        self.case_id = case_id
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(15, 15, 15)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", size=8)
        self.set_text_color(110, 110, 110)
        self.cell(
            0,
            5,
            f"Watchpost case report - case #{self.case_id} - page {self.page_no()}/{{nb}}",
            align="C",
        )

    def heading(self, text: str, size: int = 13) -> None:
        self.ln(3)
        self.set_font("Helvetica", style="B", size=size)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 7, pdf_text(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def paragraph(self, text: str, *, mono: bool = False, muted: bool = False) -> None:
        self.set_font("Courier" if mono else "Helvetica", size=8 if mono else 10)
        self.set_text_color(*((100, 100, 100) if muted else (30, 30, 30)))
        self.multi_cell(
            0,
            4.5 if mono else 5,
            pdf_text(text),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            wrapmode=WrapMode.CHAR if mono else WrapMode.WORD,
        )

    def rows(
        self, header: Iterable[str], body: Iterable[Iterable[object]], widths: tuple[int, ...]
    ) -> None:
        self.set_font("Helvetica", size=8)
        self.set_text_color(30, 30, 30)
        with self.table(col_widths=widths, text_align="LEFT", line_height=4.5) as table:
            heading = table.row()
            for title in header:
                heading.cell(pdf_text(title))
            for values in body:
                row = table.row()
                for value in values:
                    row.cell(pdf_text(str(value)))


def render_pdf(case_file: CaseFile, *, generated_at: datetime) -> bytes:
    """The case report as a PDF document."""
    case = case_file.case
    pdf = _ReportPdf(case.id)
    pdf.set_title(pdf_text(f"Case #{case.id}: {case.title}"))
    pdf.set_creator("Watchpost")
    pdf.add_page()
    pdf.heading(f"Case #{case.id}: {case.title}", size=16)
    assignee = case_file.assignee.username if case_file.assignee else "unassigned"
    creator = _person(case_file.created_by.username if case_file.created_by else None)
    pdf.rows(
        ("Field", "Value"),
        [
            ("Status", _label(case.status.value)),
            ("Severity", _label(case.severity.value)),
            ("Assignee", assignee),
            ("Opened", f"{_when(case.created_at)} by {creator}"),
            ("Resolved", _when(case.resolved_at)),
            ("Closed", _when(case.closed_at)),
            ("Report generated", _when(generated_at)),
        ],
        (40, 140),
    )

    pdf.heading("Summary")
    pdf.paragraph(case.description or "No description.", muted=not case.description)
    if case.resolution:
        pdf.heading("Resolution")
        pdf.paragraph(case.resolution)

    pdf.heading("ATT&CK techniques")
    pdf.paragraph("\n".join(_technique_lines(case_file)) or "None.")
    entities = case_file.entities
    pdf.heading("Entities")
    pdf.paragraph(
        f"Hosts: {', '.join(entities['hosts']) or '-'}\n"
        f"IP addresses: {', '.join(entities['ips']) or '-'}\n"
        f"Users: {', '.join(entities['users']) or '-'}"
    )

    pdf.heading(f"Alerts ({len(case_file.alerts)})")
    if case_file.alerts:
        pdf.rows(
            ("#", "Alert", "Severity", "Status", "First seen", "Events"),
            [
                (
                    alert.id,
                    alert.title,
                    _label(alert.severity.value),
                    _label(alert.status.value),
                    _when(alert.first_seen),
                    alert.event_count,
                )
                for alert in case_file.alerts
            ],
            (12, 70, 20, 25, 38, 15),
        )
    else:
        pdf.paragraph("No alerts linked.", muted=True)

    pdf.heading(f"Evidence ({len(case_file.evidence)})")
    if not case_file.evidence:
        pdf.paragraph("No evidence pinned.", muted=True)
    for entry in case_file.evidence:
        event = entry.event
        pdf.heading(f"Event #{event.id}: {_when(event.timestamp)}", size=10)
        pdf.paragraph(
            f"{event.log_source}; host {event.host_name or '-'}; user {event.user_name or '-'}; "
            f"source IP {event.source_ip or '-'}; action {event.event_action or '-'}. "
            f"Pinned by {_person(entry.added_by)}.",
            muted=True,
        )
        if entry.evidence.note:
            pdf.paragraph(entry.evidence.note)
        summary = _event_summary(event)
        if summary:
            pdf.paragraph(summary, mono=True)

    pdf.heading(f"Notes ({len(case_file.notes)})")
    if not case_file.notes:
        pdf.paragraph("No notes.", muted=True)
    for note in case_file.notes:
        pdf.paragraph(f"{_when(note.note.created_at)}, {_person(note.author)}", muted=True)
        pdf.paragraph(note.note.body)
        pdf.ln(1)

    pdf.heading("Activity")
    pdf.paragraph(
        "\n".join(
            f"{_when(entry.occurred_at)}: {_person(entry.username)} {describe_activity(entry)}"
            for entry in case_file.activity
        )
        or "No recorded activity."
    )
    return bytes(pdf.output())
