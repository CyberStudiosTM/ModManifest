"""Terminal and JSON rendering."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from modmanifest.models import AI_NONE_FOUND, AI_NONE_FOUND_NOTE, Report, Status, sanitize

STATUS_STYLE = {
    Status.PASS: "#A8E8DC",
    Status.WARNING: "#F4C8EA",
    Status.ERROR: "bold #F4C8EA reverse",
    Status.UNSUPPORTED: "#AED8F5",
    Status.NOT_CHECKED: "#C6B6F3",
}
ACCENT = "#C6B6F3"


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True, sort_keys=False)


def _t(text: str, limit: int = 200) -> str:
    return escape(sanitize(text, limit))


def render_terminal(report: Report, console: Console, verbose: bool = False) -> None:
    console.print(
        f"[bold {ACCENT}]ModManifest[/] {_t(report.command)}  [dim]{_t(report.target_name)}[/]"
    )
    console.print(f"[dim]target: {report.target_kind}  scan: {report.scan_status}[/]")
    if report.game_detected or report.game_selected:
        console.print(
            f"[dim]game selected: {_t(report.game_selected or '-')}  "
            f"recognized: {_t(report.game_detected or 'none')}[/]"
        )
    if report.command != "audit-ai":
        table = Table(show_header=True, header_style=ACCENT, box=None, pad_edge=False)
        table.add_column("Status")
        table.add_column("Code")
        table.add_column("Finding", overflow="fold")
        for f in report.findings:
            if f.status is Status.PASS and not verbose:
                continue
            style = STATUS_STYLE[f.status]
            where = f" [dim]({_t(f.source)})[/]" if f.source else ""
            table.add_row(f"[{style}]{f.status.value}[/]", f.code, f"{_t(f.message, 400)}{where}")
            if verbose:
                table.add_row("", "", f"[dim]{escape(f.title)} · basis: {f.basis}[/]")
        console.print(table)
        counts = report.counts()
        console.print(
            "  ".join(f"[{STATUS_STYLE[s]}]{s.value} {counts[s.value]}[/]" for s in Status)
        )
        if report.inspection_errors:
            for e in report.inspection_errors:
                console.print(f"[{STATUS_STYLE[Status.ERROR]}]{e.code}[/] {_t(e.message, 400)}")
    if report.ai_audited:
        console.print(f"\n[bold {ACCENT}]AI metadata indicators[/]")
        if not report.ai_findings:
            console.print(AI_NONE_FOUND)
            console.print(f"[dim]{AI_NONE_FOUND_NOTE}[/]")
        for a in report.ai_findings:
            console.print(
                f"[{STATUS_STYLE[Status.NOT_CHECKED]}]{a.category.value}[/] {a.code} "
                f"{_t(a.source)} [dim]{_t(a.location)}[/]"
            )
            console.print(f"  evidence: {_t(a.evidence, 120)}")
            console.print(
                f"  [dim]{escape(a.explanation)} Confidence in metadata interpretation: "
                f"{a.confidence}.[/]"
            )
        console.print(
            "[dim]These indicators describe metadata only; they do not establish how the "
            "package was made.[/]"
        )
