"""Command-line interface."""

from __future__ import annotations

import os
import sys
from enum import StrEnum
from typing import Annotated

import typer
from rich.console import Console

from modmanifest import __version__
from modmanifest.archive.limits import MB, ScanLimits
from modmanifest.inspector import run
from modmanifest.models import Report
from modmanifest.reporting import render_json, render_terminal

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Read-only inspection, validation and metadata auditing for game mod packages.",
)

EXIT_OK, EXIT_ERRORS, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3


class Game(StrEnum):
    SIMS4 = "sims4"
    INZOI = "inzoi"


PathArg = Annotated[str, typer.Argument(help="Folder, .zip, .ts4script or .package to inspect.")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Emit the stable JSON report.")]
VerboseOpt = Annotated[
    bool, typer.Option("--verbose", help="Show passing checks and finding basis.")
]
TimeoutOpt = Annotated[float, typer.Option("--timeout", min=1, help="Scan time limit in seconds.")]
MaxEntriesOpt = Annotated[int, typer.Option("--max-entries", min=1, help="Entry count limit.")]
MaxTotalOpt = Annotated[int, typer.Option("--max-total-mb", min=1, help="Expanded size limit.")]
MaxEntryOpt = Annotated[int, typer.Option("--max-entry-mb", min=1, help="Per-entry size limit.")]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"modmanifest {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = False,
) -> None:
    """ModManifest never modifies, extracts or executes the packages it inspects."""


def _exit_code(report: Report) -> int:
    if report.scan_status == "incomplete" or report.inspection_errors:
        return EXIT_INCOMPLETE
    if report.command == "validate" and report.scan_status == "nothing_recognized":
        return EXIT_INCOMPLETE
    if report.has_errors:
        return EXIT_ERRORS
    return EXIT_OK


def _execute(
    command: str,
    path: str,
    game: str | None,
    as_json: bool,
    verbose: bool,
    timeout: float,
    max_entries: int,
    max_total_mb: int,
    max_entry_mb: int,
) -> None:
    if not os.path.exists(path):
        Console(stderr=True).print(f"error: path does not exist: {path!r}", markup=False)
        raise typer.Exit(EXIT_USAGE)
    limits = ScanLimits(
        max_entries=max_entries,
        max_total_bytes=max_total_mb * MB,
        max_entry_bytes=max_entry_mb * MB,
        timeout_s=timeout,
    )
    report = run(command, path, game, limits)
    if as_json:
        sys.stdout.write(render_json(report) + "\n")
    else:
        render_terminal(report, Console(), verbose)
    raise typer.Exit(_exit_code(report))


@app.command()
def inspect(
    path: PathArg,
    json_output: JsonOpt = False,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = 30.0,
    max_entries: MaxEntriesOpt = 20_000,
    max_total_mb: MaxTotalOpt = 500,
    max_entry_mb: MaxEntryOpt = 50,
) -> None:
    """Safety checks, game recognition, validation and AI metadata audit."""
    _execute(
        "inspect",
        path,
        None,
        json_output,
        verbose,
        timeout,
        max_entries,
        max_total_mb,
        max_entry_mb,
    )


@app.command()
def validate(
    path: PathArg,
    game: Annotated[Game, typer.Option("--game", help="Game rules to validate against.")],
    json_output: JsonOpt = False,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = 30.0,
    max_entries: MaxEntriesOpt = 20_000,
    max_total_mb: MaxTotalOpt = 500,
    max_entry_mb: MaxEntryOpt = 50,
) -> None:
    """Safety checks and game-specific validation."""
    _execute(
        "validate",
        path,
        game.value,
        json_output,
        verbose,
        timeout,
        max_entries,
        max_total_mb,
        max_entry_mb,
    )


@app.command("audit-ai")
def audit_ai(
    path: PathArg,
    json_output: JsonOpt = False,
    verbose: VerboseOpt = False,
    timeout: TimeoutOpt = 30.0,
    max_entries: MaxEntriesOpt = 20_000,
    max_total_mb: MaxTotalOpt = 500,
    max_entry_mb: MaxEntryOpt = 50,
) -> None:
    """Report AI-related metadata indicators found in supported metadata containers."""
    _execute(
        "audit-ai",
        path,
        None,
        json_output,
        verbose,
        timeout,
        max_entries,
        max_total_mb,
        max_entry_mb,
    )


def main() -> None:
    app()
