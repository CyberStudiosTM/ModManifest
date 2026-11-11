"""Orchestration: open a target safely, run the selected checks, return a report."""

from __future__ import annotations

import os

from modmanifest.archive.limits import Deadline, ScanLimits, ScanTimeout
from modmanifest.archive.signatures import check_signatures
from modmanifest.archive.sources import (
    PackageSource,
    SingleFileSource,
    build_folder_source,
)
from modmanifest.archive.zip_inspector import open_zip
from modmanifest.context import ScanContext
from modmanifest.games.base import GameModule
from modmanifest.games.inzoi import InzoiModule
from modmanifest.games.sims4 import Sims4Module
from modmanifest.metadata.ai_audit import audit
from modmanifest.models import Finding, Report, Status

GAMES: dict[str, type[GameModule]] = {"sims4": Sims4Module, "inzoi": InzoiModule}


def _open_target(
    path: str, limits: ScanLimits, deadline: Deadline, report: Report
) -> PackageSource | None:
    if os.path.isdir(path):
        report.target_kind = "folder"
        src = build_folder_source(path, report.target_name, limits, deadline, report)
        return src
    lower = path.lower()
    if lower.endswith((".zip", ".ts4script")):
        report.target_kind = "ts4script" if lower.endswith(".ts4script") else "zip"
        size = os.path.getsize(path)
        return open_zip(path, report.target_name, limits, deadline, report, archive_size=size)
    report.target_kind = "file"
    src = SingleFileSource(path)
    if not lower.endswith(".package"):
        report.add(
            Finding(
                "MM-ARC-023",
                Status.UNSUPPORTED,
                "this file type is not supported as a standalone target",
                source=report.target_name,
            )
        )
    return src


def run(
    command: str,
    path: str,
    game: str | None = None,
    limits: ScanLimits | None = None,
) -> Report:
    """Run ``inspect``, ``validate`` or ``audit-ai`` against an existing path."""
    limits = limits or ScanLimits()
    deadline = Deadline(limits.timeout_s)
    name = os.path.basename(os.path.normpath(path)) or "target"
    report = Report(command, name, "unknown", game_selected=game)
    src: PackageSource | None = None
    try:
        src = _open_target(path, limits, deadline, report)
        if src is None:
            return report
        ctx = ScanContext(report, src, limits, deadline)
        check_signatures(ctx)
        if report.scan_status == "complete" and report.target_kind == "folder":
            report.add(Finding("MM-ARC-021", Status.PASS, "folder safety checks completed"))
        if command in ("inspect", "validate"):
            _run_games(ctx, command, game)
        if command in ("inspect", "audit-ai"):
            audit(ctx)
    except ScanTimeout as exc:
        report.error("MM-SCN-001", str(exc))
    except OSError as exc:
        report.error("MM-SCN-002", f"could not read target: {exc.strerror or exc}")
    finally:
        if src is not None:
            src.close()
    return report


def _run_games(ctx: ScanContext, command: str, game: str | None) -> None:
    report = ctx.report
    names = [game] if command == "validate" and game else list(GAMES)
    detected: list[str] = []
    for key in names:
        module = GAMES[key]()
        if module.recognize(ctx):
            detected.append(key)
            module.validate(ctx)
    report.game_detected = ",".join(detected) if detected else None
    if detected:
        return
    if command == "validate":
        report.add(
            Finding(
                "MM-SCN-005",
                Status.NOT_CHECKED,
                f"no {GAMES[names[0]].label} structures were recognized in this target",
            )
        )
    else:
        report.add(
            Finding(
                "MM-SCN-006", Status.NOT_CHECKED, "no supported game structures were recognized"
            )
        )
    if report.scan_status == "complete":
        report.scan_status = "nothing_recognized"
