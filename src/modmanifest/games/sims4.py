"""The Sims 4 recognizer and validator."""

from __future__ import annotations

import io

from modmanifest.archive.sources import PackageSource
from modmanifest.archive.zip_inspector import open_zip
from modmanifest.context import ScanContext
from modmanifest.games.base import GameModule
from modmanifest.games.dbpf import validate_dbpf
from modmanifest.models import Finding, RecognizedFile, Status

PACKAGE_EXT = ".package"
SCRIPT_EXT = ".ts4script"
MAX_PYC_CHECKS = 2000


def _ext(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""


class Sims4Module(GameModule):
    name = "sims4"
    label = "The Sims 4"

    def recognize(self, ctx: ScanContext) -> bool:
        if ctx.report.target_kind == "ts4script":
            return True
        return any(_ext(e.path) in (PACKAGE_EXT, SCRIPT_EXT) for e in ctx.source.entries)

    def validate(self, ctx: ScanContext) -> None:
        report = ctx.report
        packages = scripts = resources = unread = 0
        if report.target_kind == "ts4script":
            scripts += 1
            report.recognized_files.append(
                RecognizedFile(ctx.source.display, "sims4-script-archive")
            )
            self._check_script_archive(ctx, ctx.source, ctx.source.display)
        else:
            for entry in ctx.source.entries:
                if entry.kind != "file":
                    continue
                ext = _ext(entry.path)
                if ext == PACKAGE_EXT:
                    packages += 1
                    report.recognized_files.append(
                        RecognizedFile(entry.path, "sims4-package", entry.size)
                    )
                    n = self._check_package(ctx, entry.path, entry.size, entry.readable)
                    if n is None:
                        unread += 1
                    else:
                        resources += n
                elif ext == SCRIPT_EXT:
                    scripts += 1
                    report.recognized_files.append(
                        RecognizedFile(entry.path, "sims4-script-archive", entry.size)
                    )
                    self._check_nested_script(ctx, entry.path, entry.readable)
        report.package_info["sims4"] = {
            "packages": packages,
            "script_archives": scripts,
            "resources_in_verified_indexes": resources,
        }
        if packages:
            report.add(
                Finding(
                    "MM-S4-013",
                    Status.NOT_CHECKED,
                    f"{packages} package(s): index structure only; resource contents, "
                    "compression and resource types were not decoded",
                )
            )
        if scripts:
            report.add(
                Finding(
                    "MM-S4-014",
                    Status.NOT_CHECKED,
                    "script archive contents were not analyzed, imported or executed",
                )
            )
        report.add(
            Finding(
                "MM-S4-015",
                Status.NOT_CHECKED,
                "The Sims 4 has no standard mod manifest; declared dependencies and versions "
                "were not extracted",
            )
        )

    def _check_package(self, ctx: ScanContext, path: str, size: int, readable: bool) -> int | None:
        fh = ctx.open(path, ctx.limits.max_entry_bytes) if readable else None
        if fh is None:
            ctx.report.add(
                Finding(
                    "MM-S4-016",
                    Status.NOT_CHECKED,
                    "package could not be read within scan limits; see other findings",
                    source=path,
                )
            )
            return None
        try:
            return validate_dbpf(fh, size, path, ctx.report)
        finally:
            fh.close()

    def _check_nested_script(self, ctx: ScanContext, path: str, readable: bool) -> None:
        data = ctx.read(path, ctx.limits.max_entry_bytes) if readable else None
        if data is None:
            ctx.report.add(
                Finding(
                    "MM-S4-016",
                    Status.NOT_CHECKED,
                    "script archive could not be read within scan limits",
                    source=path,
                )
            )
            return
        nested = open_zip(io.BytesIO(data), path, ctx.limits, ctx.deadline, ctx.report, scope=path)
        if nested is None:
            return
        try:
            self._check_script_archive(ctx, nested, path)
        finally:
            nested.close()

    def _check_script_archive(self, ctx: ScanContext, src: PackageSource, label: str) -> None:
        scripts = [e for e in src.entries if e.kind == "file" and _ext(e.path) in (".py", ".pyc")]
        ctx.report.capability("sims4.ts4script.zip")
        ctx.report.add(
            Finding(
                "MM-S4-010",
                Status.PASS,
                f"script archive opened read-only; {len(scripts)} .py/.pyc entries listed",
                source=label,
            )
        )
        if not scripts:
            ctx.report.add(
                Finding(
                    "MM-S4-011",
                    Status.WARNING,
                    "no .py or .pyc entries were found",
                    source=label,
                )
            )
            return
        bad: list[str] = []
        checked = 0
        for entry in scripts:
            if _ext(entry.path) != ".pyc" or not entry.readable or checked >= MAX_PYC_CHECKS:
                continue
            ctx.deadline.check()
            head = src.read_bytes_prefix(entry.path, 16)
            checked += 1
            # Every CPython magic number ends in CR LF, and the header is 16 bytes.
            if len(head) < 16 or head[2:4] != b"\r\n":
                bad.append(entry.path)
        if bad:
            ctx.report.add(
                Finding(
                    "MM-S4-012",
                    Status.WARNING,
                    f"{len(bad)} of {checked} .pyc entries lack a valid compiled-code header",
                    source=label,
                    details={"examples": bad[:5]},
                )
            )
