"""inZOI candidate-package recognizer and observation-based validator.

There is no official package specification behind these checks. Rules are labelled by their
basis: ``format-rule`` (structural facts such as JSON syntax), ``observed-convention``
(patterns seen in sample packages, never required), and ``safety-limit`` (path safety).
"""

from __future__ import annotations

import json
import re
from typing import Any

from modmanifest.context import ScanContext
from modmanifest.games.base import GameModule
from modmanifest.models import Finding, RecognizedFile, Status, sanitize

MANIFEST = "mod_manifest.json"
UNREAL_EXTS = (".pak", ".ucas", ".utoc")
SCRIPT_EXTS = (".lua", ".js", ".html", ".css")
NON_MOD_DIRS = {".modding", "88849", "connect", "ingame", "modkitpreview"}
_CHECKSUM = re.compile(r"^(?P<path>.+)\|(?P<digest>[0-9A-Fa-f]{32})$")

# Field types seen in sample manifests. Observed only; no field is required.
OBSERVED_TYPES: dict[str, type | tuple[type, ...]] = {
    "FriendlyName": str,
    "ProjectName": str,
    "Description": str,
    "Author": str,
    "Version": str,
    "Url": str,
    "PackageTime": str,
    "Dependencies": list,
    "Assets": list,
    "Maps": list,
    "NonAssets": list,
    "FileChecksums": list,
    "Protected": list,
    "bEnable": bool,
    "LoadOrder": int,
    "ValidatedGameVersion": str,
    "ValidationError": str,
}


def _ext(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""


def _unsafe_listed_path(path: str) -> bool:
    if not path or path.startswith(("/", "\\")) or "\\" in path or "\x00" in path:
        return True
    if re.match(r"^[A-Za-z]:", path):
        return True
    return any(part == ".." for part in path.split("/"))


class InzoiModule(GameModule):
    name = "inzoi"
    label = "inZOI"

    def __init__(self) -> None:
        self.root = ""

    def _find_root(self, ctx: ScanContext) -> str | None:
        files = {e.path for e in ctx.source.entries if e.kind == "file"}
        if MANIFEST in files:
            return ""
        tops = {p.split("/", 1)[0] for p in files if "/" in p}
        loose = {p for p in files if "/" not in p}
        if len(tops) == 1 and not loose:
            top = next(iter(tops))
            if f"{top}/{MANIFEST}" in files:
                return top + "/"
        return None

    def recognize(self, ctx: ScanContext) -> bool:
        if self._find_root(ctx) is not None:
            return True
        return bool(self._child_candidates(ctx))

    def _child_candidates(self, ctx: ScanContext) -> list[str]:
        files = {e.path for e in ctx.source.entries if e.kind == "file"}
        return sorted(
            {p.split("/", 1)[0] for p in files if p.count("/") == 1 and p.endswith("/" + MANIFEST)}
        )

    def validate(self, ctx: ScanContext) -> None:
        report = ctx.report
        root = self._find_root(ctx)
        if root is None:
            children = self._child_candidates(ctx)
            report.add(
                Finding(
                    "MM-INZ-014",
                    Status.NOT_CHECKED,
                    f"{len(children)} subfolders contain a {MANIFEST}; inspect one mod folder "
                    "at a time. Other folders (for example mod-manager state) are unrecognized, "
                    "not invalid.",
                    details={"candidates": children[:50], "count": len(children)},
                )
            )
            return
        self.root = root
        report.add(
            Finding(
                "MM-INZ-015",
                Status.NOT_CHECKED,
                "no official inZOI package specification was used; checks are based on "
                "observed sample packages",
            )
        )
        manifest = self._read_manifest(ctx, root + MANIFEST)
        if manifest is not None:
            self._check_manifest(ctx, manifest, root)
        self._inventory(ctx, root)

    def _read_manifest(self, ctx: ScanContext, path: str) -> dict[str, Any] | None:
        report = ctx.report
        data = ctx.read(path, ctx.limits.max_metadata_bytes)
        if data is None:
            return None
        report.recognized_files.append(RecognizedFile(path, "inzoi-manifest", len(data)))
        try:
            parsed = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            report.add(
                Finding(
                    "MM-INZ-002",
                    Status.ERROR,
                    f"manifest is not valid UTF-8 JSON: {type(exc).__name__}",
                    source=path,
                )
            )
            return None
        if not isinstance(parsed, dict):
            report.add(
                Finding(
                    "MM-INZ-003",
                    Status.ERROR,
                    f"manifest root is {type(parsed).__name__}, not an object",
                    source=path,
                )
            )
            return None
        report.capability("inzoi.manifest.json")
        report.add(
            Finding(
                "MM-INZ-001",
                Status.PASS,
                "root mod_manifest.json parsed; this makes the folder a candidate inZOI mod, "
                "not a verified valid package",
                source=path,
            )
        )
        return parsed

    def _check_manifest(self, ctx: ScanContext, m: dict[str, Any], root: str) -> None:
        report = ctx.report
        for key, expected in OBSERVED_TYPES.items():
            if key not in m:
                continue
            value = m[key]
            ok = isinstance(value, expected) and not (expected is int and isinstance(value, bool))
            if not ok:
                report.add(
                    Finding(
                        "MM-INZ-004",
                        Status.WARNING,
                        f"'{key}' is {type(value).__name__}; sample packages use "
                        f"{expected.__name__ if isinstance(expected, type) else expected}",
                        source=MANIFEST,
                        location=key,
                    )
                )
        info: dict[str, Any] = {}
        for key in (
            "FriendlyName",
            "ProjectName",
            "Author",
            "Version",
            "Description",
            "ValidatedGameVersion",
            "LoadOrder",
            "bEnable",
        ):
            v = m.get(key)
            if isinstance(v, (str, int, bool)):
                info[key] = sanitize(v, 300) if isinstance(v, str) else v
        deps = m.get("Dependencies")
        info["Dependencies"] = (
            [sanitize(d, 200) if isinstance(d, str) else d for d in deps[:100]]
            if isinstance(deps, list)
            else None
        )
        report.package_info["inzoi"] = {"manifest": info}
        project = m.get("ProjectName")
        folder = root.rstrip("/") or (report.target_name if report.target_kind == "folder" else "")
        if isinstance(project, str) and folder:
            same = project == folder
            report.add(
                Finding(
                    "MM-INZ-005",
                    Status.PASS if same else Status.NOT_CHECKED,
                    "ProjectName matches the folder name (informational convention)"
                    if same
                    else "ProjectName differs from the folder name; this is informational only",
                    source=MANIFEST,
                    location="ProjectName",
                )
            )
        report.add(
            Finding(
                "MM-INZ-013",
                Status.NOT_CHECKED,
                "declared dependencies are reported as written; installation and "
                "compatibility were not verified",
                source=MANIFEST,
                location="Dependencies",
                details={"declared": len(deps) if isinstance(deps, list) else 0},
            )
        )
        report.add(
            Finding(
                "MM-INZ-017",
                Status.NOT_CHECKED,
                "game version metadata is reported as written; compatibility was not verified",
                source=MANIFEST,
            )
        )
        self._check_checksums(ctx, m, root)

    def _check_checksums(self, ctx: ScanContext, m: dict[str, Any], root: str) -> None:
        report = ctx.report
        entries = m.get("FileChecksums")
        malformed = unsafe = missing = listed = 0
        examples: list[str] = []
        if isinstance(entries, list):
            for item in entries:
                match = _CHECKSUM.match(item) if isinstance(item, str) else None
                if match is None:
                    malformed += 1
                    continue
                listed += 1
                rel = match.group("path")
                if _unsafe_listed_path(rel):
                    unsafe += 1
                    continue
                if ctx.source.get(root + rel) is None:
                    missing += 1
                    if len(examples) < 5:
                        examples.append(sanitize(rel, 120))
        if unsafe:
            report.add(
                Finding(
                    "MM-INZ-006",
                    Status.ERROR,
                    f"{unsafe} FileChecksums paths are absolute or traverse outside the package",
                    source=MANIFEST,
                    location="FileChecksums",
                )
            )
        if malformed:
            report.add(
                Finding(
                    "MM-INZ-008",
                    Status.WARNING,
                    f"{malformed} FileChecksums entries do not match the observed "
                    "'relative/path|32 hex digits' shape",
                    source=MANIFEST,
                    location="FileChecksums",
                )
            )
        if missing:
            report.add(
                Finding(
                    "MM-INZ-007",
                    Status.WARNING,
                    f"{missing} of {listed} listed files are absent from the package",
                    source=MANIFEST,
                    location="FileChecksums",
                    details={"examples": examples},
                )
            )
        report.package_info.setdefault("inzoi", {})["file_checksums"] = {
            "listed": listed,
            "verified": False,
        }
        report.add(
            Finding(
                "MM-INZ-009",
                Status.NOT_CHECKED,
                "checksum digests were not verified: the algorithm and path semantics could "
                "not be established from samples, and none was guessed. A matching digest would "
                "show consistency with the manifest only, not that a mod is safe or authentic.",
                source=MANIFEST,
                location="FileChecksums",
            )
        )

    def _inventory(self, ctx: ScanContext, root: str) -> None:
        report = ctx.report
        containers: dict[str, set[str]] = {}
        scripts = 0
        for e in ctx.source.entries:
            if e.kind != "file" or not e.path.startswith(root):
                continue
            ext = _ext(e.path)
            if ext in UNREAL_EXTS:
                stem = e.path[: -len(ext)]
                containers.setdefault(stem, set()).add(ext)
                report.recognized_files.append(RecognizedFile(e.path, "unreal-container", e.size))
            elif ext in SCRIPT_EXTS or ext == ".uplugin":
                scripts += ext in SCRIPT_EXTS
                kind = "uplugin-descriptor" if ext == ".uplugin" else "script-or-ui-file"
                report.recognized_files.append(RecognizedFile(e.path, kind, e.size))
        total = sum(len(v) for v in containers.values())
        if total:
            report.add(
                Finding(
                    "MM-INZ-010",
                    Status.NOT_CHECKED,
                    f"{total} Unreal content container file(s) (.pak/.ucas/.utoc) recognized "
                    "and inventoried; internals were not inspected",
                    details={"count": total},
                )
            )
        for stem, exts in sorted(containers.items()):
            if (".ucas" in exts) != (".utoc" in exts):
                report.add(
                    Finding(
                        "MM-INZ-011",
                        Status.WARNING,
                        "an IoStore .ucas or .utoc file has no matching partner",
                        source=stem,
                    )
                )
        if scripts:
            report.add(
                Finding(
                    "MM-INZ-012",
                    Status.NOT_CHECKED,
                    f"{scripts} script/UI file(s) listed; contents were not analyzed or executed",
                )
            )
