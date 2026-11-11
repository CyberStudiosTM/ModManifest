"""Defensive, read-only ZIP inspection. Nothing is extracted to disk."""

from __future__ import annotations

import io
import re
import stat
import zipfile
import zlib
from typing import BinaryIO

from modmanifest.archive.limits import Deadline, ScanLimits
from modmanifest.archive.sources import (
    CorruptEntry,
    Entry,
    EntryTooLarge,
    PackageSource,
    SourceReadError,
)
from modmanifest.models import Finding, Report, Status

NESTED_ARCHIVE_EXTENSIONS = (".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".bz2", ".xz")
_DRIVE = re.compile(r"^[A-Za-z]:")
_CHUNK = 64 * 1024


class ZipSource(PackageSource):
    kind = "zip"

    def __init__(self, target: str | BinaryIO, display: str) -> None:
        super().__init__(display)
        self._zf = zipfile.ZipFile(target)
        self._infos: dict[str, zipfile.ZipInfo] = {}

    def close(self) -> None:
        self._zf.close()

    def infolist(self) -> list[zipfile.ZipInfo]:
        return self._zf.infolist()

    def _read(self, path: str, limit: int) -> bytes:
        entry = self.get(path)
        info = self._infos.get(path)
        if entry is None or info is None or entry.kind != "file" or not entry.readable:
            raise SourceReadError(f"not a readable file entry: {path}")
        chunks: list[bytes] = []
        total = 0
        try:
            with self._zf.open(info) as fh:
                while total <= limit:
                    block = fh.read(min(_CHUNK, limit + 1 - total))
                    if not block:
                        break
                    chunks.append(block)
                    total += len(block)
        except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
            raise CorruptEntry(str(exc)) from exc
        except (RuntimeError, NotImplementedError) as exc:
            raise SourceReadError(str(exc)) from exc
        return b"".join(chunks)

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        data = self._read(path, max_bytes)
        if len(data) > max_bytes:
            raise EntryTooLarge(path)
        return data

    def read_bytes_prefix(self, path: str, n: int) -> bytes:
        try:
            return self._read(path, n)[:n]
        except CorruptEntry:
            return b""

    def open_seekable(self, path: str, max_bytes: int) -> BinaryIO:
        return io.BytesIO(self.read_bytes(path, max_bytes))


def _path_problem(raw: str) -> str | None:
    name = raw.replace("\\", "/")
    if "\x00" in raw:
        return "contains a NUL byte"
    if name.startswith("/"):
        return "absolute path"
    if _DRIVE.match(name):
        return "drive-letter path"
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "path traversal component"
    if any(":" in p for p in parts):
        return "colon in path component (drive or alternate data stream)"
    return None


def open_zip(
    target: str | BinaryIO,
    display: str,
    limits: ScanLimits,
    deadline: Deadline,
    report: Report,
    *,
    scope: str = "",
    archive_size: int | None = None,
) -> ZipSource | None:
    """Open and analyze a ZIP, recording findings. Returns None when it cannot be inspected."""
    label = scope or None
    if archive_size is not None and archive_size > limits.max_archive_bytes:
        report.add(
            Finding(
                "MM-ARC-016",
                Status.ERROR,
                f"archive is {archive_size} bytes; the limit is {limits.max_archive_bytes}",
                source=label,
            )
        )
        report.error("MM-SCN-004", "archive size limit reached; the archive was not opened")
        return None
    try:
        src = ZipSource(target, display)
    except zipfile.BadZipFile as exc:
        report.add(
            Finding("MM-ARC-001", Status.ERROR, f"not a readable ZIP archive: {exc}", source=label)
        )
        return None
    except OSError as exc:
        report.error("MM-SCN-002", f"could not open archive: {exc.strerror or exc}")
        return None
    report.capability("archive.zip.structure")
    infos = src.infolist()
    if len(infos) > limits.max_entries:
        report.add(
            Finding(
                "MM-ARC-007",
                Status.ERROR,
                f"{len(infos)} entries exceed the limit of {limits.max_entries}",
                source=label,
                details={"limit": limits.max_entries, "entries": len(infos)},
            )
        )
        report.error("MM-SCN-004", "entry count limit reached; the archive was not inspected")
        src.close()
        return None

    def rel(p: str) -> str:
        return f"{scope}!/{p}" if scope else p

    errors_before = sum(1 for f in report.findings if f.status is Status.ERROR)
    seen: dict[str, int] = {}
    folded: dict[str, str] = {}
    total = 0
    total_flagged = False
    for i, info in enumerate(infos):
        if i % 500 == 0:
            deadline.check()
        raw = info.orig_filename
        if "\\" in raw:
            report.add(
                Finding(
                    "MM-ARC-015",
                    Status.WARNING,
                    "entry name uses a backslash separator; treated as '/'",
                    source=rel(raw),
                )
            )
        norm = raw.replace("\\", "/")
        problem = _path_problem(raw)
        if problem:
            report.add(
                Finding(
                    "MM-ARC-002", Status.ERROR, f"unsafe entry path: {problem}", source=rel(raw)
                )
            )
            src.entries.append(Entry(norm, info.file_size, "unsafe", readable=False))
            continue
        is_dir = info.is_dir()
        path = norm.rstrip("/") if is_dir else norm
        kind = "dir" if is_dir else "file"
        readable = True
        mode = info.external_attr >> 16
        if info.create_system == 3 and not is_dir and mode:
            if stat.S_ISLNK(mode):
                kind, readable = "symlink", False
                report.add(
                    Finding(
                        "MM-ARC-005",
                        Status.WARNING,
                        "symbolic link entry recorded and never resolved",
                        source=rel(path),
                    )
                )
            elif (
                stat.S_ISCHR(mode)
                or stat.S_ISBLK(mode)
                or stat.S_ISFIFO(mode)
                or stat.S_ISSOCK(mode)
            ):
                kind, readable = "special", False
                report.add(
                    Finding(
                        "MM-ARC-006",
                        Status.ERROR,
                        "special file entry (device, pipe or socket)",
                        source=rel(path),
                    )
                )
        seen[path] = seen.get(path, 0) + 1
        if seen[path] == 2:
            report.add(
                Finding(
                    "MM-ARC-003",
                    Status.ERROR,
                    "entry name appears more than once; the entry is ambiguous and was not read",
                    source=rel(path),
                )
            )
        key = path.casefold()
        if key in folded and folded[key] != path:
            report.add(
                Finding(
                    "MM-ARC-004",
                    Status.WARNING,
                    f"differs only by case from '{folded[key]}'",
                    source=rel(path),
                )
            )
        folded.setdefault(key, path)
        if kind == "file":
            total += info.file_size
            if info.flag_bits & 0x1:
                readable = False
                report.add(
                    Finding(
                        "MM-ARC-011",
                        Status.UNSUPPORTED,
                        "encrypted entry; contents were not read",
                        source=rel(path),
                    )
                )
            if info.file_size > limits.max_entry_bytes:
                readable = False
                report.add(
                    Finding(
                        "MM-ARC-009",
                        Status.ERROR,
                        f"declared size {info.file_size} exceeds the entry limit",
                        source=rel(path),
                        details={"limit": limits.max_entry_bytes},
                    )
                )
            if (
                info.file_size >= limits.ratio_min_bytes
                and info.file_size / max(info.compress_size, 1) > limits.max_ratio
            ):
                report.add(
                    Finding(
                        "MM-ARC-010",
                        Status.WARNING,
                        f"compression ratio above {limits.max_ratio:g}:1",
                        source=rel(path),
                        details={"size": info.file_size, "compressed": info.compress_size},
                    )
                )
            if path.lower().endswith(NESTED_ARCHIVE_EXTENSIONS):
                report.add(
                    Finding(
                        "MM-ARC-012",
                        Status.UNSUPPORTED,
                        "nested archive listed but not opened",
                        source=rel(path),
                    )
                )
            if total > limits.max_total_bytes and not total_flagged:
                total_flagged = True
                report.add(
                    Finding(
                        "MM-ARC-008",
                        Status.ERROR,
                        f"declared expanded size exceeds {limits.max_total_bytes} bytes",
                        source=label,
                        details={"limit": limits.max_total_bytes},
                    )
                )
        src.entries.append(Entry(path, info.file_size, kind, info.compress_size, readable))
        src._infos.setdefault(path, info)
    ambiguous = {p for p, n in seen.items() if n > 1}
    for entry in src.entries:
        if entry.path in ambiguous:
            entry.readable = False
    if total_flagged:
        for entry in src.entries:
            entry.readable = False
    src.index()
    errors_after = sum(1 for f in report.findings if f.status is Status.ERROR)
    if errors_after == errors_before:
        report.add(
            Finding(
                "MM-ARC-014",
                Status.PASS,
                f"{len(infos)} entries checked for path safety, duplicates, links, sizes, ratios",
                source=label,
            )
        )
    return src
