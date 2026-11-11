"""Package sources: a uniform, read-only view over folders, single files and ZIP archives."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from modmanifest.archive.limits import Deadline, ScanLimits
from modmanifest.models import Finding, Report, Status

_REPARSE_POINT = 0x400


class SourceReadError(Exception):
    """An entry could not be read."""


class EntryTooLarge(SourceReadError):
    """An entry exceeds the allowed read size."""


class CorruptEntry(SourceReadError):
    """An entry's data failed an integrity check."""


@dataclass(slots=True)
class Entry:
    path: str
    size: int
    kind: str  # file | dir | symlink | special | unsafe
    compressed_size: int | None = None
    readable: bool = True


class PackageSource:
    kind = "folder"

    def __init__(self, display: str) -> None:
        self.display = display
        self.entries: list[Entry] = []
        self._by_path: dict[str, Entry] = {}

    def index(self) -> None:
        self._by_path = {e.path: e for e in self.entries if e.kind != "unsafe"}

    def get(self, path: str) -> Entry | None:
        return self._by_path.get(path)

    def files(self) -> Iterator[Entry]:
        return (e for e in self.entries if e.kind == "file" and e.readable)

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        raise NotImplementedError

    def read_head(self, path: str, n: int) -> bytes:
        return self.read_bytes_prefix(path, n)

    def read_bytes_prefix(self, path: str, n: int) -> bytes:
        raise NotImplementedError

    def open_seekable(self, path: str, max_bytes: int) -> BinaryIO:
        raise NotImplementedError

    def close(self) -> None:
        return None


class FolderSource(PackageSource):
    kind = "folder"

    def __init__(self, root: str, display: str) -> None:
        super().__init__(display)
        self.root = root

    def _full(self, path: str) -> str:
        entry = self.get(path)
        if entry is None or entry.kind != "file" or not entry.readable:
            raise SourceReadError(f"not a readable file entry: {path}")
        return os.path.join(self.root, *path.split("/"))

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        full = self._full(path)
        try:
            with open(full, "rb") as fh:
                data = fh.read(max_bytes + 1)
        except OSError as exc:
            raise SourceReadError(str(exc)) from exc
        if len(data) > max_bytes:
            raise EntryTooLarge(path)
        return data

    def read_bytes_prefix(self, path: str, n: int) -> bytes:
        full = self._full(path)
        try:
            with open(full, "rb") as fh:
                return fh.read(n)
        except OSError as exc:
            raise SourceReadError(str(exc)) from exc

    def open_seekable(self, path: str, max_bytes: int) -> BinaryIO:
        full = self._full(path)
        try:
            return open(full, "rb")  # noqa: SIM115 - the caller owns and closes the handle
        except OSError as exc:
            raise SourceReadError(str(exc)) from exc


class SingleFileSource(FolderSource):
    kind = "file"

    def __init__(self, file_path: str) -> None:
        name = os.path.basename(file_path)
        super().__init__(os.path.dirname(os.path.abspath(file_path)), name)
        size = os.stat(file_path).st_size
        self.entries = [Entry(name, size, "file")]
        self.index()


def _is_link(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink():
            return True
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & _REPARSE_POINT)


def build_folder_source(
    root: str, display: str, limits: ScanLimits, deadline: Deadline, report: Report
) -> FolderSource:
    """Walk a folder without following links and record every entry."""
    src = FolderSource(root, display)
    report.capability("folder.walk")
    stack: list[tuple[str, str]] = [(root, "")]
    links = 0
    while stack:
        deadline.check()
        directory, prefix = stack.pop()
        try:
            with os.scandir(directory) as it:
                children = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            report.error("MM-SCN-003", f"could not list '{prefix or '.'}': {exc.strerror or exc}")
            continue
        for child in children:
            rel = f"{prefix}{child.name}"
            if len(src.entries) >= limits.max_entries:
                report.add(
                    Finding(
                        "MM-ARC-007",
                        Status.ERROR,
                        f"more than {limits.max_entries} entries; the scan stopped early",
                        details={"limit": limits.max_entries},
                    )
                )
                report.error("MM-SCN-004", "entry count limit reached; results are partial")
                src.index()
                return src
            if _is_link(child):
                links += 1
                src.entries.append(Entry(rel, 0, "symlink"))
                report.add(
                    Finding(
                        "MM-ARC-020",
                        Status.WARNING,
                        "link or reparse point recorded and not followed",
                        source=rel,
                    )
                )
                continue
            try:
                st = child.stat(follow_symlinks=False)
            except OSError as exc:
                report.error("MM-SCN-003", f"could not stat '{rel}': {exc.strerror or exc}")
                continue
            if stat.S_ISDIR(st.st_mode):
                src.entries.append(Entry(rel, 0, "dir"))
                stack.append((child.path, rel + "/"))
            elif stat.S_ISREG(st.st_mode):
                src.entries.append(Entry(rel, st.st_size, "file"))
            else:
                src.entries.append(Entry(rel, 0, "special", readable=False))
                report.add(
                    Finding(
                        "MM-ARC-006",
                        Status.WARNING,
                        "special file recorded and never opened",
                        source=rel,
                    )
                )
    src.index()
    return src
