"""Shared scan context: report, source, limits and safe read helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

from modmanifest.archive.limits import Deadline, ScanLimits
from modmanifest.archive.sources import (
    CorruptEntry,
    EntryTooLarge,
    PackageSource,
    SourceReadError,
)
from modmanifest.models import Finding, Report, Status


@dataclass(slots=True)
class ScanContext:
    report: Report
    source: PackageSource
    limits: ScanLimits
    deadline: Deadline

    def _fail(self, path: str, exc: SourceReadError) -> None:
        if isinstance(exc, CorruptEntry):
            self.report.add(
                Finding("MM-ARC-001", Status.ERROR, f"entry data is corrupt: {exc}", source=path)
            )
        else:
            self.report.error("MM-SCN-003", f"could not read '{path}': {exc}")

    def read(self, path: str, max_bytes: int) -> bytes | None:
        """Read a whole entry up to ``max_bytes``. Returns None if it cannot be read."""
        self.deadline.check()
        try:
            return self.source.read_bytes(path, max_bytes)
        except EntryTooLarge:
            return None
        except SourceReadError as exc:
            self._fail(path, exc)
            return None

    def head(self, path: str, n: int) -> bytes | None:
        self.deadline.check()
        try:
            return self.source.read_bytes_prefix(path, n)
        except SourceReadError as exc:
            self._fail(path, exc)
            return None

    def open(self, path: str, max_bytes: int) -> BinaryIO | None:
        self.deadline.check()
        try:
            return self.source.open_seekable(path, max_bytes)
        except EntryTooLarge:
            return None
        except SourceReadError as exc:
            self._fail(path, exc)
            return None
