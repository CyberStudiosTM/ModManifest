"""Configurable scan limits and the scan deadline."""

from __future__ import annotations

import time
from dataclasses import dataclass

MB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_entries: int = 20_000
    max_archive_bytes: int = 1024 * MB
    max_total_bytes: int = 500 * MB
    max_entry_bytes: int = 50 * MB
    max_ratio: float = 100.0
    max_metadata_bytes: int = 1 * MB
    max_image_bytes: int = 20 * MB
    timeout_s: float = 30.0
    # Ratio warnings are skipped for tiny entries, which compress extremely well legitimately.
    ratio_min_bytes: int = 64 * 1024


class ScanTimeout(Exception):
    """Raised when the scan deadline passes."""


class Deadline:
    def __init__(self, seconds: float) -> None:
        self._end = time.monotonic() + seconds
        self.seconds = seconds

    def check(self) -> None:
        if time.monotonic() > self._end:
            raise ScanTimeout(f"scan exceeded the {self.seconds:g}s time limit")
