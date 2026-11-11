"""Structural validation of DBPF 2.x packages as used by The Sims 4.

Layout verified against the s4pi reference implementation: a 96-byte header with the
``DBPF`` magic, version fields at 4 and 8, entry count at 36, index size at 44 and index
offset at 64 (falling back to 40). The index begins with a flags word whose low three bits
mark type, group and instance-high as constant for every entry, followed by those constant
values and then fixed-width entries. Resource contents are never decoded.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

from modmanifest.models import Finding, Report, Status

HEADER_SIZE = 96
MAX_INDEX_BYTES = 64 * 1024 * 1024
_FIELDS_PER_ENTRY = 8  # type, group, instance-high, instance-low, offset, size, memsize, flags


def _u32(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", buf, off)[0])


def validate_dbpf(fh: BinaryIO, size: int, path: str, report: Report) -> int | None:
    """Validate one package. Returns the resource count when the index was verified."""
    errors_before = sum(1 for f in report.findings if f.status is Status.ERROR)

    def add(code: str, status: Status, message: str, **details: object) -> None:
        report.add(Finding(code, status, message, source=path, details=dict(details)))

    if size < HEADER_SIZE:
        add("MM-S4-002", Status.ERROR, f"file is {size} bytes; a DBPF header needs {HEADER_SIZE}")
        return None
    header = fh.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE or header[:4] != b"DBPF":
        add("MM-S4-002", Status.ERROR, "missing 'DBPF' signature at the start of the file")
        return None
    major, minor = _u32(header, 4), _u32(header, 8)
    if (major, minor) != (2, 1):
        add(
            "MM-S4-003",
            Status.UNSUPPORTED,
            f"DBPF version {major}.{minor}; this tool validates version 2.1 only",
            major=major,
            minor=minor,
        )
        return None
    count = _u32(header, 36)
    index_size = _u32(header, 44)
    index_pos = _u32(header, 64) or _u32(header, 40)
    add("MM-S4-001", Status.PASS, "DBPF 2.1 signature and header size verified", entries=count)
    report.capability("sims4.dbpf.header")
    if count == 0:
        add("MM-S4-009", Status.WARNING, "the header declares zero resources")
        return 0
    if index_pos < HEADER_SIZE or index_pos + index_size > size:
        add(
            "MM-S4-004",
            Status.ERROR,
            "index lies outside the file or overlaps the header",
            index_offset=index_pos,
            index_size=index_size,
            file_size=size,
        )
        return None
    if count * 20 > index_size:
        add(
            "MM-S4-004",
            Status.ERROR,
            f"index of {index_size} bytes cannot hold {count} entries",
            entries=count,
            index_size=index_size,
        )
        return None
    if index_size > MAX_INDEX_BYTES:
        add("MM-S4-007", Status.UNSUPPORTED, "index is too large to read within scan limits")
        return None
    fh.seek(index_pos)
    index = fh.read(index_size)
    if len(index) < 4 or len(index) < index_size:
        add("MM-S4-004", Status.ERROR, "the file ended before the index was complete")
        return None
    flags = _u32(index, 0)
    if flags & ~0x7:
        add(
            "MM-S4-007",
            Status.UNSUPPORTED,
            f"index flags 0x{flags:x} use bits beyond the constant type/group/instance fields",
        )
        return None
    const_count = bin(flags & 0x7).count("1")
    entry_ints = _FIELDS_PER_ENTRY - const_count
    expected = 4 + 4 * const_count + count * entry_ints * 4
    if index_size < expected:
        add(
            "MM-S4-004",
            Status.ERROR,
            f"index size {index_size} is smaller than the {expected} bytes its flags and "
            "entry count require",
            expected=expected,
        )
        return None
    if index_size > expected:
        add(
            "MM-S4-004",
            Status.WARNING,
            f"index size {index_size} is larger than the {expected} bytes its flags and "
            "entry count require",
            expected=expected,
        )
    consts: list[int] = []
    pos = 4
    for bit in range(3):
        if flags & (1 << bit):
            consts.append(_u32(index, pos))
            pos += 4
    seen: set[tuple[int, int, int, int]] = set()
    duplicates = 0
    bad_range = 0
    first_bad: int | None = None
    flag_values: dict[str, int] = {}
    for i in range(count):
        ints = struct.unpack_from(f"<{entry_ints - 1}I", index, pos)
        comp = struct.unpack_from("<H", index, pos + (entry_ints - 1) * 4)[0]
        pos += entry_ints * 4
        vals = list(ints)
        ci = iter(consts)
        rtype = next(ci) if flags & 1 else vals.pop(0)
        group = next(ci) if flags & 2 else vals.pop(0)
        inst_hi = next(ci) if flags & 4 else vals.pop(0)
        inst_lo, offset, filesize = vals[0], vals[1], vals[2] & 0x7FFFFFFF
        key = (rtype, group, inst_hi, inst_lo)
        if key in seen:
            duplicates += 1
        seen.add(key)
        if offset < HEADER_SIZE or offset + filesize > size:
            bad_range += 1
            if first_bad is None:
                first_bad = i
        name = f"0x{comp:04X}"
        flag_values[name] = flag_values.get(name, 0) + 1
    if bad_range:
        add(
            "MM-S4-005",
            Status.ERROR,
            f"{bad_range} of {count} resources point outside the file or into the header",
            first_index=first_bad,
            file_size=size,
        )
    if duplicates:
        add(
            "MM-S4-006",
            Status.WARNING,
            f"{duplicates} resources repeat an earlier type/group/instance key",
        )
    report.capability("sims4.dbpf.index")
    if sum(1 for f in report.findings if f.status is Status.ERROR) == errors_before:
        add(
            "MM-S4-008",
            Status.PASS,
            f"index structure verified for {count} resources; contents were not decoded",
            entries=count,
            compression_flags=flag_values,
        )
    return count
