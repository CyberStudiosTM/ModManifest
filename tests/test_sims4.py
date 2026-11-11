from __future__ import annotations

import struct
from pathlib import Path

from modmanifest.inspector import run
from modmanifest.models import Report, Status

from .helpers import make_dbpf, make_zip


def by_code(report: Report, code: str) -> list[Status]:
    return [f.status for f in report.findings if f.code == code]


def test_valid_package(tmp_path: Path) -> None:
    p = tmp_path / "m.package"
    p.write_bytes(make_dbpf())
    report = run("validate", str(p), "sims4")
    assert by_code(report, "MM-S4-001") == [Status.PASS]
    assert by_code(report, "MM-S4-008") == [Status.PASS]
    assert by_code(report, "MM-S4-013") == [Status.NOT_CHECKED]
    assert not report.has_errors


def test_bad_magic(tmp_path: Path) -> None:
    p = tmp_path / "m.package"
    p.write_bytes(b"NOPE" + b"\x00" * 200)
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-002") == [Status.ERROR]


def test_truncated_header(tmp_path: Path) -> None:
    p = tmp_path / "m.package"
    p.write_bytes(b"DBPF" + b"\x00" * 20)
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-002") == [Status.ERROR]


def test_unsupported_version(tmp_path: Path) -> None:
    data = bytearray(make_dbpf())
    struct.pack_into("<II", data, 4, 1, 1)
    p = tmp_path / "m.package"
    p.write_bytes(bytes(data))
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-003") == [Status.UNSUPPORTED]


def test_index_out_of_bounds(tmp_path: Path) -> None:
    data = bytearray(make_dbpf())
    struct.pack_into("<I", data, 64, len(data) + 1000)
    p = tmp_path / "m.package"
    p.write_bytes(bytes(data))
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-004") == [Status.ERROR]


def test_resource_outside_file(tmp_path: Path) -> None:
    data = bytearray(make_dbpf())
    index_pos = struct.unpack_from("<I", data, 64)[0]
    struct.pack_into("<I", data, index_pos + 4 + 5 * 4, 0x7FFFFFF0)  # file size field
    p = tmp_path / "m.package"
    p.write_bytes(bytes(data))
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-005") == [Status.ERROR]


def test_duplicate_keys_warn(tmp_path: Path) -> None:
    p = tmp_path / "m.package"
    p.write_bytes(make_dbpf([(1, 2, 3, 4, b"a"), (1, 2, 3, 4, b"b")]))
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-006") == [Status.WARNING]


def test_truncated_index(tmp_path: Path) -> None:
    data = make_dbpf()
    p = tmp_path / "m.package"
    p.write_bytes(data[:-10])
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-004") == [Status.ERROR]


def test_empty_package_warns(tmp_path: Path) -> None:
    p = tmp_path / "m.package"
    p.write_bytes(make_dbpf([]))
    assert by_code(run("validate", str(p), "sims4"), "MM-S4-009") == [Status.WARNING]


def test_package_inside_zip_and_always_notes(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "m.zip", {"Mods/a.package": make_dbpf()})
    report = run("validate", str(z), "sims4")
    assert by_code(report, "MM-S4-008") == [Status.PASS]
    assert by_code(report, "MM-S4-015") == [Status.NOT_CHECKED]


def test_ts4script_valid_and_empty(tmp_path: Path) -> None:
    good = make_zip(tmp_path / "a.ts4script", {"pkg/mod.pyc": b"\x6f\x0d\r\n" + b"\x00" * 20})
    report = run("validate", str(good), "sims4")
    assert by_code(report, "MM-S4-010") == [Status.PASS]
    assert by_code(report, "MM-S4-014") == [Status.NOT_CHECKED]
    empty = make_zip(tmp_path / "b.ts4script", {"readme.txt": "x"})
    assert by_code(run("validate", str(empty), "sims4"), "MM-S4-011") == [Status.WARNING]


def test_bad_pyc_header(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.ts4script", {"mod.pyc": b"garbage" * 5})
    assert by_code(run("validate", str(z), "sims4"), "MM-S4-012") == [Status.WARNING]


def test_ts4script_inside_zip(tmp_path: Path) -> None:
    inner = make_zip(tmp_path / "i.ts4script", {"mod.py": "x = 1"})
    z = make_zip(tmp_path / "o.zip", {"a.ts4script": inner.read_bytes()})
    assert by_code(run("validate", str(z), "sims4"), "MM-S4-010") == [Status.PASS]


def test_nothing_recognized(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("hello")
    report = run("validate", str(tmp_path), "sims4")
    assert report.scan_status == "nothing_recognized"
