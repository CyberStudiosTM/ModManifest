from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modmanifest.archive.limits import ScanLimits
from modmanifest.inspector import run
from modmanifest.models import Report

from .helpers import make_zip


def codes(report: Report) -> set[str]:
    return {f.code for f in report.findings}


def test_traversal_entry_is_flagged_and_not_read(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"../evil.txt": "x", "ok.txt": "y"})
    report = run("inspect", str(z))
    assert "MM-ARC-002" in codes(report)


def test_absolute_and_drive_paths(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"/abs.txt": "x", "C:/drive.txt": "y"})
    report = run("inspect", str(z))
    assert sum(1 for f in report.findings if f.code == "MM-ARC-002") >= 2


def test_backslash_name_flagged(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("placeholder")
        info.filename = "dir\\file.txt"
        zf.writestr(info, "x")
    assert "MM-ARC-015" in codes(run("inspect", str(z)))


@pytest.mark.filterwarnings("ignore:Duplicate name")
def test_duplicate_entries(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.txt", "1")
        zf.writestr("a.txt", "2")
    assert "MM-ARC-003" in codes(run("inspect", str(z)))


def test_case_collision(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"A.txt": "1", "a.txt": "2"})
    assert "MM-ARC-004" in codes(run("inspect", str(z)))


def test_symlink_entry(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777) << 16
        zf.writestr(info, "target")
    assert "MM-ARC-005" in codes(run("inspect", str(z)))


def test_entry_count_limit_sets_incomplete(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {f"f{i}.txt": "x" for i in range(10)})
    report = run("inspect", str(z), limits=ScanLimits(max_entries=5))
    assert report.scan_status == "incomplete"
    assert "MM-ARC-007" in codes(report)


def test_compression_ratio_warning(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"big.txt": b"\x00" * (4 * 1024 * 1024)})
    assert "MM-ARC-010" in codes(run("inspect", str(z)))


def test_entry_size_limit(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"big.bin": b"abcdefgh" * 1000})
    report = run("inspect", str(z), limits=ScanLimits(max_entry_bytes=100))
    assert "MM-ARC-009" in codes(report)


def test_corrupt_zip(tmp_path: Path) -> None:
    z = tmp_path / "a.zip"
    z.write_bytes(b"PK\x03\x04not really a zip")
    report = run("inspect", str(z))
    assert "MM-ARC-001" in codes(report)
    assert report.has_errors


def test_nested_archive_not_opened(tmp_path: Path) -> None:
    inner = tmp_path / "inner.zip"
    make_zip(inner, {"a.txt": "x"})
    z = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    assert "MM-ARC-012" in codes(run("inspect", str(z)))


def test_signature_mismatch(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"pic.png": b"not a png at all"})
    assert "MM-ARC-013" in codes(run("inspect", str(z)))


def test_folder_symlink_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    (target / "secret.txt").write_text("x")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link").symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    report = run("inspect", str(root))
    assert "MM-ARC-020" in codes(report)
    assert all("secret" not in r.path for r in report.recognized_files)


def test_target_name_is_basename_only(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {"a.txt": "x"})
    data = run("inspect", str(z)).to_dict()
    assert data["target"]["name"] == "a.zip"
    assert str(tmp_path) not in str(data)
