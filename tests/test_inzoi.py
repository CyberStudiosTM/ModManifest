from __future__ import annotations

from pathlib import Path

from modmanifest.inspector import run
from modmanifest.models import Report, Status

from .helpers import inzoi_manifest, make_zip, write_tree


def st(report: Report, code: str) -> list[Status]:
    return [f.status for f in report.findings if f.code == code]


def mod_tree(tmp_path: Path, **extra: bytes | str) -> Path:
    files: dict[str, bytes | str] = {"SampleMod/mod_manifest.json": inzoi_manifest()}
    files.update({f"SampleMod/{k}": v for k, v in extra.items()})
    write_tree(tmp_path, files)
    return tmp_path / "SampleMod"


def test_candidate_not_proof(tmp_path: Path) -> None:
    report = run("validate", str(mod_tree(tmp_path)), "inzoi")
    assert st(report, "MM-INZ-001") == [Status.PASS]
    assert st(report, "MM-INZ-015") == [Status.NOT_CHECKED]
    assert report.package_info["inzoi"]["manifest"]["Author"] == "Tester"
    assert not report.has_errors


def test_missing_fields_are_not_errors(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": '{"Unknown": 1}'})
    report = run("validate", str(tmp_path / "M"), "inzoi")
    assert not report.has_errors
    assert not st(report, "MM-INZ-004")


def test_invalid_json(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": "{nope"})
    assert st(run("validate", str(tmp_path / "M"), "inzoi"), "MM-INZ-002") == [Status.ERROR]


def test_non_object_root(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": "[1]"})
    assert st(run("validate", str(tmp_path / "M"), "inzoi"), "MM-INZ-003") == [Status.ERROR]


def test_type_mismatch_is_warning(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest(bEnable="yes", LoadOrder=True)})
    report = run("validate", str(tmp_path / "M"), "inzoi")
    assert st(report, "MM-INZ-004") == [Status.WARNING, Status.WARNING]


def test_project_name_comparison_informational(tmp_path: Path) -> None:
    write_tree(tmp_path, {"Other/mod_manifest.json": inzoi_manifest()})
    report = run("validate", str(tmp_path / "Other"), "inzoi")
    assert st(report, "MM-INZ-005") == [Status.NOT_CHECKED]
    assert not report.has_errors


def test_checksums_never_verified(tmp_path: Path) -> None:
    sums = ["a.lua|" + "0" * 32, "missing.lua|" + "1" * 32]
    write_tree(
        tmp_path,
        {"SampleMod/mod_manifest.json": inzoi_manifest(FileChecksums=sums), "SampleMod/a.lua": "x"},
    )
    report = run("validate", str(tmp_path / "SampleMod"), "inzoi")
    assert st(report, "MM-INZ-009") == [Status.NOT_CHECKED]
    assert st(report, "MM-INZ-007") == [Status.WARNING]
    assert report.package_info["inzoi"]["file_checksums"]["verified"] is False


def test_checksum_unsafe_and_malformed(tmp_path: Path) -> None:
    sums = ["../x|" + "0" * 32, "bad-entry", 5]
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest(FileChecksums=sums)})
    report = run("validate", str(tmp_path / "M"), "inzoi")
    assert st(report, "MM-INZ-006") == [Status.ERROR]
    assert st(report, "MM-INZ-008") == [Status.WARNING]


def test_unreal_containers_recognized_uninspected(tmp_path: Path) -> None:
    root = mod_tree(
        tmp_path,
        **{
            "Content/Paks/Windows/a.pak": b"x",
            "Content/Paks/Windows/a.ucas": b"x",
            "Content/Paks/Windows/a.utoc": b"x",
        },
    )
    report = run("validate", str(root), "inzoi")
    assert st(report, "MM-INZ-010") == [Status.NOT_CHECKED]
    assert not st(report, "MM-INZ-011")
    assert report.unsupported == []


def test_incomplete_iostore_pair(tmp_path: Path) -> None:
    root = mod_tree(tmp_path, **{"a.ucas": b"x"})
    assert st(run("validate", str(root), "inzoi"), "MM-INZ-011") == [Status.WARNING]


def test_library_folder_is_not_walked(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "A/mod_manifest.json": inzoi_manifest(),
            ".modding/state.json": "{}",
            "Connect/x.txt": "x",
        },
    )
    report = run("validate", str(tmp_path), "inzoi")
    assert st(report, "MM-INZ-014") == [Status.NOT_CHECKED]
    assert not report.has_errors


def test_zip_with_single_root(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "m.zip", {"SampleMod/mod_manifest.json": inzoi_manifest()})
    report = run("validate", str(z), "inzoi")
    assert st(report, "MM-INZ-001") == [Status.PASS]
    assert st(report, "MM-INZ-005") == [Status.PASS]


def test_dependencies_and_version_not_verified(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest(Dependencies=["Other"])})
    report = run("validate", str(tmp_path / "M"), "inzoi")
    assert st(report, "MM-INZ-013") == [Status.NOT_CHECKED]
    assert st(report, "MM-INZ-017") == [Status.NOT_CHECKED]


def test_inspect_detects_both_games(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest()})
    report = run("inspect", str(tmp_path / "M"))
    assert report.game_detected == "inzoi"
