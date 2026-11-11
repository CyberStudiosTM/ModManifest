from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from modmanifest import __version__
from modmanifest.cli import app
from modmanifest.codes import AI_CODES, CODES
from modmanifest.models import sanitize

from .helpers import inzoi_manifest, make_dbpf, make_zip, write_tree

runner = CliRunner()

TOP_KEYS = {
    "schema_version",
    "tool",
    "version",
    "command",
    "target",
    "game",
    "scan",
    "recognized_files",
    "capabilities_exercised",
    "package",
    "findings",
    "summary",
    "unsupported",
    "inspection_errors",
    "ai_metadata",
}


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_missing_path_is_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["inspect", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_invalid_game_is_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path), "--game", "other"])
    assert result.exit_code == 2


def test_json_schema_is_stable(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest()})
    for cmd in (["inspect"], ["audit-ai"], ["validate", "--game", "inzoi"]):
        args = [cmd[0], str(tmp_path / "M"), *cmd[1:], "--json"]
        result = runner.invoke(app, args)
        data = json.loads(result.stdout)
        assert set(data) == TOP_KEYS
        assert data["schema_version"] == 1
        assert set(data["summary"]) == {"PASS", "WARNING", "ERROR", "UNSUPPORTED", "NOT_CHECKED"}
        for f in data["findings"]:
            assert set(f) == {
                "code",
                "status",
                "title",
                "basis",
                "message",
                "source",
                "location",
                "details",
            }


def test_exit_zero_clean_package(tmp_path: Path) -> None:
    p = tmp_path / "a.package"
    p.write_bytes(make_dbpf())
    assert runner.invoke(app, ["validate", str(p), "--game", "sims4"]).exit_code == 0


def test_exit_one_on_validation_error(tmp_path: Path) -> None:
    p = tmp_path / "a.package"
    p.write_bytes(b"junk" * 40)
    assert runner.invoke(app, ["validate", str(p), "--game", "sims4"]).exit_code == 1


def test_exit_three_when_nothing_recognized(tmp_path: Path) -> None:
    (tmp_path / "x.txt").write_text("x")
    result = runner.invoke(app, ["validate", str(tmp_path), "--game", "inzoi", "--json"])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["scan"]["status"] == "nothing_recognized"


def test_exit_three_when_incomplete(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "a.zip", {f"f{i}": "x" for i in range(5)})
    result = runner.invoke(app, ["inspect", str(z), "--max-entries", "2"])
    assert result.exit_code == 3


def test_ai_indicators_do_not_change_exit_code(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/mod_manifest.json": '{"AIGenerated": true}'})
    assert runner.invoke(app, ["audit-ai", str(tmp_path / "a")]).exit_code == 0


def test_terminal_output_escapes_markup_and_controls(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"M/mod_manifest.json": inzoi_manifest(FriendlyName="[red]x[/red]\x1b[31m")}
    )
    result = runner.invoke(app, ["inspect", str(tmp_path / "M"), "--verbose"])
    assert "\x1b" not in result.output
    assert result.exit_code == 0


def test_json_has_no_absolute_paths(tmp_path: Path) -> None:
    write_tree(tmp_path, {"M/mod_manifest.json": inzoi_manifest()})
    out = runner.invoke(app, ["inspect", str(tmp_path / "M"), "--json"]).stdout
    assert str(tmp_path) not in out


def test_sanitize_escapes_bidi_and_control() -> None:
    assert "\u202e" not in sanitize("a\u202eb\x00")


def test_all_emitted_codes_are_registered() -> None:
    src = Path(__file__).resolve().parents[1] / "src" / "modmanifest"
    used_f: set[str] = set()
    used_a: set[str] = set()
    for py in src.rglob("*.py"):
        if py.name == "codes.py":
            continue
        for code in re.findall(r"\"(MM-[A-Z0-9]+-\d{3})\"", py.read_text(encoding="utf-8")):
            (used_a if code.startswith("MM-AI-") else used_f).add(code)
    assert used_f <= set(CODES)
    assert used_a <= set(AI_CODES)


@pytest.mark.parametrize("code", sorted(CODES))
def test_code_basis_is_valid(code: str) -> None:
    assert CODES[code][1] in {
        "format-rule",
        "observed-convention",
        "safety-limit",
        "scan-coverage",
        "static-heuristic",
    }
