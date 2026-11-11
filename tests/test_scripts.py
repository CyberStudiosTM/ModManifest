from __future__ import annotations

import marshal
import struct
from pathlib import Path

from modmanifest.inspector import run
from modmanifest.models import Report, Status
from modmanifest.scripts import DYNAMIC, ENDPOINT, NETWORK, PROCESS, scan_script

from .helpers import inzoi_manifest, make_zip, write_tree


def make_pyc(source: str) -> bytes:
    header = b"B\r\r\n" + struct.pack("<III", 0, 0, 0)
    return header + marshal.dumps(compile(source, "mod.py", "exec"))


def make_ts4script(path: Path, files: dict[str, bytes | str]) -> Path:
    return make_zip(path, files)


def statuses(report: Report, code: str) -> list[Status]:
    return [f.status for f in report.findings if f.code == code]


def test_source_indicators() -> None:
    src = (
        "import socket, subprocess\n"
        "from urllib import request\n"
        "import os\n"
        "os.system('x')\n"
        "exec('1')\n"
    )
    ind = scan_script("m.py", src.encode()).indicators
    assert ind[NETWORK] == ["socket", "urllib.request"]
    assert ind[PROCESS] == ["os.system", "subprocess"]
    assert ind[DYNAMIC] == ["exec"]


def test_benign_source_has_no_indicators() -> None:
    src = "import re, urllib.parse\nre.compile('x')\nprint(urllib.parse.quote('a'))\n"
    assert scan_script("m.py", src.encode()).indicators == {}


def test_bytecode_indicators() -> None:
    pyc = make_pyc("import subprocess, socket\nimport http.client\neval('1')\n")
    ind = scan_script("m.pyc", pyc).indicators
    assert ind[PROCESS] == ["subprocess"]
    assert ind[NETWORK] == ["http.client", "socket"]
    assert ind[DYNAMIC] == ["eval"]


def test_bytecode_ignores_ordinary_names() -> None:
    pyc = make_pyc("import re\nre.compile('x')\nsystem = 1\n")
    assert scan_script("m.pyc", pyc).indicators == {}


def test_endpoint_markers() -> None:
    data = b"url = 'https://discord.com/api/webhooks/1/abc'"
    assert scan_script("m.py", data).indicators[ENDPOINT] == ["discord.com/api/webhooks"]


def test_unparseable_source_is_not_checked_not_clean(tmp_path: Path) -> None:
    zpath = make_ts4script(tmp_path / "m.ts4script", {"a.py": "print 'x' +"})
    report = run("inspect", str(zpath))
    assert statuses(report, "MM-SCR-007") == [Status.NOT_CHECKED]
    assert statuses(report, "MM-SCR-005") == []


def test_ts4script_flags_compiled_indicators(tmp_path: Path) -> None:
    zpath = make_ts4script(
        tmp_path / "m.ts4script",
        {"a.pyc": make_pyc("import subprocess\nimport socket\n"), "b.pyc": make_pyc("x = 1\n")},
    )
    report = run("inspect", str(zpath))
    assert statuses(report, "MM-SCR-001") == [Status.WARNING]
    assert statuses(report, "MM-SCR-002") == [Status.WARNING]
    assert statuses(report, "MM-SCR-005") == []
    finding = next(f for f in report.findings if f.code == "MM-SCR-002")
    assert finding.details["examples"][0]["path"] == "a.pyc"
    assert "scripts.static-indicators" in report.capabilities
    assert not report.has_errors


def test_clean_ts4script_reports_scan_without_claiming_safety(tmp_path: Path) -> None:
    zpath = make_ts4script(tmp_path / "m.ts4script", {"a.pyc": make_pyc("x = 1\n")})
    report = run("inspect", str(zpath))
    assert statuses(report, "MM-SCR-005") == [Status.PASS]
    msg = next(f.message for f in report.findings if f.code == "MM-SCR-005")
    assert "not a statement that the scripts are safe" in msg
    assert statuses(report, "MM-S4-014") == [Status.NOT_CHECKED]


def test_script_inside_zip_package(tmp_path: Path) -> None:
    inner = make_ts4script(tmp_path / "inner.ts4script", {"a.py": "import ctypes\n"})
    zpath = make_zip(tmp_path / "bundle.zip", {"Mods/inner.ts4script": inner.read_bytes()})
    report = run("inspect", str(zpath))
    assert statuses(report, "MM-SCR-002") == [Status.WARNING]


def test_loose_python_in_folder(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "mod", {"a.package": b"x", "loose.py": "import socket\n"})
    report = run("inspect", str(root))
    assert statuses(report, "MM-SCR-001") == [Status.WARNING]


def test_inzoi_lua_and_js(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path / "t",
        {
            "SampleMod/mod_manifest.json": inzoi_manifest(),
            "SampleMod/a.lua": "os.execute('calc')\nloadstring('x')()\n",
            "SampleMod/ui.js": "fetch('http://example.test')\n",
            "SampleMod/ui.css": "body{}",
        },
    )
    report = run("inspect", str(root))
    assert statuses(report, "MM-SCR-002") == [Status.WARNING]
    assert statuses(report, "MM-SCR-003") == [Status.WARNING]
    assert statuses(report, "MM-SCR-001") == [Status.WARNING]
    assert statuses(report, "MM-INZ-012") == [Status.NOT_CHECKED]


def test_json_report_includes_indicator_details(tmp_path: Path) -> None:
    zpath = make_ts4script(tmp_path / "m.ts4script", {"a.pyc": make_pyc("import socket\n")})
    data = run("inspect", str(zpath)).to_dict()
    finding = next(f for f in data["findings"] if f["code"] == "MM-SCR-001")
    assert finding["basis"] == "static-heuristic"
    assert finding["details"]["examples"][0]["indicators"] == ["socket"]
