"""Static, read-only script risk indicators.

Scripts are never imported, compiled or executed. Python source is parsed into a syntax tree,
compiled Python is searched for name and string references without being unmarshalled, and
Lua/JavaScript files get a text pattern scan. Results are heuristic references to capabilities
that deserve a human look. They are not a malware verdict, and an empty result is not a
statement that a script is safe.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from modmanifest.archive.limits import Deadline
from modmanifest.archive.sources import PackageSource, SourceReadError
from modmanifest.models import Finding, Report, Status, sanitize

NETWORK = "MM-SCR-001"
PROCESS = "MM-SCR-002"
DYNAMIC = "MM-SCR-003"
ENDPOINT = "MM-SCR-004"

PY_EXTS = (".py", ".pyc")
TEXT_SCRIPT_EXTS = (".lua", ".js")
SCRIPT_EXTS = PY_EXTS + TEXT_SCRIPT_EXTS

MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_SCRIPT_FILES = 2000
MAX_EXAMPLES = 5
LONG_ENCODED_STRING = 2000

_NETWORK_MODULES = {
    "socket", "ssl", "urllib2", "urllib3", "httplib", "requests", "aiohttp", "httpx",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "websocket", "websockets",
    "xmlrpc", "http",
}  # fmt: skip
_PROCESS_MODULES = {"subprocess", "ctypes", "cffi", "pty", "winreg", "_winreg", "webbrowser"}
_DYNAMIC_MODULES = {"marshal", "pickle", "cPickle", "importlib"}
_DYNAMIC_BUILTINS = {"exec", "eval", "compile", "__import__"}
_OS_PROCESS_CALLS = {"system", "popen", "startfile"}
_OS_PROCESS_PREFIXES = ("spawn", "exec")

# Names looked up as exact strings inside compiled Python. Names that are also common in
# ordinary game scripts (compile, system, popen) are left out to keep this quiet.
_BYTECODE_TOKENS: dict[str, tuple[str, ...]] = {
    NETWORK: (
        "socket", "ssl", "urllib.request", "urllib2", "urllib3", "http.client", "httplib",
        "requests", "aiohttp", "httpx", "ftplib", "smtplib", "telnetlib", "websocket",
        "websockets", "xmlrpc.client",
    ),
    PROCESS: (
        "subprocess", "ctypes", "cffi", "pty", "winreg", "_winreg", "webbrowser", "startfile",
        "Popen",
    ),
    DYNAMIC: ("exec", "eval", "__import__", "marshal", "pickle", "cPickle", "importlib"),
}  # fmt: skip

# Substrings searched case-insensitively in script text or compiled bytes.
_ENDPOINT_MARKERS = (
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
    "webhook.site",
    "pastebin.com",
    "hastebin",
    "transfer.sh",
    "gofile.io",
    "anonfiles",
    "ngrok",
    "login data",
    "local state",
    "leveldb",
    "web data",
)

_LUA_PATTERNS: dict[str, tuple[tuple[str, str], ...]] = {
    PROCESS: (
        (r"\bos\.execute\b", "os.execute"),
        (r"\bio\.popen\b", "io.popen"),
        (r"\bpackage\.loadlib\b", "package.loadlib"),
    ),
    DYNAMIC: (
        (r"\bloadstring\s*\(", "loadstring"),
        (r"\bload\s*\(", "load"),
        (r"\bdofile\s*\(", "dofile"),
    ),
    NETWORK: ((r"""require\s*\(?\s*["']socket""", "require socket"),),
}
_JS_PATTERNS: dict[str, tuple[tuple[str, str], ...]] = {
    PROCESS: ((r"\bchild_process\b", "child_process"),),
    DYNAMIC: (
        (r"\beval\s*\(", "eval"),
        (r"\bnew\s+Function\s*\(", "new Function"),
    ),
    NETWORK: (
        (r"\bXMLHttpRequest\b", "XMLHttpRequest"),
        (r"\bfetch\s*\(", "fetch"),
        (r"\bWebSocket\b", "WebSocket"),
        (r"\bnavigator\.sendBeacon\b", "sendBeacon"),
    ),
}


@dataclass(slots=True)
class ScriptScan:
    """Indicators found in one script: finding code -> sorted indicator names."""

    indicators: dict[str, list[str]] = field(default_factory=dict)
    analyzed: bool = True

    def add(self, code: str, name: str) -> None:
        names = self.indicators.setdefault(code, [])
        if name not in names:
            names.append(name)


def _ext(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""


def _scan_endpoints(scan: ScriptScan, data: bytes) -> None:
    lowered = data.lower()
    for marker in _ENDPOINT_MARKERS:
        if marker.encode() in lowered:
            scan.add(ENDPOINT, marker)


def _module_indicator(scan: ScriptScan, module: str, imported: Iterable[str] = ()) -> None:
    root = module.split(".")[0]
    if root == "urllib":
        names = set(imported)
        if module.startswith("urllib.request") or names & {"request", "urlopen"}:
            scan.add(NETWORK, "urllib.request")
    elif root in _NETWORK_MODULES:
        scan.add(NETWORK, root)
    if root in _PROCESS_MODULES:
        scan.add(PROCESS, root)
    if root in _DYNAMIC_MODULES:
        scan.add(DYNAMIC, root)


def _scan_python_source(scan: ScriptScan, data: bytes) -> None:
    try:
        tree = ast.parse(data.decode("utf-8", "replace"))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        scan.analyzed = False
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _module_indicator(scan, alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            _module_indicator(scan, node.module, (a.name for a in node.names))
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _DYNAMIC_BUILTINS:
                scan.add(DYNAMIC, func.id)
            elif (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and (func.attr in _OS_PROCESS_CALLS or func.attr.startswith(_OS_PROCESS_PREFIXES))
            ):
                scan.add(PROCESS, f"os.{func.attr}")
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and len(node.value) >= LONG_ENCODED_STRING
            and re.fullmatch(r"[A-Za-z0-9+/=\s]+", node.value)
        ):
            scan.add(DYNAMIC, "long encoded string")


def _bytecode_pattern(token: str) -> re.Pattern[bytes]:
    raw = re.escape(token.encode())
    n = len(token)
    # Marshal short strings: type byte (with or without the ref flag) then a one-byte length.
    short = rb"[zZ\xfa\xda]" + re.escape(bytes([n])) if n < 256 else b""
    # Older marshal strings: type byte then a four-byte little-endian length.
    long_ = rb"[aAtu\xe1\xc1\xf4\xf5]" + re.escape(n.to_bytes(4, "little"))
    return re.compile(b"(?:" + short + b"|" + long_ + b")" + raw)


_BYTECODE_PATTERNS: list[tuple[str, str, re.Pattern[bytes]]] = [
    (code, token, _bytecode_pattern(token))
    for code, tokens in _BYTECODE_TOKENS.items()
    for token in tokens
]


def _scan_python_bytecode(scan: ScriptScan, data: bytes) -> None:
    for code, token, pattern in _BYTECODE_PATTERNS:
        if pattern.search(data):
            scan.add(code, token)


def _scan_text(
    scan: ScriptScan, data: bytes, patterns: dict[str, tuple[tuple[str, str], ...]]
) -> None:
    text = data.decode("utf-8", "replace")
    for code, entries in patterns.items():
        for pattern, name in entries:
            if re.search(pattern, text):
                scan.add(code, name)


def scan_script(path: str, data: bytes) -> ScriptScan:
    """Scan one script's bytes. ``path`` only selects the format by extension."""
    scan = ScriptScan()
    ext = _ext(path)
    if ext == ".py":
        _scan_python_source(scan, data)
    elif ext == ".pyc":
        _scan_python_bytecode(scan, data)
    elif ext == ".lua":
        _scan_text(scan, data, _LUA_PATTERNS)
    elif ext == ".js":
        _scan_text(scan, data, _JS_PATTERNS)
    _scan_endpoints(scan, data)
    for names in scan.indicators.values():
        names.sort()
    return scan


_MESSAGES = {
    NETWORK: "{n} script file(s) reference network capabilities",
    PROCESS: "{n} script file(s) reference process execution, native code or system access",
    DYNAMIC: "{n} script file(s) reference dynamic code execution or encoded payloads",
    ENDPOINT: "{n} script file(s) reference file-hosting, webhook or credential-store markers",
}


def audit_scripts(
    report: Report,
    source: PackageSource,
    deadline: Deadline,
    label: str | None,
    paths: Iterable[str],
    max_entry_bytes: int,
) -> None:
    """Scan ``paths`` in ``source`` and add summary findings for ``label``."""
    max_bytes = min(max_entry_bytes, MAX_SCRIPT_BYTES)
    hits: dict[str, list[tuple[str, list[str]]]] = {}
    scanned = skipped = unparsed = 0
    for path in paths:
        deadline.check()
        if scanned + skipped >= MAX_SCRIPT_FILES:
            skipped += 1
            continue
        try:
            data = source.read_bytes(path, max_bytes)
        except SourceReadError:
            skipped += 1
            continue
        scan = scan_script(path, data)
        scanned += 1
        unparsed += not scan.analyzed
        for code, names in scan.indicators.items():
            hits.setdefault(code, []).append((path, names))
    if scanned:
        report.capability("scripts.static-indicators")
    for code in (NETWORK, PROCESS, DYNAMIC, ENDPOINT):
        found = hits.get(code)
        if not found:
            continue
        report.add(
            Finding(
                code,
                Status.WARNING,
                _MESSAGES[code].format(n=len(found)) + "; this is a reference, not proof of misuse",
                source=label,
                details={
                    "examples": [
                        {"path": sanitize(p), "indicators": [sanitize(i, 60) for i in names[:5]]}
                        for p, names in found[:MAX_EXAMPLES]
                    ]
                },
            )
        )
    if unparsed:
        report.add(
            Finding(
                "MM-SCR-007",
                Status.NOT_CHECKED,
                f"{unparsed} Python source file(s) could not be parsed and were not scanned "
                "for code indicators",
                source=label,
            )
        )
    if skipped:
        report.add(
            Finding(
                "MM-SCR-006",
                Status.NOT_CHECKED,
                f"{skipped} script file(s) were too large, unreadable or over the file limit "
                "and were not scanned",
                source=label,
            )
        )
    if scanned and not hits and not unparsed and not skipped:
        report.add(
            Finding(
                "MM-SCR-005",
                Status.PASS,
                f"{scanned} script file(s) scanned; no indicators found. This is not a "
                "statement that the scripts are safe",
                source=label,
            )
        )
