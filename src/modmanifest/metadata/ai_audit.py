"""Evidence-based audit of AI-related metadata indicators.

Findings describe what metadata a package contains. They never describe how the package
was made, and a missing indicator is never read as evidence of anything.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterator
from typing import Any

import yaml
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from modmanifest.context import ScanContext
from modmanifest.metadata import ai_signatures as sig
from modmanifest.metadata.parsers import PNG_MAGIC, parse_jpeg, parse_png, parse_xmp
from modmanifest.models import AIFinding, Category

TEXT_EXTS = (".json", ".toml", ".yaml", ".yml", ".xml", ".txt", ".md", ".uplugin")
MANIFEST_HINTS = ("manifest", "modinfo", "metadata", "readme", "credits", "about", "uplugin")
IMAGE_EXTS = (".png", ".jpg", ".jpeg")
MAX_IMAGES = 500
MAX_NODES = 5000
LIMIT_NOTE = (
    "Only listed metadata containers are examined; image pixels, scripts and binary game data "
    "are not analyzed."
)
CONFIDENCE_NOTE = (
    "Confidence applies to how the metadata is interpreted, not to how the package was made."
)


def _ext(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""


def _walk(obj: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, str, Any]]:
    budget = [MAX_NODES]

    def rec(o: Any, p: str, d: int) -> Iterator[tuple[str, str, Any]]:
        if d > 8 or budget[0] <= 0:
            return
        budget[0] -= 1
        if isinstance(o, dict):
            for k, v in o.items():
                kp = f"{p}.{k}" if p else str(k)
                yield kp, str(k), v
                yield from rec(v, kp, d + 1)
        elif isinstance(o, list):
            for i, v in enumerate(o[:200]):
                yield from rec(v, f"{p}[{i}]", d + 1)

    yield from rec(obj, path, depth)


class _Audit:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.findings: list[AIFinding] = []

    def add(
        self,
        code: str,
        cat: Category,
        source: str,
        location: str,
        evidence: str,
        explanation: str,
        confidence: str,
        polarity: str = "unspecified",
    ) -> None:
        self.findings.append(
            AIFinding(
                code,
                cat,
                source,
                location,
                evidence,
                explanation,
                confidence,
                polarity,
                [CONFIDENCE_NOTE, LIMIT_NOTE],
            )
        )

    def structured(self, source: str, doc: Any) -> None:
        for loc, key, value in _walk(doc):
            nk = sig.normalize_key(key)
            if nk in sig.BOOLEAN_KEYS:
                flag = value if isinstance(value, bool) else None
                if flag is None and isinstance(value, str) and value.lower() in ("true", "false"):
                    flag = value.lower() == "true"
                if flag is not None:
                    self.add(
                        "MM-AI-001",
                        Category.EXPLICIT,
                        source,
                        loc,
                        f"{key} = {str(flag).lower()}",
                        "The manifest contains a boolean field whose name states AI involvement.",
                        "high",
                        "affirmative" if flag else "negative",
                    )
            elif nk in sig.DISCLOSURE_KEYS and isinstance(value, (str, list)):
                self.add(
                    "MM-AI-002",
                    Category.EXPLICIT,
                    source,
                    loc,
                    f"{key} = {value}",
                    "The manifest contains a field intended for an AI disclosure.",
                    "high",
                )
            elif nk in sig.TOOL_KEYS and isinstance(value, str):
                self.tool(source, loc, key, value)
            elif nk in sig.FREE_TEXT_KEYS and isinstance(value, str):
                self.free_text(source, loc, value)

    def tool(self, source: str, loc: str, key: str, value: str) -> None:
        kind = sig.match_tool(value)
        if kind == "unambiguous":
            self.add(
                "MM-AI-003",
                Category.TOOL,
                source,
                loc,
                f"{key} = {value}",
                "A tool field names software commonly used to generate content.",
                "medium",
            )
        elif kind == "ambiguous":
            self.add(
                "MM-AI-003",
                Category.AMBIGUOUS,
                source,
                loc,
                f"{key} = {value}",
                "A tool field contains a name that may or may not refer to an AI product.",
                "low",
            )

    def free_text(self, source: str, loc: str, text: str) -> None:
        for pat in sig.FREE_TEXT_PATTERNS:
            m = pat.search(text)
            if m:
                self.add(
                    "MM-AI-004",
                    Category.AMBIGUOUS,
                    source,
                    loc,
                    m.group(0),
                    "Descriptive text mentions AI; free text is not a structured declaration.",
                    "low",
                )
                return

    def plain_text(self, source: str, text: str) -> None:
        for line_no, line in enumerate(text.splitlines()[:2000], 1):
            for pat in sig.FREE_TEXT_PATTERNS:
                m = pat.search(line)
                if m:
                    self.add(
                        "MM-AI-004",
                        Category.AMBIGUOUS,
                        source,
                        f"line {line_no}",
                        m.group(0),
                        "Text mentions AI; free text is not a structured declaration.",
                        "low",
                    )
                    return

    def image(self, path: str, data: bytes) -> None:
        if data.startswith(PNG_MAGIC):
            meta = parse_png(data)
        elif data.startswith(b"\xff\xd8"):
            meta = parse_jpeg(data)
        else:
            return
        for key, value in meta.text:
            lk = key.lower()
            loc = f"text chunk '{key}'"
            if lk == "parameters" and "Steps:" in value and "Sampler:" in value:
                self.add(
                    "MM-AI-010",
                    Category.EXPLICIT,
                    path,
                    loc,
                    f"chunk '{key}' with generation settings",
                    "The chunk has the structure of a diffusion-style generation record. "
                    "Its text is deliberately not reproduced.",
                    "high",
                )
            elif lk in ("prompt", "workflow") and '"class_type"' in value:
                self.add(
                    "MM-AI-011",
                    Category.EXPLICIT,
                    path,
                    loc,
                    f"chunk '{key}' with node graph",
                    "The chunk holds a node-graph workflow. Its text is not reproduced.",
                    "high",
                )
            elif lk in sig.PNG_TOOL_KEYS:
                self.add(
                    "MM-AI-013",
                    Category.TOOL,
                    path,
                    loc,
                    f"chunk '{key}' present",
                    "The chunk key is specific to a known generation tool.",
                    "high",
                )
            elif lk in ("software", "source", "comment") and sig.match_tool(value):
                kind = sig.match_tool(value)
                self.add(
                    "MM-AI-012",
                    Category.TOOL if kind == "unambiguous" else Category.AMBIGUOUS,
                    path,
                    loc,
                    f"{key} = {value}",
                    "A software field names a possible generation tool.",
                    "medium" if kind == "unambiguous" else "low",
                )
        for k, v in meta.exif.items():
            if sig.match_tool(v):
                kind = sig.match_tool(v)
                self.add(
                    "MM-AI-030",
                    Category.TOOL if kind == "unambiguous" else Category.AMBIGUOUS,
                    path,
                    f"EXIF {k}",
                    f"{k} = {v}",
                    "An EXIF field names a possible generation tool.",
                    "medium" if kind == "unambiguous" else "low",
                )
        for blob in meta.xmp_blobs:
            self.xmp(path, blob)
        if meta.c2pa_marker:
            self.c2pa(path, "embedded provenance structure")

    def xmp(self, path: str, blob: bytes) -> None:
        props = parse_xmp(blob)
        if not props:
            return
        for value in props.get("DigitalSourceType", []):
            tail = value.rsplit("/", 1)[-1].lower()
            if tail in sig.AI_SOURCE_TYPES:
                self.add(
                    "MM-AI-020",
                    Category.EXPLICIT,
                    path,
                    "XMP DigitalSourceType",
                    tail,
                    "XMP declares a digital source type for AI-generated or AI-composited media.",
                    "high",
                    "affirmative",
                )
            elif tail in sig.AMBIGUOUS_SOURCE_TYPES:
                self.add(
                    "MM-AI-020",
                    Category.AMBIGUOUS,
                    path,
                    "XMP DigitalSourceType",
                    tail,
                    "XMP declares an algorithmic source type that does not by itself mean AI.",
                    "low",
                )
        for name in ("CreatorTool", "softwareAgent"):
            for value in props.get(name, []):
                kind = sig.match_tool(value)
                if kind:
                    self.add(
                        "MM-AI-021",
                        Category.TOOL if kind == "unambiguous" else Category.AMBIGUOUS,
                        path,
                        f"XMP {name}",
                        f"{name} = {value}",
                        "An XMP tool field names a possible generation tool.",
                        "medium" if kind == "unambiguous" else "low",
                    )
        for value in props.get("AISystemUsed", []):
            self.add(
                "MM-AI-022",
                Category.EXPLICIT,
                path,
                "XMP AISystemUsed",
                f"AISystemUsed = {value}",
                "XMP contains an AI-specific property naming a system.",
                "high",
            )

    def c2pa(self, path: str, what: str) -> None:
        self.add(
            "MM-AI-040",
            Category.AMBIGUOUS,
            path,
            "provenance container",
            what,
            "A possible C2PA provenance structure is present. It was detected only: not parsed, "
            "and no signature or authenticity was validated.",
            "low",
        )


def audit(ctx: ScanContext) -> None:
    report = ctx.report
    a = _Audit(ctx)
    files = [e for e in ctx.source.entries if e.kind == "file" and e.readable]
    tops = {e.path.split("/", 1)[0] for e in files if "/" in e.path}
    wrapper = len(tops) == 1 and not any("/" not in e.path for e in files)
    text_scanned = images = skipped = 0
    for e in files:
        ctx.deadline.check()
        ext = _ext(e.path)
        depth = e.path.count("/") - (1 if wrapper else 0)
        name = e.path.rsplit("/", 1)[-1].lower()
        if ext == ".c2pa":
            a.c2pa(e.path, "sidecar file")
        elif ext in TEXT_EXTS and (depth <= 1 or any(h in name for h in MANIFEST_HINTS)):
            data = ctx.read(e.path, ctx.limits.max_metadata_bytes)
            if data is None:
                skipped += 1
                continue
            text_scanned += 1
            _scan_text(a, e.path, ext, data)
        elif ext in IMAGE_EXTS:
            if images >= MAX_IMAGES:
                skipped += 1
                continue
            data = ctx.read(e.path, ctx.limits.max_image_bytes)
            if data is None:
                skipped += 1
                continue
            images += 1
            a.image(e.path, data)
    report.ai_audited = True
    report.ai_findings.extend(a.findings)
    report.ai_coverage = {
        "text_metadata_files_scanned": text_scanned,
        "images_scanned": images,
        "files_skipped_for_size_or_limits": skipped,
        "formats": ["json", "toml", "yaml", "xml", "txt", "md", "png", "jpeg", "xmp", "exif"],
        "c2pa": "detection only; not parsed or validated",
        "limitations": LIMIT_NOTE,
    }
    report.capability("ai.metadata_audit")


def _scan_text(a: _Audit, path: str, ext: str, data: bytes) -> None:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return
    doc: Any = None
    try:
        if ext in (".json", ".uplugin"):
            doc = json.loads(text)
        elif ext == ".toml":
            doc = tomllib.loads(text)
        elif ext in (".yaml", ".yml"):
            doc = yaml.safe_load(text)
        elif ext == ".xml":
            root = SafeET.fromstring(text, forbid_dtd=True)
            doc = {el.tag.rsplit("}", 1)[-1]: (el.text or "").strip() for el in root.iter()}
    except (ValueError, RecursionError, yaml.YAMLError, DefusedXmlException, SafeET.ParseError):
        doc = None
    if doc is not None:
        a.structured(path, doc)
    elif ext in (".txt", ".md"):
        a.plain_text(path, text)
