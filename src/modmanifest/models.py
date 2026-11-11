"""Report data model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from modmanifest import SCHEMA_VERSION, __version__
from modmanifest.codes import AI_CODES, CODES


class Status(StrEnum):
    PASS = "PASS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_CHECKED = "NOT_CHECKED"


class Category(StrEnum):
    EXPLICIT = "explicit_declaration"
    TOOL = "tool_reference"
    AMBIGUOUS = "ambiguous_indicator"


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def sanitize(text: str, limit: int = 200) -> str:
    """Make untrusted text safe to print and serialize (no control or bidi characters)."""

    def repl(m: re.Match[str]) -> str:
        return f"\\u{ord(m.group()):04x}"

    out = _CONTROL.sub(repl, text)
    return out if len(out) <= limit else out[: limit - 1] + "\u2026"


@dataclass(slots=True)
class Finding:
    code: str
    status: Status
    message: str
    source: str | None = None
    location: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def title(self) -> str:
        return CODES[self.code][0]

    @property
    def basis(self) -> str:
        return CODES[self.code][1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status.value,
            "title": self.title,
            "basis": self.basis,
            "message": sanitize(self.message, 400),
            "source": sanitize(self.source) if self.source is not None else None,
            "location": sanitize(self.location) if self.location is not None else None,
            "details": self.details,
        }


@dataclass(slots=True)
class AIFinding:
    code: str
    category: Category
    source: str
    location: str
    evidence: str
    explanation: str
    confidence: str  # confidence in the metadata interpretation only
    polarity: str = "unspecified"  # affirmative | negative | unspecified
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": AI_CODES[self.code],
            "category": self.category.value,
            "source": sanitize(self.source),
            "location": sanitize(self.location),
            "evidence": sanitize(self.evidence, 120),
            "explanation": self.explanation,
            "confidence_in_metadata_interpretation": self.confidence,
            "declared_polarity": self.polarity,
            "limitations": list(self.limitations),
        }


@dataclass(slots=True)
class RecognizedFile:
    path: str
    kind: str
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"path": sanitize(self.path), "kind": self.kind, "size": self.size}


@dataclass(slots=True)
class InspectionError:
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": sanitize(self.message, 400)}


AI_NONE_FOUND = "No supported AI metadata indicators found."
AI_NONE_FOUND_NOTE = (
    "Metadata may be absent, incomplete, or removed. This result is not evidence that no AI "
    "was involved, and it is not a statement about how the package was made."
)


@dataclass(slots=True)
class Report:
    command: str
    target_name: str
    target_kind: str
    game_selected: str | None = None
    game_detected: str | None = None
    recognized_files: list[RecognizedFile] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ai_findings: list[AIFinding] = field(default_factory=list)
    ai_audited: bool = False
    ai_coverage: dict[str, Any] = field(default_factory=dict)
    unsupported: list[dict[str, str]] = field(default_factory=list)
    inspection_errors: list[InspectionError] = field(default_factory=list)
    package_info: dict[str, Any] = field(default_factory=dict)
    scan_status: str = "complete"  # complete | incomplete | nothing_recognized

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.status is Status.UNSUPPORTED:
            self.unsupported.append(
                {
                    "code": finding.code,
                    "path": sanitize(finding.source or ""),
                    "reason": sanitize(finding.message, 300),
                }
            )

    def capability(self, name: str) -> None:
        if name not in self.capabilities:
            self.capabilities.append(name)

    def error(self, code: str, message: str) -> None:
        self.inspection_errors.append(InspectionError(code, message))
        self.scan_status = "incomplete"

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    @property
    def has_errors(self) -> bool:
        return any(f.status is Status.ERROR for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool": "modmanifest",
            "version": __version__,
            "command": self.command,
            "target": {"name": sanitize(self.target_name), "kind": self.target_kind},
            "game": {"selected": self.game_selected, "detected": self.game_detected},
            "scan": {
                "complete": self.scan_status == "complete",
                "status": self.scan_status,
            },
            "recognized_files": [r.to_dict() for r in self.recognized_files],
            "capabilities_exercised": list(self.capabilities),
            "package": self.package_info,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.counts(),
            "unsupported": self.unsupported,
            "inspection_errors": [e.to_dict() for e in self.inspection_errors],
        }
        ai: dict[str, Any] = {
            "audited": self.ai_audited,
            "findings": [a.to_dict() for a in self.ai_findings],
            "coverage": self.ai_coverage,
        }
        if self.ai_audited and not self.ai_findings:
            ai["summary"] = AI_NONE_FOUND
            ai["note"] = AI_NONE_FOUND_NOTE
        data["ai_metadata"] = ai
        return data
