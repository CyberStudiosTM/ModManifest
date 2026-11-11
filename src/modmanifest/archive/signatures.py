"""Structural file-signature checks for extensions where a signature is well defined."""

from __future__ import annotations

from modmanifest.context import ScanContext
from modmanifest.models import Finding, Status

_ZIP = (b"PK\x03\x04", b"PK\x05\x06")
SIGNATURES: dict[str, tuple[bytes, ...]] = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".zip": _ZIP,
    ".ts4script": _ZIP,
}
# .package signatures are verified by the Sims 4 DBPF parser, not here.


def check_signatures(ctx: ScanContext) -> None:
    checked = 0
    for entry in ctx.source.files():
        ext = "." + entry.path.rsplit(".", 1)[-1].lower() if "." in entry.path else ""
        sigs = SIGNATURES.get(ext)
        is_webp = ext == ".webp"
        if sigs is None and not is_webp:
            continue
        ctx.deadline.check()
        head = ctx.head(entry.path, 12)
        if head is None:
            continue
        checked += 1
        ok = (
            head[:4] == b"RIFF" and head[8:12] == b"WEBP"
            if is_webp
            else any(head.startswith(s) for s in sigs or ())
        )
        if not ok:
            ctx.report.add(
                Finding(
                    "MM-ARC-013",
                    Status.WARNING,
                    f"extension '{ext}' does not match the file signature",
                    source=entry.path,
                )
            )
    if checked:
        ctx.report.capability("archive.signature_check")
