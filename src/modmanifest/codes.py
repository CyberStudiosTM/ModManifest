"""Stable diagnostic code registry.

Every emitted finding code must be listed here. Each entry is ``(title, basis)``.

Basis values:
    format-rule          a documented or independently verified structural rule
    observed-convention  behaviour seen in sample packages, not an official requirement
    safety-limit         a defensive check or configurable scan limit
    scan-coverage        describes what the tool did or did not inspect
"""

from __future__ import annotations

CODES: dict[str, tuple[str, str]] = {
    # Archive and folder safety
    "MM-ARC-001": ("ZIP archive is corrupt or truncated", "format-rule"),
    "MM-ARC-002": ("Unsafe entry path", "safety-limit"),
    "MM-ARC-003": ("Duplicate archive entry", "safety-limit"),
    "MM-ARC-004": ("Entry names differ only by letter case", "safety-limit"),
    "MM-ARC-005": ("Symbolic link entry", "safety-limit"),
    "MM-ARC-006": ("Special file entry", "safety-limit"),
    "MM-ARC-007": ("Entry count limit exceeded", "safety-limit"),
    "MM-ARC-008": ("Total expanded size limit exceeded", "safety-limit"),
    "MM-ARC-009": ("Entry size limit exceeded", "safety-limit"),
    "MM-ARC-010": ("Suspicious compression ratio", "safety-limit"),
    "MM-ARC-011": ("Encrypted entry cannot be inspected", "scan-coverage"),
    "MM-ARC-012": ("Nested archive not opened", "scan-coverage"),
    "MM-ARC-013": ("File extension does not match file signature", "format-rule"),
    "MM-ARC-014": ("Archive structure checks completed", "safety-limit"),
    "MM-ARC-015": ("Backslash in archive entry name", "format-rule"),
    "MM-ARC-016": ("Archive file size limit exceeded", "safety-limit"),
    "MM-ARC-020": ("Link or reparse point not followed", "safety-limit"),
    "MM-ARC-021": ("Folder structure checks completed", "safety-limit"),
    "MM-ARC-023": ("Unsupported file type", "scan-coverage"),
    # Scan lifecycle
    "MM-SCN-001": ("Scan timed out", "scan-coverage"),
    "MM-SCN-002": ("Target could not be read", "scan-coverage"),
    "MM-SCN-003": ("Path could not be read", "scan-coverage"),
    "MM-SCN-004": ("Scan stopped at a configured limit", "scan-coverage"),
    "MM-SCN-005": ("No structures recognized for the selected game", "scan-coverage"),
    "MM-SCN-006": ("No supported structures recognized", "scan-coverage"),
    # The Sims 4
    "MM-S4-001": ("DBPF header is valid", "format-rule"),
    "MM-S4-002": ("File is not a valid DBPF package", "format-rule"),
    "MM-S4-003": ("DBPF version is not supported by this tool", "scan-coverage"),
    "MM-S4-004": ("DBPF index is inconsistent or out of bounds", "format-rule"),
    "MM-S4-005": ("Resource data lies outside the file", "format-rule"),
    "MM-S4-006": ("Duplicate resource key", "format-rule"),
    "MM-S4-007": ("DBPF index flags are not supported by this tool", "scan-coverage"),
    "MM-S4-008": ("DBPF index structure verified", "format-rule"),
    "MM-S4-009": ("Package contains no resources", "format-rule"),
    "MM-S4-010": ("Script archive is readable", "format-rule"),
    "MM-S4-011": ("Script archive has no .py or .pyc entries", "observed-convention"),
    "MM-S4-012": ("Compiled script header is not valid", "format-rule"),
    "MM-S4-013": ("Package resource contents were not decoded", "scan-coverage"),
    "MM-S4-014": ("Script contents were not analyzed or executed", "scan-coverage"),
    "MM-S4-015": ("No standard Sims 4 manifest; dependencies not extracted", "scan-coverage"),
    "MM-S4-016": ("Package too large to read from inside an archive", "scan-coverage"),
    # inZOI
    "MM-INZ-001": ("Candidate inZOI mod manifest parsed", "format-rule"),
    "MM-INZ-002": ("Manifest is not valid JSON", "format-rule"),
    "MM-INZ-003": ("Manifest root is not a JSON object", "format-rule"),
    "MM-INZ-004": ("Manifest field type differs from observed samples", "observed-convention"),
    "MM-INZ-005": ("Project name and folder name comparison", "observed-convention"),
    "MM-INZ-006": ("Unsafe path listed in manifest", "safety-limit"),
    "MM-INZ-007": ("File listed in manifest is missing from the package", "observed-convention"),
    "MM-INZ-008": ("Malformed FileChecksums entry", "observed-convention"),
    "MM-INZ-009": ("FileChecksums were not verified", "scan-coverage"),
    "MM-INZ-010": (
        "Unreal content containers recognized, internals not inspected",
        "scan-coverage",
    ),
    "MM-INZ-011": ("Unreal IoStore .ucas/.utoc pair is incomplete", "format-rule"),
    "MM-INZ-012": ("Script and UI files were not analyzed", "scan-coverage"),
    "MM-INZ-013": ("Declared dependencies were not verified", "scan-coverage"),
    "MM-INZ-014": ("Folder contains several candidate mods", "scan-coverage"),
    "MM-INZ-015": ("No official inZOI package specification was used", "scan-coverage"),
    "MM-INZ-017": ("Game version compatibility was not verified", "scan-coverage"),
}

AI_CODES: dict[str, str] = {
    "MM-AI-001": "Manifest boolean AI declaration",
    "MM-AI-002": "Manifest AI disclosure field",
    "MM-AI-003": "Manifest tool reference",
    "MM-AI-004": "Free-text reference in descriptive field",
    "MM-AI-010": "PNG text chunk with diffusion-style generation parameters",
    "MM-AI-011": "PNG text chunk with node-graph workflow",
    "MM-AI-012": "PNG text chunk tool reference",
    "MM-AI-013": "PNG text chunk with tool-specific metadata key",
    "MM-AI-020": "XMP digital source type",
    "MM-AI-021": "XMP tool reference",
    "MM-AI-022": "XMP AI-specific property",
    "MM-AI-030": "EXIF tool reference",
    "MM-AI-040": "Possible C2PA provenance structure",
}
