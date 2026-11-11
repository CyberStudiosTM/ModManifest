# ✦ ModManifest Changelog

*A history of changes, improvements, and milestones.*

ModManifest is developed by [CyberStudios™](https://github.com/CyberStudiosTM).

This document tracks notable changes to the project as its inspection, validation, and metadata auditing capabilities evolve.

---

## ◇ Version 0.1.1

**Script indicators**

- Added static script scanning for Python source, compiled `.pyc`, Lua, and JavaScript files, including those inside `.ts4script` archives and inZOI packages.
- New findings `MM-SCR-001` to `MM-SCR-007` flag references to network access, process execution, dynamic code, and exfiltration-style endpoints, using the new `static-heuristic` basis.
- Scripts are never imported or executed. Findings are pointers for review, not a malware verdict.

---

## ◇ Version 0.1.0

**Initial implementation · Alpha**

The first version of ModManifest establishes the foundation for read-only game mod inspection.

Its initial focus is **The Sims 4**, **inZOI**, archive safety, and evidence-based AI metadata auditing.

### ✦ What's included

**📦 Package inspection**

Introduced the core command-line interface:

- `modmanifest inspect`
- `modmanifest validate`
- `modmanifest audit-ai`

Includes terminal reporting, JSON export, and stable JSON schema version `1`.

**🛡️ Archive safety**

Added configurable checks for potentially problematic archive and folder structures, including unsafe paths, suspicious entries, resource limits, and unsupported conditions.

**🎮 The Sims 4**

Initial structural validation for:

- DBPF 2.1 `.package` files.
- ZIP-based `.ts4script` files.

The tool does not decode package resources or analyze compiled script contents.

**◇ inZOI**

Introduced candidate-package detection through `mod_manifest.json`, observation-based metadata checks, and inventory of recognized Unreal content containers.

Manifest declarations are reported without assuming that dependencies, checksums, or game compatibility have been verified.

**✧ AI metadata auditing**

Introduced metadata-based detection across supported manifest and image metadata sources, including:

- JSON, TOML, YAML and XML.
- Text and Markdown notes.
- PNG metadata.
- XMP and selected EXIF fields.
- Possible C2PA structures, detection only.

Findings describe available evidence rather than making unsupported conclusions about authorship.

### Design principles established

Version 0.1.0 introduces the project's core commitments:

**Read-only inspection. Explicit limitations. Structured findings. No fabricated certainty.**

---

## ✦ Future releases

Future changes will be documented here as they are implemented and released.

New format coverage, expanded checks, behavior changes, and important fixes should be recorded with their corresponding release versions.

---

<div align="center">

**ModManifest · CyberStudios™**

[Source](https://github.com/CyberStudiosTM/ModManifest) · [README](README.md) · [Contributing](CONTRIBUTING.md)

</div>
