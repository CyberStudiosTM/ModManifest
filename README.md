
<div align="center">

# ✦ ModManifest

### Inspect the package. Understand the metadata.

**Read-only mod inspection, validation & metadata auditing for The Sims 4 and inZOI.**

[![PyPI](https://img.shields.io/pypi/v/modmanifest?style=for-the-badge&color=C6B6F3&label=PyPI)](https://pypi.org/project/modmanifest/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-AED8F5?style=for-the-badge&logo=python&logoColor=202842)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-A8E8DC?style=for-the-badge)](https://github.com/CyberStudiosTM/ModManifest/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-F4C8EA?style=for-the-badge)](https://github.com/CyberStudiosTM/ModManifest/releases)

*A developer utility from [CyberStudios™](https://github.com/CyberStudiosTM).*

[Website](https://cyberthreed.github.io/CyberStudios/projects/modmanifest.html) · [Documentation](https://github.com/cyberthreed/CyberStudios/wiki/ModManifest) · [GitHub](https://github.com/CyberStudiosTM/ModManifest) · [PyPI](https://pypi.org/project/modmanifest/)

---

**Know what was checked. Know what wasn't.**

</div>

## ◇ Meet ModManifest

Mod packages are more than the files you see at first glance.

Archives, compiled scripts, manifests, dependencies, and metadata all contain information about how a package is structured.

**ModManifest** is an open-source command-line utility designed to help modders and developers inspect that information without modifying the original package.

It examines supported mod structures, identifies potential issues, audits available AI-related metadata, and generates transparent reports.

Rather than making assumptions about unfamiliar content, ModManifest separates **verified findings**, **observed information**, and **unsupported checks**.

No executing unfamiliar scripts. No uploading your mods. No modifying package contents.

**Just structured findings, clear boundaries, and a better understanding of what you're working with.**

---

## ✧ Features

| | Capability | Description |
| :---: | :--- | :--- |
| 📦 | **Package Inspection** | Examine supported mod structures and identify recognized formats. |
| 🎮 | **Game-Aware Validation** | Run supported structural checks for The Sims 4 and inZOI. |
| 🛡️ | **Archive Safety** | Identify suspicious paths, duplicate entries, archive limits, and other structural risks. |
| 🔎 | **Script Indicators** | Flag static references to network access, process execution, dynamic code, and exfiltration-style endpoints in Python, Lua, and JavaScript files. |
| ✦ | **AI Metadata Audit** | Detect supported AI-related metadata indicators without making unsupported authorship claims. |
| ◇ | **Structured Reports** | Generate human-readable results or machine-readable JSON. |
| 🔒 | **Read-Only Design** | Inspect without executing scripts, extracting archives, modifying files, or uploading content. |

## 🎮 Supported Games

### The Sims 4

**Supported formats**

- `.package` files using DBPF 2.1
- `.ts4script` ZIP-based archives

**Available checks**

- Package headers and signatures
- Index and resource boundaries
- Duplicate resource keys
- Archive structure
- Applicable compiled Python header information
- Static script indicators in `.py`, compiled `.pyc`, `.lua`, and `.js` files

Package resources are not decoded. Scripts are never imported or executed, and their behavior is not analyzed. Script findings are static pointers for human review, not a malware verdict.

### inZOI

**Supported inspection**

- Candidate mod folders containing `mod_manifest.json`
- Manifest syntax and observed metadata fields
- Project identity, version, author, and dependency declarations
- File references and path safety
- Recognition of `.pak`, `.ucas`, and `.utoc` containers

**Important:** inZOI inspection follows observed package conventions. It is not an official game format specification.

Declared dependencies, compatibility, and unestablished checksum algorithms are not independently verified.

---

## 01 / Installation

**Requirements:** Python 3.11 or newer.

Install the latest published version from PyPI:

```bash
python -m pip install modmanifest
```

Verify installation:

```bash
modmanifest --version
```

Upgrade an existing installation:

```bash
python -m pip install --upgrade modmanifest
```

**Package:** [modmanifest on PyPI](https://pypi.org/project/modmanifest/)

## 02 / Quick Start

### Inspect a mod

```bash
modmanifest inspect "./MyMod"
```

Runs applicable archive safety, package recognition, validation, and supported metadata checks.

### Validate a Sims 4 package

```bash
modmanifest validate "./MyMod.package" --game sims4
```

### Validate an inZOI mod

```bash
modmanifest validate "./MyInZOIMod" --game inzoi
```

### Audit AI-related metadata

```bash
modmanifest audit-ai "./MyMod.zip"
```

### Export a JSON report

```bash
modmanifest inspect "./MyMod" --json
```

### Command Reference

| Command | Purpose |
| :--- | :--- |
| `inspect` | Run applicable inspection and auditing checks |
| `validate` | Validate supported structures for a selected game |
| `audit-ai` | Search supported metadata for AI-related indicators |
| `--version` | Display the installed version |

**Additional options:** `--json`, `--verbose`, `--timeout`, `--max-entries`, `--max-total-mb`, `--max-entry-mb`.

---

## 03 / Understanding Your Results

ModManifest reports findings using explicit statuses.

| Status | Meaning |
| :--- | :--- |
| `PASS` | A specific check passed |
| `WARNING` | A condition deserves attention |
| `ERROR` | A check identified an error |
| `UNSUPPORTED` | The condition is outside supported inspection coverage |
| `NOT CHECKED` | Available evidence cannot establish the result |

Each finding includes diagnostic information explaining the basis of the result.

### Exit Codes

| Code | Meaning |
| :---: | :--- |
| `0` | Scan completed without error findings |
| `1` | One or more error findings |
| `2` | Invalid arguments or missing target |
| `3` | Incomplete scan or unrecognized validation target |

**A successful scan is not a guarantee that a mod is safe, authentic, compatible, or functional in-game.**

---

## 04 / AI Metadata Auditing

**Metadata can provide clues. It cannot tell the entire story.**

ModManifest examines supported metadata sources for potential AI-related indicators.

Sources include:

- JSON, TOML, YAML, and XML
- Text and Markdown
- PNG text metadata
- XMP and selected EXIF fields
- Potential C2PA structures (detection only)

Findings are categorized as:

| Category | Interpretation |
| :--- | :--- |
| **Explicit Declaration** | Metadata directly declares relevant AI involvement |
| **Tool Reference** | Metadata references an AI-associated tool or service |
| **Ambiguous Indicator** | A possible signal without sufficient evidence for a stronger conclusion |

### What if nothing is detected?

A report stating that no supported AI metadata indicators were found means only that none were identified within the supported inspection scope.

It does **not** prove that a mod was created without AI.

Likewise, detecting an AI-associated tool name does not establish that a mod was AI-generated.

**ModManifest reports evidence, not assumptions.**

---

## 05 / Archive Safety

ModManifest includes configurable safeguards for inspecting supported archives and folders.

| Area | Examples |
| :--- | :--- |
| Paths | Traversal, absolute paths, drive letters, alternate streams |
| Entries | Duplicate names and case collisions |
| File types | Symlinks and special files |
| Resources | Entry count, file size, compression ratios |
| Integrity | Signature mismatches and encrypted entries |
| Nested archives | Identification without recursively opening contents |

Scan limits can be adjusted using the available CLI options.

The tool does not extract archives or execute their contents.

---

## 06 / JSON Reporting

For developers building automation or analysis workflows, ModManifest provides structured JSON output.

```bash
modmanifest inspect "./MyMod" --json
```

**Current report schema:** `1`

Reports include information about:

- Target and command
- Game recognition
- Inspection coverage
- Recognized file types
- Package metadata
- Diagnostic findings
- Unsupported conditions
- AI-related metadata indicators

JSON output is designed to make results easier to process programmatically.

---

## 07 / Scope & Limitations

> **IMPORTANT**
>
> ModManifest is not antivirus software, a malware scanner, an official game validator, or a runtime compatibility tester.

Current limitations include:

- Sims 4 package resources are not decoded.
- Scripts are checked for static risk indicators only. They are never executed, and obfuscated or novel behavior may not be detected.
- Unreal content container internals are not parsed.
- Game compatibility and dependencies are not independently verified.
- Unsupported archive formats may be recognized without being opened.
- AI auditing is limited to supported metadata sources.
- Passing checks does not guarantee a mod is safe or functional.

**Transparency is part of the design.**

When something cannot be verified, ModManifest reports that limitation rather than guessing.

---

## ✧ Documentation & Resources

| Resource | Link |
| :--- | :--- |
| ☁️ Project Website | [Explore ModManifest](https://cyberthreed.github.io/CyberStudios/projects/modmanifest.html) |
| 📖 Documentation Wiki | [Read the Documentation](https://github.com/cyberthreed/CyberStudios/wiki/ModManifest) |
| 💻 Source Code | [GitHub Repository](https://github.com/CyberStudiosTM/ModManifest) |
| 📦 PyPI | [Python Package](https://pypi.org/project/modmanifest/) |
| 🐛 Issues & Feedback | [Report an Issue](https://github.com/CyberStudiosTM/ModManifest/issues) |
| ✧ Changelog | [Version History](https://github.com/CyberStudiosTM/ModManifest/blob/main/CHANGELOG.md) |
| ♡ Contributing | [Contribution Guide](https://github.com/CyberStudiosTM/ModManifest/blob/main/CONTRIBUTING.md) |

---

<div align="center">

### ✦ Built within CyberStudios™

*Creative technology, developer tools, and interactive experiences.*

**Inspect with curiosity. Report with precision.**

[CyberStudios Website](https://cyberthreed.github.io/CyberStudios/) · [GitHub Organization](https://github.com/CyberStudiosTM)

MIT Licensed · © CyberStudios™

</div>
