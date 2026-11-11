# ✦ ModManifest

**Inspect the package. Understand the metadata. Know what was actually checked.**

*An open-source mod inspection and metadata auditing toolkit from [CyberStudios™](https://github.com/CyberStudiosTM).*

[![Python](https://img.shields.io/badge/Python-3.11%2B-AED8F5?style=for-the-badge&logo=python&logoColor=202842)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-C6B6F3?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-F4C8EA?style=for-the-badge)](CHANGELOG.md)
[![CyberStudios](https://img.shields.io/badge/By-CyberStudios-A8E8DC?style=for-the-badge)](https://github.com/CyberStudiosTM)

---

### ◇ A little more clarity for your modding workflow

Mod packages contain more than the files we see at first glance. Archives, compiled scripts, metadata, dependency declarations, and content containers all tell different parts of a package's story.

**ModManifest** is a read-only command-line utility built to make that information easier to inspect.

It examines supported mod packages, reports structural issues, audits available metadata for AI-related indicators, and tells you where verification stops.

No executing unfamiliar scripts. No modifying someone else's files. No pretending that an unchecked dependency or checksum is verified.

**Just structured findings, clear boundaries, and a better understanding of what you're working with.**

### ✧ Supported games

| Game | Current inspection coverage |
| :--- | :--- |
| **The Sims 4** | `.package` DBPF 2.1 structure and `.ts4script` archive checks |
| **inZOI** | Candidate mod folders, observed manifest metadata, and Unreal container inventory |

> [!IMPORTANT]
> ModManifest is an inspection tool, not an antivirus, game compatibility checker, or official validator. A package passing its available checks does not guarantee that it is safe, compatible, authentic, or functional in-game.

---

## ✦ Explore ModManifest

| | |
| :--- | :--- |
| 📦 **Package inspection** | Identify supported formats and examine their available structure. |
| 🛡️ **Archive safety checks** | Flag suspicious paths, collisions, oversized entries, and other archive-related risks. |
| 🎮 **Game-aware validation** | Apply format-specific checks for The Sims 4 and inZOI. |
| ✧ **AI metadata auditing** | Surface supported metadata indicators without making unsupported authorship claims. |
| ◇ **Structured reports** | Read findings in a terminal or export stable-schema JSON. |
| 🔒 **Read-only operation** | No package extraction, script execution, file modification, or uploads. |

### What makes it different?

ModManifest separates **what it can verify** from **what it can merely observe**.

A manifest declaring a dependency does not prove that the dependency is installed. A version field does not prove game compatibility. An AI-related tool name does not prove that a package was AI-generated.

Those boundaries matter, especially when working with unfamiliar community-made content.

---

## 01 / Getting started

**Requirements:** Python 3.11 or newer.

### Install

```bash
pip install modmanifest
```

Install directly from a local checkout:

```bash
pip install .
```

> [!NOTE]
> The package is named `modmanifest` in the project configuration. Check the [repository](https://github.com/CyberStudiosTM/ModManifest) for its current distribution status.

### Meet the CLI

```text
modmanifest inspect PATH [--json]
modmanifest validate PATH --game sims4|inzoi [--json]
modmanifest audit-ai PATH [--json]
modmanifest --version
```

`PATH` can refer to a folder, `.zip`, `.ts4script`, or `.package`.

### Your first inspection

Inspect a mod package:

```bash
modmanifest inspect "./MyMod"
```

Validate a Sims 4 package:

```bash
modmanifest validate "./MyMod.package" --game sims4
```

Validate an inZOI mod folder:

```bash
modmanifest validate "./MyInZOIMod" --game inzoi
```

Audit supported AI metadata:

```bash
modmanifest audit-ai "./MyMod.zip"
```

Export a JSON report:

```bash
modmanifest inspect "./MyMod" --json
```

### Commands at a glance

| Command | What it does |
| :--- | :--- |
| `inspect` | Archive safety, game recognition and validation, plus AI metadata auditing |
| `validate` | Archive safety and validation for the selected game |
| `audit-ai` | Archive safety and supported AI metadata auditing |

**Available options:** `--json`, `--verbose`, `--timeout`, `--max-entries`, `--max-total-mb`, `--max-entry-mb`.

---

## 02 / Understanding the findings

ModManifest reports results with explicit statuses rather than reducing everything to a potentially misleading pass/fail result.

| Status | Interpretation |
| :--- | :--- |
| `PASS` | A particular check passed. |
| `WARNING` | A condition deserves attention but is not reported as an error. |
| `ERROR` | A check detected an error. |
| `UNSUPPORTED` | The target or condition is outside supported handling. |
| `NOT CHECKED` | The tool cannot establish the result from its available checks. |

In JSON, `NOT CHECKED` is represented as `NOT_CHECKED`.

Each finding includes a registered diagnostic code and a basis for the conclusion.

**Diagnostic families:** `MM-ARC-*`, `MM-SCN-*`, `MM-S4-*`, `MM-INZ-*`.

**Evidence bases:** `format-rule`, `observed-convention`, `safety-limit`, `scan-coverage`.

### Exit codes

| Code | Meaning |
| :---: | :--- |
| `0` | Scan completed without `ERROR` findings |
| `1` | One or more `ERROR` findings |
| `2` | Invalid arguments or missing path |
| `3` | Incomplete scan, or a validation run that recognized nothing |

AI metadata indicators do not affect the exit code.

> [!TIP]
> A completed scan is not the same thing as complete verification. Review `NOT CHECKED` findings and coverage information before drawing conclusions.

---

## 03 / Game-specific inspection

### ◇ The Sims 4

ModManifest supports structural inspection for two common Sims 4 mod formats.

**`.package` / DBPF 2.1**

Checks include the file signature, header, index size and bounds, resource ranges, and duplicate resource keys.

The package's resource contents are not decoded.

**`.ts4script`**

ModManifest reads the script package as a ZIP archive, lists supported Python file entries, and checks compiled `.pyc` headers.

It does not analyze or execute the script contents.

**Known boundary:** No standard Sims 4 manifest is assumed, so dependency and version information is not extracted from one.

### ◇ inZOI

inZOI inspection is based on observed sample package structures.

A root `mod_manifest.json` marks a **candidate package**, not a guarantee of a valid or working mod.

Available inspection includes:

- JSON syntax and observed field types.
- Reported project identity, author, description, version, dependencies and game-version metadata.
- Informational comparison of `ProjectName` with the containing folder.
- `FileChecksums` structure, path safety and referenced-file existence.
- Inventory of recognized `.pak`, `.ucas` and `.utoc` content containers.
- Recognition of unrelated folders as unrecognized rather than automatically invalid.

**What remains unverified**

Declared dependencies and compatibility are not independently verified. File checksum digests are not checked because the algorithm and path semantics have not been established from the inspected samples.

Unreal content containers are recognized, but their internal contents are not parsed. A lone `.ucas` or `.utoc` receives a warning.

For best results, point ModManifest at one inZOI mod folder at a time.

> [!NOTE]
> These checks are not presented as an official inZOI package specification. Observed fields are not treated as universally required.

---

## 04 / Archive safety

Archive handling is deliberately cautious.

ModManifest checks applicable targets for issues such as:

| Area | Examples |
| :--- | :--- |
| **Paths** | Traversal, absolute paths, drive letters, alternate streams and backslashes |
| **Names** | Duplicate entries and case collisions |
| **File types** | Symlinks and special files |
| **Resources** | Entry count, per-entry and total size, compression ratio |
| **Archive integrity** | Signature mismatches and encrypted entries |
| **Nested archives** | Listed without opening their contents |

Encrypted entries are reported as unsupported. Scan limits are configurable.

The tool does not extract archives or execute their contents.

---

## 05 / AI metadata audit

**Metadata can provide clues. It cannot tell the entire story.**

ModManifest searches supported metadata sources for AI-related indicators and classifies its findings as:

| Category | Meaning |
| :--- | :--- |
| **Explicit declaration** | Metadata directly declares relevant AI involvement. |
| **Tool reference** | Metadata names a tool or service associated with AI. |
| **Ambiguous indicator** | A possible signal that does not establish a reliable conclusion. |

The audit examines supported JSON, TOML, YAML, XML, text and Markdown metadata, PNG text chunks, XMP, and selected EXIF fields.

Potential C2PA structures can be detected, but are not fully parsed or signature-verified.

### When nothing appears

> No supported AI metadata indicators found.

This means exactly what it says.

It does **not** prove that a package was made without AI. Metadata may be absent, stripped, incomplete, or outside supported formats.

Confidence descriptions apply to the interpretation of metadata, not the certainty of a package's creative origin.

Prompt text is never copied into generated reports.

---

## 06 / JSON reports

For automation, tooling, or additional analysis, use the `--json` option.

ModManifest provides schema version `1`.

The report contains structured information about:

- The command and target.
- Game recognition and scan coverage.
- Detected file types and capabilities exercised.
- Package metadata.
- Diagnostic findings and summary counts.
- Unsupported conditions and inspection errors.
- AI metadata indicators.

Top-level fields include:

`tool`, `version`, `command`, `target`, `game`, `scan`, `recognized_files`, `capabilities_exercised`, `package`, `findings`, `summary`, `unsupported`, `inspection_errors`, `ai_metadata`.

Target names are reduced to base names instead of absolute local paths. Untrusted control and bidirectional characters are escaped.

---

## 07 / Current limitations

ModManifest is intentionally precise about its coverage.

- Format validation relies on public format knowledge and observed samples, not official vendor specifications.
- Sims 4 resources and scripts are not decoded, analyzed or executed.
- Unreal `.pak`, `.ucas` and `.utoc` internals are not parsed.
- Declared game compatibility and dependencies are not verified.
- Unestablished inZOI checksum algorithms are not guessed.
- AI audits cover supported metadata, not every possible binary or content source.
- 7z, RAR and other unsupported archive types may be listed without opening them.
- Passing checks does not establish safety, authenticity, or in-game functionality.

Transparency is part of the tool's design.

---

## 08 / For developers

Want to help improve format coverage, documentation, diagnostics, or tests?

Clone the repository and install the development dependencies:

```bash
pip install -e ".[dev]"
```

Run the checks:

```bash
ruff check .
ruff format --check .
pytest
```

Read the [contributing guide](CONTRIBUTING.md) before submitting changes.

Especially useful contributions include reproducible bug reports, synthetic test cases, and evidence-based improvements to recognized formats.

Please do not commit copyrighted third-party mod packages as test fixtures.

---

## ✦ Project links

| | |
| :--- | :--- |
| **Source code** | [CyberStudiosTM/ModManifest](https://github.com/CyberStudiosTM/ModManifest) |
| **Bug reports and ideas** | [Issues](https://github.com/CyberStudiosTM/ModManifest/issues) |
| **Contributing** | [CONTRIBUTING.md](CONTRIBUTING.md) |
| **Security** | [SECURITY.md](SECURITY.md) |
| **Version history** | [CHANGELOG.md](CHANGELOG.md) |
| **License** | [MIT](LICENSE) |
| **CyberStudios** | [GitHub organization](https://github.com/CyberStudiosTM) |

---

<div align="center">

### ✧ Built within CyberStudios™

*Tools for creators, developers, and the worlds they build.*

**Inspect with curiosity. Report with precision.**

MIT Licensed · Copyright © CyberStudios

</div>
