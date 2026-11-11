# ModManifest

Read-only inspection, validation and metadata auditing for game mod packages.
Supports **The Sims 4** and **inZOI**. Part of [CyberStudios](https://github.com/CyberStudiosTM).

ModManifest never extracts, executes, modifies or uploads anything. It reports what it can
verify, what it only observed, and what it did not check.

## Install

```powershell
pip install modmanifest
```

Requires Python 3.11+. From source: `pip install .`

## Usage

```text
modmanifest inspect PATH [--json]
modmanifest validate PATH --game sims4|inzoi [--json]
modmanifest audit-ai PATH [--json]
modmanifest --version
```

`PATH` is a folder, `.zip`, `.ts4script` or `.package`.

| Command | Runs |
|---|---|
| `inspect` | archive safety, game recognition and validation, AI metadata audit |
| `validate` | archive safety and the selected game's validation |
| `audit-ai` | archive safety and the AI metadata audit |

Options: `--json`, `--verbose`, `--timeout`, `--max-entries`, `--max-total-mb`, `--max-entry-mb`.

### Statuses

`PASS`, `WARNING`, `ERROR`, `UNSUPPORTED`, `NOT CHECKED` (`NOT_CHECKED` in JSON).
Every finding carries a stable code (`MM-ARC-*`, `MM-SCN-*`, `MM-S4-*`, `MM-INZ-*`) and a
basis: `format-rule`, `observed-convention`, `safety-limit` or `scan-coverage`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | scan complete, no `ERROR` findings |
| 1 | one or more `ERROR` findings |
| 2 | invalid arguments or missing path |
| 3 | incomplete scan (limit, timeout, read failure), or `validate` recognized nothing |

AI indicators never change the exit code.

## Example

```text
$ modmanifest validate SampleMod --game inzoi
ModManifest validate  SampleMod
target: folder  scan: complete
game selected: inzoi  recognized: inzoi
Status       Code        Finding
NOT_CHECKED  MM-INZ-015  no official inZOI package specification was used; ...
NOT_CHECKED  MM-INZ-013  declared dependencies are reported as written; ...
NOT_CHECKED  MM-INZ-017  game version metadata is reported as written; ...
NOT_CHECKED  MM-INZ-009  checksum digests were not verified: the algorithm ...
PASS 2  WARNING 0  ERROR 0  UNSUPPORTED 0  NOT_CHECKED 5
```

## Validation coverage

### The Sims 4

- `.package` (DBPF 2.1): signature, header, index bounds and size, resource ranges,
  duplicate keys. Resource contents are **not** decoded.
- `.ts4script`: opened as a ZIP, `.py`/`.pyc` entries listed, compiled-code header checked.
  Script contents are **not** analyzed or executed.
- No standard Sims 4 manifest is assumed, so dependencies and versions are not extracted.

### inZOI

A root `mod_manifest.json` marks a **candidate** mod, not a valid package. There is no
official specification behind these checks.

- JSON syntax and field types, compared with sample packages. Observed fields are never required.
- Identity, author, version, description, declared dependencies and game-version metadata are
  reported as written. Dependencies and compatibility are **not** verified.
- `ProjectName` versus folder name is informational.
- `FileChecksums`: shape, path safety and listed-file existence are checked. Digests are
  **NOT CHECKED**: in sample packages the algorithm and path semantics could not be
  established, and none is guessed. A matching digest would show consistency with the
  manifest only, not that a mod is safe or authentic.
- `.pak`, `.ucas`, `.utoc`: recognized as Unreal content containers and inventoried;
  internals are not inspected. A lone `.ucas` or `.utoc` is reported as a warning.
- Unrelated folders (mod-manager state, hosted content) are unrecognized, not invalid.
  Point ModManifest at one mod folder at a time.

### Archive and folder safety (all targets)

Traversal and absolute paths, drive letters and alternate streams, backslashes, duplicates,
case collisions, symlinks and special files, entry count, total and per-entry size,
compression ratio, signature mismatch, encrypted entries (`UNSUPPORTED`), and nested
archives (listed, not opened). Limits are configurable.

## AI metadata audit

Reports indicators found in metadata, in three categories: explicit declaration, tool
reference, ambiguous indicator. Confidence refers to the interpretation of the metadata
only.

Supported sources: JSON, TOML, YAML and XML manifests; text and Markdown notes; PNG text
chunks; XMP; EXIF `Software`/`ImageDescription`. C2PA is **detection only**: possible
structures are reported, never parsed or signature-validated.

When nothing is found, the result is:

> No supported AI metadata indicators found.

Metadata may be absent, incomplete or removed. That result is not evidence about how a
package was made. Prompt text is never copied into reports. Name tables used for matching
live in `src/modmanifest/metadata/ai_signatures.py` and are detection data only.

## JSON output

Stable schema, `schema_version: 1`. Top-level keys: `tool`, `version`, `command`, `target`,
`game`, `scan`, `recognized_files`, `capabilities_exercised`, `package`, `findings`,
`summary`, `unsupported`, `inspection_errors`, `ai_metadata`. The target is a base name,
never an absolute path. Untrusted text has control and bidirectional characters escaped.

## Limitations

- Format checks reflect observed samples and public format knowledge, not vendor specs.
- Only listed metadata containers are audited; scripts and binary game data are not.
- 7z, RAR and other archive formats are listed, not opened.
- Package validity here does not mean a mod is safe, compatible or working in game.

## Development

```powershell
pip install -e ".[dev]"
ruff check . ; ruff format --check .
pytest
```

## License

MIT. Copyright (c) CyberStudios.
