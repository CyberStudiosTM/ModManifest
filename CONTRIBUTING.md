# ✦ Contributing to ModManifest

**Good tools become better through careful collaboration.**

Thank you for your interest in contributing to ModManifest, an open-source project by [CyberStudios™](https://github.com/CyberStudiosTM).

Whether you're fixing a bug, researching a file format, refining a diagnostic message, or improving documentation, contributions are welcome.

Our priority is simple: **make mod inspection more reliable without claiming to verify things we cannot actually establish.**

---

## 01 / Before you begin

ModManifest is a read-only inspection tool for supported game mod packages.

Every contribution should preserve its core principles.

| Principle | What it means |
| :--- | :--- |
| **Read-only by design** | Never extract, execute, modify, or upload user files. |
| **Evidence before assumptions** | Ground validation rules in known format details or clearly described observations. |
| **Transparent limitations** | Report unknown information as `NOT CHECKED` rather than inventing answers. |
| **Safe handling** | Treat archives, manifests, metadata, and paths as untrusted input. |
| **Focused changes** | Keep each contribution understandable, testable, and appropriately scoped. |

> [!IMPORTANT]
> Do not introduce unsupported game compatibility claims, guessed checksum algorithms, or heuristic conclusions about whether a mod was AI-generated.

---

## 02 / Set up your development environment

ModManifest requires Python 3.11 or newer.

Fork and clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/ModManifest.git
cd ModManifest
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```bash
source .venv/bin/activate
```

Install the development dependencies:

```bash
pip install -e ".[dev]"
```

### Run the checks

```bash
ruff check .
ruff format --check .
pytest
```

These checks should pass before opening a pull request.

---

## 03 / What you can contribute

### ◇ Format research

Help improve the accuracy of known Sims 4 or inZOI package checks.

When proposing a validation rule, document its basis:

- A known format rule.
- An observed convention in sample packages.
- A safety constraint.
- A scan coverage limitation.

Do not turn an observed convention into a universal requirement without supporting evidence.

### ◇ Diagnostic improvements

Each emitted diagnostic code must be registered in:

`src/modmanifest/codes.py`

Include its evidence basis and preserve the meaning of existing codes.

If a check cannot establish a result, use the appropriate `NOT CHECKED` or unsupported reporting path.

### ◇ Tests

Tests should use synthetic fixtures created in code.

**Do not commit real third-party mod packages, proprietary game assets, or personal files.**

Useful tests include malformed package structures, path edge cases, incomplete archives, and metadata classification scenarios.

### ◇ Documentation

Documentation improvements are just as valuable as code contributions.

Keep examples reproducible and clearly identify any sample output that is illustrative rather than captured from a real execution.

---

## 04 / Submitting a change

1. Open an issue first when a proposed change is large, security-sensitive, or changes public behavior.
2. Create a descriptive feature or fix branch.
3. Make your changes and add appropriate tests.
4. Run the development checks.
5. Open a pull request explaining what changed, why, and how you verified it.

For format-related changes, explain which behavior is established and which remains observational.

Small, focused pull requests are easier to review and maintain.

---

## 05 / Reporting problems

Found something that doesn't behave as expected?

Use [GitHub Issues](https://github.com/CyberStudiosTM/ModManifest/issues) for ordinary bugs, documentation problems, and feature suggestions.

When reporting a problem, include:

- The ModManifest version.
- Your Python version and operating system.
- The command you ran.
- The observed behavior.
- The expected behavior.
- A minimal, synthetic reproduction where possible.

**Remove private paths and personal information before sharing logs.**

For suspected vulnerabilities, use the private reporting process in [SECURITY.md](SECURITY.md) instead.

---

## ✦ A note on collaboration

ModManifest is designed to be cautious, transparent, and useful to the communities creating and maintaining game modifications.

Contributing isn't only about expanding the number of formats recognized. Better failure messages, safer input handling, more accurate coverage reporting, and clearer documentation matter just as much.

Thank you for helping build tools that creators can understand and trust.

---

<div align="center">

**ModManifest · CyberStudios™**

*Curiosity is welcome. Evidence is essential.*

[Repository](https://github.com/CyberStudiosTM/ModManifest) · [Issues](https://github.com/CyberStudiosTM/ModManifest/issues) · [License](LICENSE)

</div>
