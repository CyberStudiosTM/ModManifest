# ✦ Security Policy

**Responsible disclosure. Careful inspection. Clear limitations.**

Security is an important part of ModManifest's design.

Because ModManifest examines potentially untrusted game mod packages, its archive handling, file parsing, and resource limits are treated as security-relevant functionality.

This policy explains how to report vulnerabilities and what security guarantees the project does, and does not, provide.

---

## 01 / Supported versions

Security fixes and reports are focused on the latest release.

| Version | Support |
| :--- | :--- |
| Latest release | Supported |
| Older versions | Not guaranteed |

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## 02 / Reporting a vulnerability

> [!CAUTION]
> **Please do not disclose security vulnerabilities in public GitHub Issues, discussions, or pull requests before they have been reviewed.**

Use GitHub's private vulnerability reporting feature:

**[Report a vulnerability privately](https://github.com/CyberStudiosTM/ModManifest/security/advisories/new)**

You can also navigate to the repository's **Security** tab and select **Report a vulnerability**.

### Helpful information

Where possible, include:

- A concise description of the issue.
- The affected version or commit.
- The affected file type or parser.
- Steps to reproduce the behavior.
- Expected and observed outcomes.
- A minimal synthetic test case.
- Relevant logs with personal information removed.

Do not upload sensitive files or proprietary mod content unless explicitly authorized through an appropriate private process.

Reports can be investigated more efficiently when the affected behavior is reproducible.

---

## 03 / Security scope

Examples of security-relevant issues include:

| Area | Examples |
| :--- | :--- |
| **Archive handling** | Path traversal, unsafe entry names, unexpected archive processing |
| **Resource exhaustion** | Excessive memory, CPU, decompression, or file enumeration |
| **Parser robustness** | Crashes or unsafe behavior triggered by malformed files |
| **Read-only guarantees** | Unexpected file modification, extraction, or execution |
| **Privacy** | Unexpected network transmission or disclosure of sensitive local information |

ModManifest is intended to inspect local inputs without executing or altering their contents.

Any behavior violating that boundary is worth reporting.

---

## 04 / What ModManifest does not guarantee

ModManifest is **not** an antivirus, malware scanner, sandbox, or runtime compatibility tester.

A successful inspection does not prove that a mod is:

- Free from malicious code.
- Safe to install or execute.
- Compatible with a particular game version.
- Authentic or untampered.
- Free of AI-generated content.
- Functional in-game.

Metadata inspections and structural checks are limited to their explicitly documented coverage.

> [!IMPORTANT]
> A `PASS` finding applies to the specific check performed. It is not a security certification for the entire package.

Similarly, `NOT CHECKED` indicates an unverified area, not an implied pass.

---

## 05 / Responsible research

Security research should be conducted with permission and appropriate safeguards.

Please avoid testing with copyrighted third-party content that you cannot redistribute.

When preparing a vulnerability report, synthetic fixtures are preferred whenever they can reproduce the problem.

Do not attempt to demonstrate an issue by targeting other users, distributing harmful packages, or accessing systems without authorization.

---

## ✦ Thank you

Responsible vulnerability reporting helps keep ModManifest more reliable for developers and modding communities.

We appreciate researchers and contributors who approach these issues carefully.

---

<div align="center">

**CyberStudios™ · ModManifest**

*Know the boundaries. Protect the workflow.*

[Repository](https://github.com/CyberStudiosTM/ModManifest) · [Contributing](CONTRIBUTING.md)

</div>
