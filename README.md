<div align="center">

# 🛡️ AragSoft Security

### One line. Every security check that matters.

`Enterprise-grade security scanning for your GitHub repositories — secrets, dependencies, static analysis, CodeQL, Docker, licenses, SBOM and repository hardening, in a single composite action with a 0–100 score and pull-request reports.`

[![Marketplace](https://img.shields.io/badge/GitHub_Marketplace-AragSoft_Security-blue?logo=github&logoColor=white)](https://github.com/marketplace) <!-- logo placeholder -->
[![test](https://github.com/amixiid/security-checker-workflow/actions/workflows/test.yml/badge.svg)](https://github.com/amixiid/security-checker-workflow/actions/workflows/test.yml)
[![release](https://github.com/amixiid/security-checker-workflow/actions/workflows/release.yml/badge.svg)](https://github.com/amixiid/security-checker-workflow/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

```yaml
- uses: amixiid/security-checker-workflow@v1
```

**Linux · macOS · Windows**

</div>

---

## Table of contents

- [What it does](#what-it-does)
- [Features](#features)
- [Installation](#installation)
- [Example usage](#example-usage)
- [Configuration](#configuration)
- [Score](#score)
- [Reports](#reports)
- [Screenshots](#screenshots)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Versioning](#versioning)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

AragSoft Security installs and orchestrates the industry's leading
open-source security tools for you, normalizes their results, merges them into
a single SARIF file, computes a **0–100 security score**, and posts a readable
report as a **pull-request comment** and **job summary** — all from one line in
your workflow.

| Check | Tool | Output |
| --- | --- | --- |
| 🔒 Secret scanning | [Gitleaks](https://github.com/gitleaks/gitleaks) | SARIF · JSON · MD |
| 📦 Dependency vulnerabilities | [OSV-Scanner](https://github.com/google/osv-scanner) | SARIF · JSON · MD |
| 🔍 Static code analysis | [Semgrep](https://semgrep.dev) (official security rules) | SARIF · JSON · MD |
| 🧬 CodeQL | [github/codeql-action](https://github.com/github/codeql-action) | SARIF (uploaded) |
| 🐳 Docker security | [Trivy](https://trivy.dev) | SARIF · JSON · MD |
| ⚖️ License compliance | npm lockfile · SPDX SBOM · pip | JSON · MD |
| 📋 SBOM | [Syft](https://github.com/anchore/syft) | CycloneDX · SPDX |
| 🏗️ Repository hardening | GitHub API + local files | JSON · MD |

---

## Features

- **Zero-config** — automatic package-manager detection (`npm`, `pnpm`,
  `yarn`, `pip`, `cargo`, `go`), automatic CodeQL initialization, and Docker
  scanning only when a Dockerfile exists.
- **Works everywhere** — a composite action that runs on Linux, macOS and
  Windows GitHub runners.
- **Fail gates you control** — `fail-on-secrets`, `fail-on-high`,
  `fail-on-critical`, `fail-on-license`, `fail-on-tool-error`.
- **Full reports** — JSON, Markdown, self-contained HTML, a GitHub step
  summary, and a merged `security.sarif`.
- **PR comments** — created once, updated on every run (no comment spam).
- **Artifacts** — reports and SBOM are uploaded automatically.
- **Cross-tool SARIF** — every tool's SARIF is merged into
  `security.sarif`, ready for code scanning upload.
- **Reproducible** — every tool version is pin-able via inputs.
- **Marketplace-ready** — passes `actionlint`, `shellcheck`, and follows
  GitHub Actions best practices.

---

## Installation

The action requires **zero setup**. Add the workflow file below to your
repository (`.github/workflows/security.yml`):

```yaml
name: Security

on:
  push:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: amixiid/security-checker-workflow@v1
```

> **Tip:** use `with: fetch-depth: 0` on `actions/checkout` so Gitleaks can
> scan the full commit history.

### Permissions

The default `GITHUB_TOKEN` works out of the box. To unlock **PR comments** and
**repository-security queries**, declare:

```yaml
permissions:
  contents: read
  pull-requests: write
```

---

## Example usage

### Minimal (defaults)

```yaml
- uses: actions/checkout@v4
- uses: amixiid/security-checker-workflow@v1
```

### Fail only on critical issues, skip Docker and CodeQL

```yaml
- uses: amixiid/security-checker-workflow@v1
  with:
    enable-codeql: 'false'
    enable-docker: 'false'
    fail-on-high: 'false'
    fail-on-critical: 'true'
```

### Full configuration

See [examples/advanced.yml](examples/advanced.yml) and
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Configuration

All inputs are optional; defaults are shown.

| Input | Default | Description |
| --- | --- | --- |
| `fail-on-secrets` | `true` | Fail when secrets are detected. |
| `fail-on-high` | `false` | Fail on high-severity dependency vulnerabilities. |
| `fail-on-critical` | `true` | Fail on critical-severity dependency vulnerabilities. |
| `fail-on-license` | `false` | Fail on GPL-family licenses. |
| `fail-on-tool-error` | `false` | Fail when a tool fails to execute. |
| `enable-secrets` | `true` | Run Gitleaks secret scanning. |
| `enable-dependencies` | `true` | Run OSV-Scanner. |
| `enable-semgrep` | `true` | Run Semgrep static analysis. |
| `enable-codeql` | `true` | Run CodeQL. |
| `enable-docker` | `true` | Run Trivy when a Dockerfile is present. |
| `enable-license` | `true` | Run license compliance scan. |
| `enable-sbom` | `true` | Generate an SBOM with Syft. |
| `enable-repo` | `true` | Check repository hardening. |
| `semgrep-rules` | `p/security-audit` | Semgrep rule set or local path. |
| `semgrep-severity-threshold` | `warning` | Minimum severity that fails Semgrep. |
| `codeql-languages` | *(auto)* | Comma-separated CodeQL languages. |
| `docker-image` | *(empty)* | Image to scan for OS packages. |
| `docker-build` | `false` | Build and scan the image from the Dockerfile. |
| `sbom-format` | `cyclonedx` | `cyclonedx`, `spdx`, or `both`. |
| `trivy-ignore-unfixed` | `true` | Ignore vulnerabilities with no fix. |
| `gitleaks-version` | `8.30.1` | Tool version pin. |
| `osv-scanner-version` | `2.4.0` | Tool version pin. |
| `trivy-version` | `0.72.0` | Tool version pin. |
| `syft-version` | `1.50.0` | Tool version pin. |
| `semgrep-version` | `latest` | Tool version pin. |
| `upload-artifacts` | `true` | Upload reports and SBOM as artifacts. |
| `enable-pr-comment` | `true` | Comment the report on pull requests. |
| `report-title` | `AragSoft Security Report` | Report title. |
| `debug` | `false` | Enable debug logging. |

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Score

The action computes a transparent **0–100 score** from the enabled checks:

| Check | Weight |
| --- | --- |
| Secret scanning | 25 |
| Dependencies | 20 |
| Static analysis (Semgrep) | 15 |
| CodeQL | 15 |
| Docker | 10 |
| Licenses | 10 |
| Repository security | 5 |

**PASS** earns full weight, **WARNING** earns 60%, **FAIL** earns 0. Disabled
or not-applicable checks are excluded from the total, so the score always
stays within 0–100.

Example output:

```
Secrets ............. PASS
Dependencies ........ PASS
CodeQL .............. PASS
Docker .............. PASS
Licenses ............ WARNING

Overall Score

96 / 100
```

Read the full methodology in [docs/SCORING.md](docs/SCORING.md).

---

## Reports

Every run produces, in `$RUNNER_TEMP/aragsoft-security/` (uploaded as the
`aragsoft-security-reports` artifact):

| File | Contents |
| --- | --- |
| `report.json` | Full machine-readable report. |
| `report.md` | Markdown report (also used as the PR comment). |
| `report.html` | Self-contained HTML dashboard. |
| `summary.md` | Dashboard added to the job summary. |
| `security.sarif` | Merged SARIF from all tools. |
| `results/` | Raw per-tool output. |
| `sarif/` | Individual per-tool SARIF files. |
| `sbom/` | CycloneDX / SPDX SBOM files. |

Upload the merged SARIF to code scanning if you like:

```yaml
- name: Upload SARIF to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ runner.temp }}/aragsoft-security/security.sarif
```

### Outputs

`score`, `status`, `exit-code`, `secrets`, `dependencies`, `code`, `codeql`,
`docker`, `licenses`, `repo` — usable in later steps, e.g. to gate deployments.

---

## Screenshots

<!-- screenshots placeholder -->

| Job summary | Pull-request comment | HTML dashboard |
| --- | --- | --- |
| *A professional dashboard in the job summary.* | *A clean, emoji-driven report comment.* | *A self-contained HTML scorecard.* |
| _(screenshot to be added)_ | _(screenshot to be added)_ | _(screenshot to be added)_ |

---

## Troubleshooting

Common issues and fixes are documented in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md):

- Permissions errors (PR comments, repository checks)
- Tool installation / network failures
- CodeQL not producing results
- Slow Docker scans
- Windows-specific issues

---

## FAQ

See [docs/FAQ.md](docs/FAQ.md) for answers to common questions, including:

- Do I need a license or API key? — **No.**
- Why does the action download tools? — They are pinned and cached per run.
- How do I disable checks? — `enable-*` inputs.
- Does it support monorepos? — Yes.
- Why are GPL licenses only a warning? — Set `fail-on-license: 'true'`.

---

## Versioning

AragSoft Security follows [Semantic Versioning](https://semver.org/). The
release workflow automatically creates releases from semver tags and maintains
rolling tags:

- `v1` — major (recommended)
- `v1.0` — minor
- `v1.0.0` — exact patch

```yaml
# Pin to a major version for auto-updates
- uses: amixiid/security-checker-workflow@v1

# Or pin exactly for reproducibility
- uses: amixiid/security-checker-workflow@v1.0.0
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md)
first. Report vulnerabilities privately per
[SECURITY.md](SECURITY.md) — do not open public issues for them.

## License

[MIT](LICENSE) © 2026 AragSoft.
# security-checker-workflow
