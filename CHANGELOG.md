# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release of AragSoft Security.

## [1.0.0] - 2026-08-02

### Added
- Composite GitHub Action supporting Linux, macOS and Windows runners.
- **Secret scanning** with Gitleaks (SARIF, JSON and Markdown output, workflow
  failure gate).
- **Dependency vulnerability scanning** with OSV-Scanner (auto-detects npm,
  pnpm, yarn, pip, cargo and Go manifests; JSON + SARIF output).
- **Static code analysis** with Semgrep and the official `p/security-audit`
  rules (SARIF + JSON output, configurable severity threshold).
- **CodeQL** integration: automatic initialization, autobuild, analysis and
  SARIF upload via `github/codeql-action`.
- **Docker security** with Trivy (filesystem, IaC/Dockerfile configuration and
  optional image/OS package scanning; SARIF + JSON output).
- **License compliance** scan (npm lockfile + SPDX SBOM + pip) that warns on
  GPL-family licenses with an optional `fail-on-license` gate.
- **SBOM generation** with Syft in CycloneDX and/or SPDX format, uploaded as a
  separate artifact.
- **Repository security** checks: branch protection, CODEOWNERS, SECURITY.md,
  Dependabot configuration and GitHub secret scanning status.
- **0-100 security score** with transparent, documented weighting.
- Reports: `report.json`, `report.md`, `report.html`, `summary.md` (GitHub
  step summary) and a merged `security.sarif`.
- Automatic **pull-request comments** that are created once and updated on
  subsequent runs.
- Artifacts uploaded as `aragsoft-security-reports` and `aragsoft-security-sbom`.
- Full input surface: `fail-on-*` gates and `enable-*` toggles with sensible
  defaults.
- `test.yml` workflow: actionlint + shellcheck linting, cross-platform smoke
  tests, a failure-gate test and a full-scan integration test.
- `release.yml` workflow: automatic GitHub Releases from semver tags, with
  maintenance of `v1` / `v1.0` rolling tags.

[Unreleased]: https://github.com/amixiid/aragsoft-security/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/amixiid/aragsoft-security/releases/tag/v1.0.0
