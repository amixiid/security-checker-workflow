# Frequently Asked Questions

## General

### Do I need a license or API key?
No. AragSoft Security uses only open-source, free tools and the standard
`GITHUB_TOKEN` that GitHub automatically provides. No commercial license is
required.

### Which tools does the action use?
[Gitleaks](https://github.com/gitleaks/gitleaks) (secrets),
[OSV-Scanner](https://github.com/google/osv-scanner) (dependencies),
[Semgrep](https://semgrep.dev) (static analysis),
[GitHub CodeQL](https://codeql.github.com) (via `github/codeql-action`),
[Trivy](https://trivy.dev) (Docker), and
[Syft](https://github.com/anchore/syft) (SBOM). All of them are downloaded on
demand and pinned to configurable versions.

### Why does the action download tools on every run?
The tools are cached in the runner's temporary directory. On hosted runners a
fresh machine starts each job, so downloads repeat. Pin versions for
reproducibility; tool binaries are cached inside the same run, so multiple
checks reuse them.

### Can I run it on self-hosted runners?
Yes, on Linux, macOS and Windows self-hosted runners. Network access is
required to download tools and query vulnerability databases.

## Installation and usage

### What is the minimum workflow?
```yaml
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amixiid/security-checker-workflow@v1
```

### Which checkout options should I use?
Use `fetch-depth: 0` for the most complete Gitleaks history scan. The action
works without it, but shallow clones may hide secrets that were removed in
earlier commits.

### I only want some checks
Disable the rest:
```yaml
- uses: amixiid/security-checker-workflow@v1
  with:
    enable-semgrep: 'false'
    enable-codeql: 'false'
    enable-docker: 'false'
```

## Permissions

### Why aren't PR comments posted?
Pull-request comments require `pull-requests: write` on the `GITHUB_TOKEN`:

```yaml
permissions:
  contents: read
  pull-requests: write
```

Comments are silently skipped (with a warning) when the token lacks
permission, and **comments from forks** are not allowed by GitHub by default.

### Why is the branch-protection status "unknown"?
Reading branch protection and secret-scanning status requires a token with
appropriate scopes. With the default token this often appears as "unknown /
insufficient permissions". The action degrades gracefully and still reports
the local checks (CODEOWNERS, SECURITY.md, Dependabot config).

## Behaviour

### Why did my workflow fail?
Look at the step summary or the `aragsoft-security-reports` artifact. The
`report.json` contains `failure_reasons`. Common causes: secrets committed,
critical/high dependency vulnerabilities, or a failed gate you enabled.

### Can I look without failing the build?
Yes — set the gates to `false`:
```yaml
- uses: amixiid/security-checker-workflow@v1
  with:
    fail-on-secrets: 'false'
    fail-on-critical: 'false'
    fail-on-high: 'false'
```
The score and reports are still produced; you can enforce them later.

### Why is Docker skipped even though I have a Dockerfile?
The filesystem/config scans run only when a Dockerfile is present. OS package
scanning additionally requires an image. Either set `docker-image` to an
existing image, or enable `docker-build` (requires Docker on the runner).

### Why are some checks "skipped" in the score?
A check is skipped when it is disabled, or not applicable (e.g. Docker without
a Dockerfile, dependencies without a supported lockfile). Skipped checks are
excluded from the score rather than punished.

### Why are GPL licenses only a warning by default?
The action is configurable by design. Set `fail-on-license: 'true'` to treat
GPL-family licenses as a build failure.

## Outputs and reports

### Where are the reports?
They are uploaded as artifacts `aragsoft-security-reports` and
`aragsoft-security-sbom`, written to `$RUNNER_TEMP/aragsoft-security`, and
also available from the step summary and the pull-request comment.

### Can I upload SARIF to GitHub code scanning?
SARIF files from Gitleaks, OSV-Scanner, Semgrep and Trivy are merged into
`security.sarif`. You can upload it yourself:

```yaml
- name: Upload SARIF to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ runner.temp }}/aragsoft-security/security.sarif
```

### How do I add my own rules or ignore paths?
- **Semgrep**: pass `semgrep-rules` pointing at your rule directory in the repo.
- **Gitleaks**: add a `.gitleaks.toml` at the repository root (Gitleaks
  auto-detects it).
- **OSV-Scanner**: add an `osv-scanner.toml` (or `.osv-scanner.toml`) config
  file. See the
  [OSV-Scanner configuration docs](https://google.github.io/osv-scanner/configuration/).
- **Trivy**: pass `--skip-dirs` values via the `trivy` config file or use the
  `trivy-ignore-unfixed` input.

## Compatibility

### Does it work with monorepos?
Yes. OSV-Scanner runs with `--recursive`, and Semgrep/Trivy/Syft scan the whole
workspace.

### Does it support Windows/macOS?
Yes. The action is a composite action using `bash` (Git Bash on Windows). The
CI test matrix runs smoke tests on `ubuntu-latest`, `macos-latest` and
`windows-latest`.

### Will this action scan itself?
Only if you run it on this repository. Reports are written outside the
workspace so they are never re-scanned by the tools.
