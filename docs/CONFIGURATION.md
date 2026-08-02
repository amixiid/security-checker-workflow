# Configuration

AragSoft Security ships with sensible defaults so a single line is enough to
start scanning. This page documents every input, how to tune it, and the
available outputs.

## Inputs

### Failure gates

| Input | Default | Description |
| --- | --- | --- |
| `fail-on-secrets` | `true` | Fail the workflow when Gitleaks detects secrets. |
| `fail-on-high` | `false` | Fail the workflow when high-severity dependency vulnerabilities are found. |
| `fail-on-critical` | `true` | Fail the workflow when critical-severity dependency vulnerabilities are found. |
| `fail-on-license` | `false` | Fail the workflow when GPL-family (restrictive) licenses are detected. |
| `fail-on-tool-error` | `false` | Fail the workflow when a security tool fails to execute. |

> Note: `fail-on-high` and `fail-on-critical` evaluate OSV-Scanner findings by
> severity. Because `fail-on-critical` defaults to `true`, the action fails by
> default when critical dependency vulnerabilities exist.

### Check toggles

| Input | Default | Description |
| --- | --- | --- |
| `enable-secrets` | `true` | Run secret scanning with Gitleaks. |
| `enable-dependencies` | `true` | Run dependency vulnerability scanning with OSV-Scanner. |
| `enable-semgrep` | `true` | Run static code analysis with Semgrep. |
| `enable-codeql` | `true` | Initialize and run GitHub CodeQL analysis. |
| `enable-docker` | `true` | Run Docker/container scanning with Trivy when a Dockerfile is present. |
| `enable-license` | `true` | Run license compliance scanning. |
| `enable-sbom` | `true` | Generate a Software Bill of Materials with Syft. |
| `enable-repo` | `true` | Check repository security configuration. |

### Scan configuration

| Input | Default | Description |
| --- | --- | --- |
| `semgrep-rules` | `p/security-audit` | Semgrep rule set or path. Supports registry configs (`p/security-audit`, `r/<id>`) or a path relative to the workspace (e.g. `semgrep-rules/`). |
| `semgrep-severity-threshold` | `warning` | Minimum Semgrep severity that fails the check: `error`, `warning`, or `info`. |
| `codeql-languages` | *(auto)* | Comma-separated languages for CodeQL. Leave empty to auto-detect from the repository. |
| `docker-image` | *(empty)* | Container image to scan for OS packages with Trivy (e.g. `myorg/app:latest`). Leave empty to skip OS package scanning. |
| `docker-build` | `false` | Build the Docker image from the Dockerfile and scan it for OS packages and application dependencies. |
| `sbom-format` | `cyclonedx` | SBOM output format: `cyclonedx`, `spdx`, or `both`. |
| `trivy-ignore-unfixed` | `true` | Exclude vulnerabilities with no known fix from Trivy file/config scans. |

### Tool versions

| Input | Default | Description |
| --- | --- | --- |
| `gitleaks-version` | `8.30.1` | Gitleaks version to install. |
| `osv-scanner-version` | `2.4.0` | OSV-Scanner version to install. |
| `trivy-version` | `0.72.0` | Trivy version to install. |
| `syft-version` | `1.50.0` | Syft version to install. |
| `semgrep-version` | `latest` | Semgrep version to install (`latest` or an exact version). |

Pinning versions is recommended for reproducible scans in production. You can
override any of them per workflow.

### Reporting

| Input | Default | Description |
| --- | --- | --- |
| `upload-artifacts` | `true` | Upload SARIF, JSON, Markdown, HTML reports and SBOM as workflow artifacts. |
| `enable-pr-comment` | `true` | Post the security report as a comment on pull requests. |
| `report-title` | `AragSoft Security Report` | Title used in reports and pull-request comments. |
| `debug` | `false` | Enable debug logging. |

## Outputs

| Output | Description |
| --- | --- |
| `score` | Overall security score (0-100). |
| `status` | Overall status: `pass`, `warning`, or `fail`. |
| `exit-code` | Exit code produced by the action (0 = pass, 1 = fail). |
| `secrets` | Secret scan result: `pass`, `warning`, `fail`, `skipped`, `error`. |
| `dependencies` | Dependency scan result. |
| `code` | Static analysis result. |
| `codeql` | CodeQL result. |
| `docker` | Docker scan result. |
| `licenses` | License scan result. |
| `repo` | Repository security result. |

## Generated files

All reports are written to `<runner.temp>/aragsoft-security/`:

| File | Description |
| --- | --- |
| `report.json` | Full machine-readable report (score, status, per-check details, findings). |
| `report.md` | Markdown report, used as the pull-request comment body. |
| `report.html` | Self-contained HTML dashboard. |
| `summary.md` | Dashboard written to the GitHub step summary. |
| `security.sarif` | Merged SARIF from every tool. |
| `results/*` | Raw per-tool output (Gitleaks, OSV-Scanner, Semgrep, Trivy, licenses, repo). |
| `sarif/*` | Individual per-tool SARIF files. |
| `sbom/sbom.cyclonedx.json` | CycloneDX SBOM (when enabled). |
| `sbom/sbom.spdx.json` | SPDX SBOM (when enabled). |

## Full example

```yaml
- uses: amixiid/security-checker-workflow@v1
  with:
    # Failure gates
    fail-on-secrets: 'true'
    fail-on-high: 'true'
    fail-on-critical: 'true'
    fail-on-license: 'true'
    fail-on-tool-error: 'true'

    # Checks
    enable-secrets: 'true'
    enable-dependencies: 'true'
    enable-semgrep: 'true'
    enable-codeql: 'true'
    enable-docker: 'true'
    enable-license: 'true'
    enable-sbom: 'true'
    enable-repo: 'true'

    # Tuning
    semgrep-rules: 'p/security-audit'
    codeql-languages: 'javascript-typescript,python'
    docker-image: 'myorg/app:latest'
    sbom-format: 'both'
    debug: 'false'
```

## Environment variables

All inputs are also exported as `AS_*` environment variables for the job
(`AS_FAIL_ON_SECRETS`, `AS_ENABLE_CODEQL`, ...). These are managed by the
action; overriding them manually is not recommended unless you know what you
are doing.
