# Troubleshooting

Solutions to the most common problems when using AragSoft Security.

## The action fails with a permissions error

**Symptom:** PR comment is not created, or branch-protection status shows
"insufficient permissions".

**Fix:** grant the token the needed scopes:

```yaml
permissions:
  contents: read
  pull-requests: write
```

## Tool installation fails

**Symptom:** logs show `Could not be installed` or a download error, and the
check is marked `error`.

**Causes and fixes:**

- **No network access** — the action downloads its tools from GitHub releases
  and PyPI. Self-hosted runners must be able to reach `github.com` and `pypi.org`.
- **Version pinned to an asset that does not exist** — if you overrode
  `gitleaks-version` / `osv-scanner-version` / `trivy-version` / `syft-version`
  with a very old or non-existent version, the download 404s. Use the defaults
  or a recent release.
- **Proxy / rate limiting** — on GitHub-hosted runners this is rare. On
  self-hosted runners, configure `HTTP(S)_PROXY` for the runner.
- **Python too old for Semgrep** — Semgrep needs Python 3.8+. On Windows,
  ensure `python` resolves to a real Python (not the Microsoft Store stub).

## Semgrep produces no report / reports execution errors

- Verify `semgrep-rules` is valid. For registry configs use `p/<name>` (e.g.
  `p/security-audit`). For local rules, the path is resolved relative to the
  workspace root.
- If you use a pinned `semgrep-version`, make sure it exists.
- The `error` status appears when Semgrep exits with errors and no results.
  Re-run with `debug: 'true'` and check the raw output in the logs.

## CodeQL does not run or produces no results

- CodeQL runs through `github/codeql-action`. If `codeql-init` fails
  (e.g. languages cannot be detected), the action records CodeQL as `error`
  and continues. Set `codeql-languages` explicitly to fix detection.
- CodeQL requires a build for compiled languages; `autobuild` is used. If the
  project needs a custom build, run a manual build step before the action or
  provide a build step after `github/codeql-action/init` — for now, the
  recommended approach is to disable CodeQL in this action and use
  `github/codeql-action` directly for custom build scenarios.
- CodeQL uploads to code scanning require the repository to have code scanning
  enabled.

## Docker scan is slow or fails

- Trivy downloads its vulnerability database on first run (can take a few
  minutes). Subsequent scans within a run reuse the cache.
- OS package scanning requires an image. Without `docker-image` (or
  `docker-build: 'true'`), the action scans the filesystem for application
  dependencies and the Dockerfile for misconfigurations only.
- If Trivy cannot reach its update endpoints, set `trivy-ignore-unfixed` as
  needed and check your network policy.

## The score seems lower than expected

- Review `docs/SCORING.md`. A single `fail` on secrets (weight 25) drops the
  score dramatically — this is intentional.
- Checks that are disabled or skipped do not contribute to the score.
- Trivy IaC misconfigurations (e.g. `DS-0026`) can turn Docker into a
  `warning`. Use a hardened Dockerfile to raise the score.

## Reports are not uploaded as artifacts

- The `upload-artifacts` input must be `true` (default).
- Artifacts require the `actions: write` permission on the token:
  ```yaml
  permissions:
    actions: write
  ```
- Artifacts are retained for 7 days by default; they are not visible from
  forks' pull requests in the same way as for the base repository.

## Working directory / monorepo issues

- The action scans `$GITHUB_WORKSPACE` (the checkout root). To scan a
  subdirectory, either adjust your checkout or place the manifests you want
  scanned at the root.
- OSV-Scanner uses `--recursive`, but respects `.gitignore`. Files ignored by
  git are not scanned.

## Windows-specific issues

- The action requires `bash`. GitHub-hosted Windows runners ship Git Bash, so
  this works out of the box.
- If a tool binary fails to start with "Permission denied", ensure your
  checkout or self-hosted runner antivirus is not quarantining the downloaded
  binaries.
- Python on Windows: use `setup-python` if `python -m semgrep` fails.

## Still stuck?

Open an issue at <https://github.com/amixiid/aragsoft-security/issues> and
include:

- the runner OS and action version,
- your `action.yml` inputs,
- the relevant log lines from the failing step group,
- and the `aragsoft-security-reports` artifact if available.
