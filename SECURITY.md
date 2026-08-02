# Security Policy

We take the security of AragSoft Security and of the repositories that use it
seriously. Thanks for helping to keep the project and its users safe.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

Always use the latest patch of the `v1` release line:

```yaml
- uses: amixiid/security-checker-workflow@v1
```

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via one of the following channels:

- **GitHub Security Advisory:** open a private advisory at
  <https://github.com/amixiid/security-checker-workflow/security/advisories/new>
- **Email:** security@aragsoft.example (replace with the maintainer's
  real address)

When reporting, please include:

- The affected version and environment (runner OS, action version).
- A description of the vulnerability and its impact.
- Steps to reproduce or a minimal proof of concept.
- Any suggested remediation, if you have one.

You will receive an acknowledgement within **48 hours**, and we will aim to
ship a fix within **7 days** of confirmation. We will keep you informed of the
remediation timeline and credit you (if you wish) in the release notes.

## Disclosure Policy

- We will confirm the vulnerability and determine affected versions.
- We will fix the issue in a private branch and test the fix.
- We will release a patched version and announce it in the CHANGELOG.
- We will publish the advisory (including credit) after the fix is released.

## Scope

This policy covers the source code in this repository, its GitHub Actions
workflows, and the scripts shipped with the action. Vulnerabilities in
third-party tools that this action invokes (Gitleaks, OSV-Scanner, Semgrep,
Trivy, Syft, CodeQL, etc.) should be reported to those projects directly.

## Security Considerations for Users

- This action requires **network access** to install its scanning tools and to
  query vulnerability databases (`osv.dev`, Trivy/Syft databases, Semgrep
  rules). Do not run it on self-hosted runners that are fully air-gapped.
- The action runs with the permissions of the `GITHUB_TOKEN` passed to it. By
  default it uses the automatic token with its default permissions. For
  pull-request comments and branch-protection queries, grant
  `contents: read` and `pull-requests: write` (see README).
- Reports may contain **redacted** secret material (Gitleaks `--redact` is
  enabled). Artifacts are retained for 7 days by default; configure retention
  to match your needs.
