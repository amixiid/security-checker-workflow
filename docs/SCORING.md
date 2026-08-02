# Scoring

AragSoft Security computes a single **0-100 security score** from the enabled
checks. The scoring is deliberately simple, transparent and deterministic so
you can reason about changes between runs.

## How the score works

Each check has a fixed weight. All enabled checks that produced a result
(`pass`, `warning`, or `fail`) contribute to the score:

| Check | Weight | Pass | Warning | Fail |
| --- | --- | --- | --- | --- |
| Secret scanning (Gitleaks) | 25 | 25 | 15 | 0 |
| Dependency vulnerabilities (OSV-Scanner) | 20 | 20 | 12 | 0 |
| Static analysis (Semgrep) | 15 | 15 | 9 | 0 |
| CodeQL | 15 | 15 | 9 | 0 |
| Docker security (Trivy) | 10 | 10 | 6 | 0 |
| License compliance | 10 | 10 | 6 | 0 |
| Repository security | 5 | 5 | 3 | 0 |
| **Total** | **100** | **100** | — | — |

A `warning` status earns **60%** of the check's weight. A `fail` earns **0**.

Checks that are disabled, skipped (not applicable) or that errored are
**excluded** from the score, and their weight is dropped from the total so the
score always ranges from 0 to 100.

```
score = round( 100 * Σ(weight of each passing/warning check) / Σ(weight of included checks) )
```

## Per-check status rules

| Check | PASS | WARNING | FAIL |
| --- | --- | --- | --- |
| Secrets | no findings | — | 1+ findings |
| Dependencies | no vulnerabilities | only low/medium | any high or critical |
| Static analysis | no findings | findings below threshold | findings at/above threshold |
| CodeQL | no findings | only `warning` results | any `error` result |
| Docker | no findings | only low/medium | any high/critical |
| Licenses | no GPL packages | 1+ GPL packages (default) | 1+ GPL packages with `fail-on-license` |
| Repository | all checks satisfied | some missing | all missing |

## Overall status

- `fail` if any included check fails
- otherwise `warning` if any included check warns
- otherwise `pass`

## Failure gates vs score

The score is informative; the **failure gates** are what stop your build:

| Gate | Fails when |
| --- | --- |
| `fail-on-secrets` (default `true`) | secrets are detected |
| `fail-on-critical` (default `true`) | critical dependency vulnerabilities exist |
| `fail-on-high` (default `false`) | high dependency vulnerabilities exist |
| `fail-on-license` (default `false`) | GPL-family licenses are detected |
| `fail-on-tool-error` (default `false`) | any security tool fails to run |

A scan that finds critical vulnerabilities will therefore both lower the score
**and** fail the workflow by default.

## Example

Secrets PASS (25) + Dependencies PASS (20) + CodeQL PASS (15) + Docker PASS
(10) + Licenses WARNING (6) + Semgrep PASS (15) + Repo PASS (5) = **96/100**.
