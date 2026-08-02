# Contributing

Thank you for your interest in improving AragSoft Security! Contributions of
all kinds are welcome: bug reports, documentation, new checks, and code.

Please read this guide and our [Code of Conduct](#code-of-conduct) before
opening an issue or pull request.

## Table of contents

- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Making changes](#making-changes)
- [Testing](#testing)
- [Linting](#linting)
- [Adding a new check](#adding-a-new-check)
- [Commit guidelines](#commit-guidelines)
- [Opening a pull request](#opening-a-pull-request)

## Development setup

Requirements:

- Bash 4+
- Node.js 18+ (used for report aggregation and the license scanner)
- Python 3.8+ (used for Semgrep)
- [shellcheck](https://github.com/koalaman/shellcheck)
- [actionlint](https://github.com/rhysd/actionlint)

Clone and install the dev dependencies:

```bash
git clone https://github.com/amixiid/aragsoft-security.git
cd aragsoft-security
# No install step: this project has no runtime dependencies of its own.
# The scan tools are downloaded on demand at run time.
```

## Project layout

```
aragsoft-security/
├── action.yml               # Composite action definition (inputs, steps, outputs)
├── scripts/
│   ├── lib.sh               # Shared helpers (logging, tool install, env)
│   ├── main.sh              # Scan stage entry point
│   ├── finalize.sh          # Aggregation, reports, PR comment, failure gates
│   └── checks/              # One script per security check
├── src/
│   ├── aggregate.js         # Scoring + JSON/Markdown/HTML/SARIF report engine
│   └── license-scan.js      # License detection (npm lockfile, SPDX, pip)
├── docs/                    # In-depth documentation
├── examples/                # Example workflows
└── .github/
    ├── workflows/           # test.yml, release.yml
    └── tests/fixture/       # Sample project used by the CI smoke tests
```

## Making changes

1. Fork the repository and create a feature branch.
2. Make your change, following the existing style.
3. Add or update tests in `.github/workflows/test.yml` if your change affects
   behaviour.
4. Update documentation (`README.md`, `docs/`) and `CHANGELOG.md`.
5. Run the lint checks below.
6. Open a pull request against `main`.

## Testing

There are no unit tests in the traditional sense; quality is enforced through:

- **Static checks** — shellcheck, actionlint and Node syntax validation, run
  automatically in the `lint` job.
- **Smoke tests** — the action is exercised end-to-end on Ubuntu, macOS and
  Windows against a fixture project (`.github/tests/fixture`).
- **Failure-gate test** — verifies the action fails the build when secrets are
  committed.
- **Full-scan test** — runs every check (including CodeQL) on Ubuntu.

Run the checks locally:

```bash
export PATH="$HOME/.local/bin:$PATH"   # if you installed tools there

# Syntax
for f in scripts/*.sh scripts/checks/*.sh; do bash -n "$f"; done
for f in src/*.js; do node --check "$f"; done

# Linting
shellcheck -x scripts/*.sh scripts/checks/*.sh
actionlint action.yml
actionlint .github/workflows/test.yml
actionlint .github/workflows/release.yml

# Local end-to-end smoke test (requires network to install the scan tools)
AS_WORKSPACE=/tmp/example-repo \
AS_ARTIFACTS_DIR=/tmp/aragsoft-out \
AS_REPOSITORY=you/example \
AS_ENABLE_CODEQL=false \
bash scripts/main.sh

AS_ARTIFACTS_DIR=/tmp/aragsoft-out \
AS_CODEQL_INIT_OUTCOME=skipped \
AS_CODEQL_ANALYZE_OUTCOME=skipped \
bash scripts/finalize.sh
```

## Linting

The CI `lint` job runs:

- `actionlint action.yml` and every workflow
- `shellcheck -x scripts/*.sh scripts/checks/*.sh`
- `bash -n` on every shell script
- `node --check` on every JavaScript source

Keep these passing before you open a pull request.

## Adding a new check

1. Create `scripts/checks/check-<name>.sh` that defines a `check_<name>`
   function. It should write raw results into `$AS_RESULTS_DIR` (or
   `$AS_SARIF_DIR`) and use `as_record` to set `<name>_error` /
   `<name>_skipped` as appropriate.
2. Source the new script in `scripts/main.sh` and call it from `main()`.
3. Add an `enable-<name>` input in `action.yml` and export it in the
   "Export AragSoft Security inputs" step.
4. In `src/aggregate.js`: add a weight in `WEIGHTS`, an evaluator function,
   a status row in the report renderers, and any new failure gate.
5. Add documentation and a smoke-test case.

## Commit guidelines

- Use concise, imperative commit messages (`Fix osv-scanner exit-code handling`).
- Reference issues with `#123` where relevant.
- Keep the `CHANGELOG.md` up to date under `## [Unreleased]`.

## Code of conduct

Be respectful and constructive. Harassment and discrimination of any kind are
not tolerated. Please report unacceptable behaviour to the maintainers.

## Getting help

Open a [discussion](https://github.com/amixiid/aragsoft-security/discussions)
or read `docs/TROUBLESHOOTING.md` and `docs/FAQ.md` first.
