#!/usr/bin/env bash
# shellcheck shell=bash
#
# AragSoft Security - finalize stage.
#
# Aggregates all scan results (including the CodeQL SARIF produced by
# github/codeql-action), computes the score, writes the reports, posts the
# pull-request comment, writes job outputs and applies the failure gates.

set -uo pipefail

AS_VERSION="1.0.0"
AS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/lib.sh
source "$AS_SCRIPT_DIR/lib.sh"
as_env_defaults

export AS_VERSION
export AS_CODEQL_INIT_OUTCOME="${AS_CODEQL_INIT_OUTCOME:-skipped}"
export AS_CODEQL_AUTOBUILD_OUTCOME="${AS_CODEQL_AUTOBUILD_OUTCOME:-skipped}"
export AS_CODEQL_ANALYZE_OUTCOME="${AS_CODEQL_ANALYZE_OUTCOME:-skipped}"

# ---------------------------------------------------------------------------
# Aggregate and load the resulting environment
# ---------------------------------------------------------------------------

node "$AS_ACTION_PATH/src/aggregate.js" "$AS_ARTIFACTS_DIR" > "$AS_ARTIFACTS_DIR/.summary.env"

# shellcheck disable=SC1090,SC1091
source "$AS_ARTIFACTS_DIR/.summary.env"

as_log "Score: ${AS_SCORE:-0}/100 (${AS_STATUS:-error})"
as_log "Reports written to $AS_ARTIFACTS_DIR (report.json, report.md, report.html, security.sarif)"

# ---------------------------------------------------------------------------
# GitHub step summary
# ---------------------------------------------------------------------------

if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -f "$AS_ARTIFACTS_DIR/summary.md" ]]; then
  cat "$AS_ARTIFACTS_DIR/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

# ---------------------------------------------------------------------------
# Pull-request comment
# ---------------------------------------------------------------------------

as_post_pr_comment() {
  if [[ "$(as_bool "$AS_ENABLE_PR_COMMENT")" != "true" ]]; then
    as_debug "PR comments are disabled."
    return 0
  fi
  if [[ "$AS_EVENT_NAME" != "pull_request" ]]; then
    as_debug "Not a pull request event; skipping PR comment."
    return 0
  fi
  if [[ -z "${AS_TOKEN:-}" ]]; then
    as_warn "No GITHUB_TOKEN available; skipping PR comment."
    return 0
  fi
  if [[ -z "${GITHUB_EVENT_PATH:-}" || ! -f "$GITHUB_EVENT_PATH" ]]; then
    as_warn "No GITHUB_EVENT_PATH available; skipping PR comment."
    return 0
  fi

  local pr_number
  pr_number="$(node -e '
    try {
      const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      const n = (d.pull_request && d.pull_request.number) || d.number || "";
      process.stdout.write(String(n));
    } catch (e) { process.stdout.write(""); }
  ' "$GITHUB_EVENT_PATH")"
  if [[ -z "$pr_number" ]]; then
    as_warn "Could not determine pull request number; skipping PR comment."
    return 0
  fi

  local marker="<!-- aragsoft-security-report -->"
  local body=""
  if [[ -f "$AS_ARTIFACTS_DIR/report.md" ]]; then
    body="$(cat "$AS_ARTIFACTS_DIR/report.md")"
  fi
  body="${body:0:60000}"
  body+=$'\n'
  body+="$marker"

  local payload existing_id comment_url response
  payload="$(node -e 'process.stdout.write(JSON.stringify({ body: process.argv[1] }))' "$body")"

  response="$(curl -sS -f \
    -H "Authorization: Bearer $AS_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$AS_REPOSITORY/issues/$pr_number/comments" \
    2>/dev/null || true)"
  existing_id="$(node -e '
    const marker = process.argv[1];
    try {
      const arr = JSON.parse(process.argv[2]);
      if (Array.isArray(arr)) {
        for (const c of arr) {
          if (c && c.body && c.body.includes(marker)) { process.stdout.write(String(c.id)); return; }
        }
      }
    } catch (e) {}
    process.stdout.write("");
  ' "$marker" "$response")"

  if [[ -n "$existing_id" ]]; then
    as_log "Updating existing security comment (#$existing_id) on PR #$pr_number"
    comment_url="https://api.github.com/repos/$AS_REPOSITORY/issues/comments/$existing_id"
    if curl -sS -f -X PATCH \
      -H "Authorization: Bearer $AS_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      --data "$payload" \
      "$comment_url" >/dev/null 2>&1; then
      as_info "PR comment updated."
    else
      as_warn "Failed to update PR comment."
    fi
  else
    as_log "Creating security comment on PR #$pr_number"
    if curl -sS -f -X POST \
      -H "Authorization: Bearer $AS_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      --data "$payload" \
      "https://api.github.com/repos/$AS_REPOSITORY/issues/$pr_number/comments" \
      >/dev/null 2>&1; then
      as_info "PR comment created."
    else
      as_warn "Failed to create PR comment (check GITHUB_TOKEN permissions for this event)."
    fi
  fi
}

as_post_pr_comment || true

# ---------------------------------------------------------------------------
# Job outputs
# ---------------------------------------------------------------------------

as_set_output "score" "${AS_SCORE:-0}"
as_set_output "status" "${AS_STATUS:-error}"
as_set_output "exit-code" "${AS_EXIT_CODE:-1}"
as_set_output "secrets" "${AS_SECRETS:-skipped}"
as_set_output "dependencies" "${AS_DEPENDENCIES:-skipped}"
as_set_output "code" "${AS_CODE:-skipped}"
as_set_output "codeql" "${AS_CODEQL:-skipped}"
as_set_output "docker" "${AS_DOCKER:-skipped}"
as_set_output "licenses" "${AS_LICENSES:-skipped}"
as_set_output "repo" "${AS_REPO:-skipped}"

# ---------------------------------------------------------------------------
# Apply failure gate
# ---------------------------------------------------------------------------

as_log "Exit code: ${AS_EXIT_CODE:-1}"
exit "${AS_EXIT_CODE:-1}"
