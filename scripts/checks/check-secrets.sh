#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# Secret scanning with Gitleaks.

check_secrets() {
  if [[ "$(as_bool "$AS_ENABLE_SECRETS")" != "true" ]]; then
    as_log "Secret scanning is disabled."
    return 0
  fi

  as_group "AragSoft Security - Secret scanning (Gitleaks)"

  local exe findings_json findings_sarif
  if ! exe="$(install_gitleaks)"; then
    as_annotation warning "Gitleaks could not be installed. Secret scanning was skipped."
    as_record "secrets_error" "Gitleaks installation failed"
    as_endgroup
    return 0
  fi
  as_log "Running Gitleaks over $AS_WORKSPACE"
  "$exe" --version

  findings_json="$AS_RESULTS_DIR/secrets.json"
  findings_sarif="$AS_SARIF_DIR/gitleaks.sarif"

  if ! "$exe" detect \
    --source "$AS_WORKSPACE" \
    --no-banner \
    --redact \
    --report-format json \
    --report-path "$findings_json" \
    --exit-code 0 \
    --log-level error; then
    as_warn "Gitleaks exited abnormally; results may be incomplete."
  fi

  "$exe" detect \
    --source "$AS_WORKSPACE" \
    --no-banner \
    --redact \
    --report-format sarif \
    --report-path "$findings_sarif" \
    --exit-code 0 \
    --log-level error >/dev/null 2>&1 || true

  if [[ -f "$findings_json" ]]; then
    local count
    count="$(node -e 'try{const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(Array.isArray(d)?d.length:0))}catch(e){process.stdout.write("0")}' "$findings_json")"
    as_log "Gitleaks found $count potential secret(s)."
    if [[ "$count" -gt 0 ]]; then
      as_annotation error "Gitleaks detected $count potential secret(s). See the security report."
    else
      as_annotation notice "Gitleaks found no secrets."
    fi
  else
    as_warn "Gitleaks produced no report file."
    as_record "secrets_error" "Gitleaks produced no report file"
  fi

  as_endgroup
}
