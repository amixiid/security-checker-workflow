#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# Static code analysis with Semgrep.

check_semgrep() {
  if [[ "$(as_bool "$AS_ENABLE_SEMGREP")" != "true" ]]; then
    as_log "Static analysis is disabled."
    return 0
  fi

  as_group "AragSoft Security - Static code analysis (Semgrep)"

  local py exe rules
  py="$(find_python)" || {
    as_annotation warning "Python is required for Semgrep. Static analysis was skipped."
    as_record "code_error" "Python interpreter not found for Semgrep"
    as_endgroup
    return 0
  }

  if ! exe="$(install_semgrep "$py")"; then
    as_annotation warning "Semgrep could not be installed. Static analysis was skipped."
    as_record "code_error" "Semgrep installation failed"
    as_endgroup
    return 0
  fi
  "$exe" --version

  rules="$AS_SEMGREP_RULES"
  case "$rules" in
    p/*|r/*|https://*|http://*) : ;;
    *) if [[ -d "$AS_WORKSPACE/$rules" || -f "$AS_WORKSPACE/$rules" ]]; then
         rules="$AS_WORKSPACE/$rules"
       else
         as_warn "Semgrep rules path '$rules' was not found in the workspace; falling back to p/security-audit."
         rules="p/security-audit"
       fi ;;
  esac
  as_log "Using Semgrep configuration: $rules"

  local json_out sarif_out
  json_out="$AS_RESULTS_DIR/semgrep.json"
  sarif_out="$AS_SARIF_DIR/semgrep.sarif"

  export SEMGREP_ENABLE_METRICS=0
  if ! "$exe" scan \
    --config "$rules" \
    --json \
    --output "$json_out" \
    --metrics off \
    --disable-version-check \
    --exclude .git \
    "$AS_WORKSPACE"; then
    :
  fi

  "$exe" scan \
    --config "$rules" \
    --sarif \
    --output "$sarif_out" \
    --metrics off \
    --disable-version-check \
    --exclude .git \
    "$AS_WORKSPACE" >/dev/null 2>&1 || true

  if [[ -f "$json_out" ]]; then
    local count
    count="$(node -e '
      try {
        const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        process.stdout.write(String((d.results || []).length));
      } catch (e) { process.stdout.write("0"); }
    ' "$json_out")"
    as_log "Semgrep reported $count finding(s)."
    if [[ "$count" -gt 0 ]]; then
      as_annotation error "Semgrep reported $count finding(s). See the security report."
    fi
  else
    as_warn "Semgrep produced no report file."
    as_record "code_error" "Semgrep produced no report file"
  fi

  as_endgroup
}
