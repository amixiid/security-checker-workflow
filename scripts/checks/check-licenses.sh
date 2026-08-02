#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# License compliance scanning.

check_licenses() {
  if [[ "$(as_bool "$AS_ENABLE_LICENSE")" != "true" ]]; then
    as_log "License scanning is disabled."
    return 0
  fi

  as_group "AragSoft Security - License compliance"

  local node
  node="$(find_node)" || {
    as_annotation warning "Node.js is required for license scanning. License scan was skipped."
    as_record "licenses_error" "Node.js not found for license scanning"
    as_endgroup
    return 0
  }

  local args=("$AS_WORKSPACE" "$AS_RESULTS_DIR/licenses.json")
  local spdx
  spdx="$(find "$AS_SBOM_DIR" -maxdepth 1 -type f -name 'sbom.spdx.json' 2>/dev/null | head -n 1)"
  if [[ -n "$spdx" ]]; then
    args+=(--spdx "$spdx")
  fi

  # Best-effort pip license detection (filtered to requirements.txt packages).
  local py pip_licenses_file requirements_file
  pip_licenses_file="$AS_RESULTS_DIR/pip-licenses.json"
  requirements_file=""
  if [[ -f "$AS_WORKSPACE/requirements.txt" ]]; then
    requirements_file="$AS_WORKSPACE/requirements.txt"
  fi
  if [[ -n "$requirements_file" ]] && py="$(find_python 2>/dev/null)"; then
    if "$py" -m pip install --quiet --disable-pip-version-check pip-licenses 2>/dev/null; then
      "$py" -m pip_licenses --format=json --with-system=false > "$pip_licenses_file" 2>/dev/null || true
      if [[ -s "$pip_licenses_file" ]]; then
        args+=(--pip-licenses "$pip_licenses_file" --pip-requirements "$requirements_file")
      fi
    fi
  fi

  if ! "$node" "$AS_ACTION_PATH/src/license-scan.js" "${args[@]}"; then
    as_record "licenses_error" "License scanner failed"
    as_endgroup
    return 0
  fi

  if [[ -f "$AS_RESULTS_DIR/licenses.json" ]]; then
    local gpl_count pkg_count
    gpl_count="$(node -e 'try{const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(d.counts?d.counts.gpl:0))}catch(e){process.stdout.write("0")}' "$AS_RESULTS_DIR/licenses.json")"
    pkg_count="$(node -e 'try{const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(d.counts?d.counts.packages:0))}catch(e){process.stdout.write("0")}' "$AS_RESULTS_DIR/licenses.json")"
    as_log "License scan: $pkg_count package(s) inspected, $gpl_count with GPL-family license."
    if [[ "$gpl_count" -gt 0 ]]; then
      as_annotation warning "Detected $gpl_count package(s) with GPL-family licenses."
    else
      as_annotation notice "No GPL-family licenses detected."
    fi
  else
    as_record "licenses_error" "License scanner produced no report"
  fi

  as_endgroup
}
