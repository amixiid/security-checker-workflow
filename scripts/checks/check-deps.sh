#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# Dependency vulnerability scanning with OSV-Scanner.

# List of lockfiles / manifests OSV-Scanner understands, used to detect which
# package managers exist in the repository.
as_lockfiles() {
  printf '%s\n' \
    package-lock.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json bun.lockb bun.lock \
    requirements.txt requirements-*.txt pyproject.toml Pipfile Pipfile.lock poetry.lock uv.lock \
    go.mod go.sum Gopkg.lock vendor/modules.txt \
    Cargo.lock composer.lock Gemfile.lock gradle.lockfile mix.lock \
    packages.lock.json Paket.lock
}

check_dependencies() {
  if [[ "$(as_bool "$AS_ENABLE_DEPENDENCIES")" != "true" ]]; then
    as_log "Dependency scanning is disabled."
    return 0
  fi

  as_group "AragSoft Security - Dependency vulnerabilities (OSV-Scanner)"

  local exe found=0 manager
  local managers=""

  # Auto-detect which package managers exist.
  for manager in npm pnpm yarn pip cargo go; do
    case "$manager" in
      npm) if [[ -f "$AS_WORKSPACE/package-lock.json" || -f "$AS_WORKSPACE/npm-shrinkwrap.json" ]]; then
             found=1; managers="$managers npm"; fi ;;
      pnpm) if [[ -f "$AS_WORKSPACE/pnpm-lock.yaml" ]]; then
              found=1; managers="$managers pnpm"; fi ;;
      yarn) if [[ -f "$AS_WORKSPACE/yarn.lock" ]]; then
              found=1; managers="$managers yarn"; fi ;;
      pip) if [[ -f "$AS_WORKSPACE/requirements.txt" || -f "$AS_WORKSPACE/Pipfile.lock" \
             || -f "$AS_WORKSPACE/poetry.lock" || -f "$AS_WORKSPACE/pyproject.toml" ]]; then
             found=1; managers="$managers pip"; fi ;;
      cargo) if [[ -f "$AS_WORKSPACE/Cargo.lock" ]]; then
               found=1; managers="$managers cargo"; fi ;;
      go) if [[ -f "$AS_WORKSPACE/go.sum" || -f "$AS_WORKSPACE/go.mod" ]]; then
             found=1; managers="$managers go"; fi ;;
    esac
  done

  if [[ "$found" -eq 0 ]]; then
    as_log "No supported lockfiles or manifests found - dependency scan skipped."
    as_record "dependencies_skipped" "No supported lockfiles or manifests found"
    as_endgroup
    return 0
  fi

  as_log "Detected package manager(s):$managers"

  if ! exe="$(install_osv_scanner)"; then
    as_annotation warning "OSV-Scanner could not be installed. Dependency scan was skipped."
    as_record "dependencies_error" "OSV-Scanner installation failed"
    as_endgroup
    return 0
  fi
  "$exe" --version 2>&1 | head -n 1

  local json_out sarif_out
  json_out="$AS_RESULTS_DIR/deps.json"
  sarif_out="$AS_SARIF_DIR/osv-scanner.sarif"

  if ! "$exe" scan \
    --recursive \
    --format json \
    --verbosity error \
    --no-call-analysis=go \
    "$AS_WORKSPACE" > "$json_out" 2> "$AS_RESULTS_DIR/osv-scanner.log"; then
    as_debug "OSV-Scanner exited non-zero (this is expected when vulnerabilities are found)."
  fi

  "$exe" scan \
    --recursive \
    --format sarif \
    --verbosity error \
    --no-call-analysis=go \
    "$AS_WORKSPACE" > "$sarif_out" 2>> "$AS_RESULTS_DIR/osv-scanner.log" || true

  if [[ -f "$json_out" ]]; then
    local count
    count="$(node -e '
      try {
        const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        let n = 0;
        for (const r of (d.results || [])) for (const p of (r.packages || [])) n += (p.vulnerabilities || []).length;
        process.stdout.write(String(n));
      } catch (e) { process.stdout.write("0"); }
    ' "$json_out")"
    as_log "OSV-Scanner found $count known vulnerable dependency instance(s)."
  else
    as_warn "OSV-Scanner produced no report file."
    as_record "dependencies_error" "OSV-Scanner produced no report file"
  fi

  as_endgroup
}
