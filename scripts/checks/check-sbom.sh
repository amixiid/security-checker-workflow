#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# SBOM generation with Syft.

check_sbom() {
  if [[ "$(as_bool "$AS_ENABLE_SBOM")" != "true" ]]; then
    as_log "SBOM generation is disabled."
    return 0
  fi

  as_group "AragSoft Security - SBOM generation (Syft)"

  local exe
  if ! exe="$(install_syft)"; then
    as_annotation warning "Syft could not be installed. SBOM generation was skipped."
    as_record "sbom_error" "Syft installation failed"
    as_endgroup
    return 0
  fi
  "$exe" --version

  case "$AS_SBOM_FORMAT" in
    cyclonedx|spdx|both) : ;;
    *) as_warn "Unsupported sbom-format '$AS_SBOM_FORMAT'; using cyclonedx."
       AS_SBOM_FORMAT="cyclonedx" ;;
  esac

  local syft_args=()
  syft_args+=(dir:"$AS_WORKSPACE")
  syft_args+=(--exclude '**/.git/**')
  syft_args+=(--exclude '**/node_modules/**')
  syft_args+=(--exclude '**/vendor/**')
  syft_args+=(--exclude '**/dist/**')
  syft_args+=(--exclude '**/build/**')

  if [[ "$AS_SBOM_FORMAT" == "cyclonedx" || "$AS_SBOM_FORMAT" == "both" ]]; then
    as_log "Generating CycloneDX SBOM"
    "$exe" "${syft_args[@]}" \
      --output "cyclonedx-json=$AS_SBOM_DIR/sbom.cyclonedx.json" \
      >/dev/null 2> "$AS_RESULTS_DIR/syft.log" || {
        as_warn "Syft CycloneDX generation reported an error; see syft.log"
      }
  fi

  if [[ "$AS_SBOM_FORMAT" == "spdx" || "$AS_SBOM_FORMAT" == "both" ]]; then
    as_log "Generating SPDX SBOM"
    "$exe" "${syft_args[@]}" \
      --output "spdx-json=$AS_SBOM_DIR/sbom.spdx.json" \
      >/dev/null 2>> "$AS_RESULTS_DIR/syft.log" || {
        as_warn "Syft SPDX generation reported an error; see syft.log"
      }
  fi

  local count files=""
  files="$(find "$AS_SBOM_DIR" -maxdepth 1 -type f -name 'sbom.*.json' | wc -l | tr -d ' ')"
  count="${files:-0}"
  as_log "SBOM file(s) generated: $count"
  as_record "sbom_files" "$count"

  as_endgroup
}
