#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# Docker security scanning with Trivy.

check_docker() {
  if [[ "$(as_bool "$AS_ENABLE_DOCKER")" != "true" ]]; then
    as_log "Docker scanning is disabled."
    return 0
  fi

  as_group "AragSoft Security - Docker security (Trivy)"

  local has_dockerfile=0 dockerfile=""
  dockerfile="$(find "$AS_WORKSPACE" -maxdepth 3 -type f -iname 'Dockerfile' -o -type f -iname 'Dockerfile.*' 2>/dev/null | head -n 1)"

  if [[ -n "$dockerfile" ]]; then
    has_dockerfile=1
    as_log "Dockerfile found: $dockerfile"
  fi

  local has_image=0
  if [[ -n "${AS_DOCKER_IMAGE:-}" ]]; then
    has_image=1
    as_log "Docker image configured for scanning: $AS_DOCKER_IMAGE"
  fi

  if [[ "$has_dockerfile" -eq 0 && "$has_image" -eq 0 ]]; then
    as_log "No Dockerfile and no docker-image input - Docker scan skipped."
    as_record "docker_skipped" "No Dockerfile and no docker-image input"
    as_endgroup
    return 0
  fi

  local exe
  if ! exe="$(install_trivy)"; then
    as_annotation warning "Trivy could not be installed. Docker scan was skipped."
    as_record "docker_error" "Trivy installation failed"
    as_endgroup
    return 0
  fi
  "$exe" --version | head -n 1

  export TRIVY_CACHE_DIR="$AS_TOOLS_DIR/trivy-cache"
  mkdir -p "$TRIVY_CACHE_DIR"

  local ignore_unfixed=()
  if [[ "$(as_bool "$AS_TRIVY_IGNORE_UNFIXED")" == "true" ]]; then
    ignore_unfixed=(--ignore-unfixed)
  fi

  # Scan the configured image (OS packages + application dependencies).
  if [[ "$has_image" -eq 1 ]]; then
    as_log "Scanning container image: $AS_DOCKER_IMAGE"
    "$exe" image \
      --format json \
      --output "$AS_RESULTS_DIR/trivy-image.json" \
      --exit-code 0 \
      --timeout 15m \
      "${ignore_unfixed[@]}" \
      "$AS_DOCKER_IMAGE" 2> "$AS_RESULTS_DIR/trivy-image.log" || {
        as_warn "Trivy image scan reported an error; see trivy-image.log"
      }
    "$exe" image \
      --format sarif \
      --output "$AS_SARIF_DIR/trivy-image.sarif" \
      --exit-code 0 \
      --timeout 15m \
      "${ignore_unfixed[@]}" \
      "$AS_DOCKER_IMAGE" >/dev/null 2>&1 || true
  fi

  # Optionally build the image from the Dockerfile.
  if [[ "$(as_bool "$AS_DOCKER_BUILD")" == "true" && "$has_dockerfile" -eq 1 ]]; then
    if command -v docker >/dev/null 2>&1; then
      local built_image="aragsoft-security:scan"
      as_log "Building image $built_image for OS package scanning"
      if docker build --quiet -t "$built_image" "$(dirname "$dockerfile")" >/dev/null 2>&1; then
        "$exe" image \
          --format json \
          --output "$AS_RESULTS_DIR/trivy-image.json" \
          --exit-code 0 \
          --timeout 15m \
          "${ignore_unfixed[@]}" \
          "$built_image" 2> "$AS_RESULTS_DIR/trivy-image.log" || true
      else
        as_warn "Docker image build failed; OS package scan skipped."
        as_record "docker_os_scan_skipped" "Docker image build failed"
      fi
    else
      as_warn "Docker CLI not available; skipping image build and OS package scan."
      as_record "docker_os_scan_skipped" "Docker CLI not available"
    fi
  fi

  # Scan the repository filesystem (application dependencies + secrets).
  if [[ "$has_dockerfile" -eq 1 ]]; then
    as_log "Scanning repository filesystem with Trivy"
    "$exe" fs \
      --scanners vuln,secret \
      --format json \
      --output "$AS_RESULTS_DIR/trivy-fs.json" \
      --exit-code 0 \
      --timeout 15m \
      --skip-dirs "node_modules" \
      --skip-dirs ".git" \
      --skip-dirs "vendor" \
      --skip-dirs "dist" \
      --skip-dirs "build" \
      --skip-dirs "__pycache__" \
      "${ignore_unfixed[@]}" \
      "$AS_WORKSPACE" 2> "$AS_RESULTS_DIR/trivy-fs.log" || {
        as_warn "Trivy filesystem scan reported an error; see trivy-fs.log"
      }
    "$exe" fs \
      --scanners vuln,secret \
      --format sarif \
      --output "$AS_SARIF_DIR/trivy-fs.sarif" \
      --exit-code 0 \
      --timeout 15m \
      --skip-dirs "node_modules" \
      --skip-dirs ".git" \
      --skip-dirs "vendor" \
      --skip-dirs "dist" \
      --skip-dirs "build" \
      --skip-dirs "__pycache__" \
      "${ignore_unfixed[@]}" \
      "$AS_WORKSPACE" >/dev/null 2>&1 || true

    as_log "Scanning IaC / Dockerfile configuration with Trivy"
    "$exe" config \
      --format json \
      --output "$AS_RESULTS_DIR/trivy-config.json" \
      --exit-code 0 \
      --timeout 10m \
      "$AS_WORKSPACE" 2> "$AS_RESULTS_DIR/trivy-config.log" || {
        as_warn "Trivy config scan reported an error; see trivy-config.log"
      }
    "$exe" config \
      --format sarif \
      --output "$AS_SARIF_DIR/trivy-config.sarif" \
      --exit-code 0 \
      --timeout 10m \
      "$AS_WORKSPACE" >/dev/null 2>&1 || true
  fi

  as_endgroup
}
