#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC2317
#
# lib.sh - shared helpers for the AragSoft Security action.
#
# This library is meant to be sourced (not executed) by the entry point
# scripts. It provides logging, GitHub Actions workflow-command helpers,
# environment defaults and tool installation routines.

set -uo pipefail

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

as_log() {
  printf '\033[0;36m[aragsoft]\033[0m %s\n' "$*" >&2
}

as_info() {
  printf '\033[0;32m[aragsoft]\033[0m %s\n' "$*" >&2
}

as_warn() {
  printf '\033[0;33m[aragsoft]\033[0m WARNING: %s\n' "$*" >&2
}

as_error() {
  printf '\033[0;31m[aragsoft]\033[0m ERROR: %s\n' "$*" >&2
}

as_debug() {
  if [[ "${AS_DEBUG:-false}" == "true" ]]; then
    printf '\033[0;90m[aragsoft][debug]\033[0m %s\n' "$*" >&2
  fi
}

as_group() {
  echo "::group::$*"
}

as_endgroup() {
  echo "::endgroup::"
}

as_annotation() {
  local level="${1:-notice}"
  local message="$2"
  local file="${3:-}"
  local title="${4:-AragSoft Security}"
  if [[ -n "$file" ]]; then
    echo "::$level file=$file,title=$title::$message"
  else
    echo "::$level title=$title::$message"
  fi
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

# Populate AS_* variables with sensible defaults when running outside of
# GitHub Actions (local testing / development).
as_env_defaults() {
  local key
  for key in \
    AS_FAIL_ON_SECRETS AS_FAIL_ON_HIGH AS_FAIL_ON_CRITICAL AS_FAIL_ON_LICENSE \
    AS_FAIL_ON_TOOL_ERROR AS_ENABLE_SECRETS AS_ENABLE_DEPENDENCIES \
    AS_ENABLE_SEMGREP AS_ENABLE_CODEQL AS_ENABLE_DOCKER AS_ENABLE_LICENSE \
    AS_ENABLE_SBOM AS_ENABLE_REPO AS_SEMGREP_RULES \
    AS_SEMGREP_SEVERITY_THRESHOLD AS_CODEQL_LANGUAGES AS_DOCKER_IMAGE \
    AS_DOCKER_BUILD AS_SBOM_FORMAT AS_TRIVY_IGNORE_UNFIXED AS_GITLEAKS_VERSION \
    AS_OSV_SCANNER_VERSION AS_TRIVY_VERSION AS_SYFT_VERSION AS_SEMGREP_VERSION \
    AS_UPLOAD_ARTIFACTS AS_ENABLE_PR_COMMENT AS_REPORT_TITLE AS_DEBUG; do
    if [[ -z "${!key:-}" ]]; then
      as_debug "Missing $key - setting local default"
      case "$key" in
        AS_FAIL_ON_SECRETS) export "$key=true" ;;
        AS_FAIL_ON_HIGH) export "$key=false" ;;
        AS_FAIL_ON_CRITICAL) export "$key=true" ;;
        AS_FAIL_ON_LICENSE) export "$key=false" ;;
        AS_FAIL_ON_TOOL_ERROR) export "$key=false" ;;
        AS_ENABLE_PR_COMMENT) export "$key=false" ;;
        AS_ENABLE_*) export "$key=true" ;;
        AS_SEMGREP_RULES) export "$key=p/security-audit" ;;
        AS_SEMGREP_SEVERITY_THRESHOLD) export "$key=warning" ;;
        AS_CODEQL_LANGUAGES) export "$key=" ;;
        AS_DOCKER_IMAGE) export "$key=" ;;
        AS_DOCKER_BUILD) export "$key=false" ;;
        AS_SBOM_FORMAT) export "$key=cyclonedx" ;;
        AS_TRIVY_IGNORE_UNFIXED) export "$key=true" ;;
        AS_GITLEAKS_VERSION) export "$key=8.30.1" ;;
        AS_OSV_SCANNER_VERSION) export "$key=2.4.0" ;;
        AS_TRIVY_VERSION) export "$key=0.72.0" ;;
        AS_SYFT_VERSION) export "$key=1.50.0" ;;
        AS_SEMGREP_VERSION) export "$key=latest" ;;
        AS_UPLOAD_ARTIFACTS) export "$key=true" ;;
        AS_REPORT_TITLE) export "$key=AragSoft Security Report" ;;
        AS_DEBUG) export "$key=false" ;;
      esac
    fi
  done

  AS_WORKSPACE="${AS_WORKSPACE:-$PWD}"
  AS_REPOSITORY="${AS_REPOSITORY:-local/repository}"
  AS_SHA="${AS_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
  AS_REF="${AS_REF:-$(git symbolic-ref --short HEAD 2>/dev/null || echo local)}"
  AS_DEFAULT_BRANCH="${AS_DEFAULT_BRANCH:-main}"
  AS_EVENT_NAME="${AS_EVENT_NAME:-push}"
  AS_RUN_ID="${AS_RUN_ID:-local}"
  AS_ACTION_PATH="${AS_ACTION_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
  AS_ARTIFACTS_DIR="${AS_ARTIFACTS_DIR:-${RUNNER_TEMP:-/tmp}/aragsoft-security}"
  AS_RESULTS_DIR="$AS_ARTIFACTS_DIR/results"
  AS_SARIF_DIR="$AS_ARTIFACTS_DIR/sarif"
  AS_SBOM_DIR="$AS_ARTIFACTS_DIR/sbom"
  AS_TOOLS_DIR="${AS_TOOLS_DIR:-$AS_ARTIFACTS_DIR/tools}"
  export AS_WORKSPACE AS_REPOSITORY AS_SHA AS_REF AS_DEFAULT_BRANCH AS_EVENT_NAME
  export AS_RUN_ID AS_ACTION_PATH AS_ARTIFACTS_DIR AS_RESULTS_DIR AS_SARIF_DIR
  export AS_SBOM_DIR AS_TOOLS_DIR

  mkdir -p "$AS_ARTIFACTS_DIR" "$AS_RESULTS_DIR" "$AS_SARIF_DIR" "$AS_SBOM_DIR" "$AS_TOOLS_DIR"
}

# Parse an AS_* boolean-ish input into a canonical value.
as_bool() {
  case "$1" in
    true|True|TRUE|1|yes|on) echo "true" ;;
    *) echo "false" ;;
  esac
}

# ---------------------------------------------------------------------------
# OS / architecture detection
# ---------------------------------------------------------------------------

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "unknown" ;;
  esac
}

AS_OS="$(detect_os)"
AS_ARCH="$(detect_arch)"
export AS_OS AS_ARCH

# Return the platform binary extension, if any.
bin_ext() {
  if [[ "$AS_OS" == "windows" ]]; then
    echo ".exe"
  fi
}

# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

# Download a URL to a destination file with a follow redirects.
as_download() {
  local url="$1"
  local dest="$2"
  local tmp
  tmp="$dest.part"
  as_debug "Downloading $url -> $dest"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 -o "$tmp" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp" "$url"
  else
    as_error "Neither curl nor wget is available to download $url"
    return 1
  fi
  mv "$tmp" "$dest"
}

# Extract an archive (tar.gz / zip) into a destination directory.
as_extract() {
  local archive="$1"
  local dest="$2"
  mkdir -p "$dest"
  case "$archive" in
    *.zip) unzip -oq "$archive" -d "$dest" ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$dest" ;;
    *)
      as_error "Unsupported archive format: $archive"
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Tool installation
# ---------------------------------------------------------------------------

# Internal: write the path of an installed binary into AS_TOOLS_BIN via
# stdout. Creates a small wrapper when the binary is not directly executable
# (e.g. .exe on Windows) so callers can always invoke it plainly.
as_install_binary() {
  local tool="$1"
  local bin_dir="$AS_TOOLS_DIR/bin"
  local exe
  exe="$bin_dir/$tool$(bin_ext)"
  mkdir -p "$bin_dir"
  if [[ "$AS_OS" == "windows" ]]; then
    chmod +x "$exe" 2>/dev/null || true
  fi
  printf '%s\n' "$exe"
}

# Download and install Gitleaks.
install_gitleaks() {
  local version="${AS_GITLEAKS_VERSION:-8.30.1}"
  local os_asset arch_asset archive
  case "$AS_OS" in
    linux) os_asset="linux" ;;
    darwin) os_asset="darwin" ;;
    windows) os_asset="windows" ;;
  esac
  case "$AS_ARCH" in
    amd64) arch_asset="x64" ;;
    arm64) arch_asset="arm64" ;;
  esac
  archive="$AS_TOOLS_DIR/gitleaks.tar.gz"
  if [[ "$AS_OS" == "windows" ]]; then
    archive="$AS_TOOLS_DIR/gitleaks.zip"
  fi
  if [[ ! -x "$AS_TOOLS_DIR/bin/gitleaks$(bin_ext)" ]]; then
    as_log "Installing Gitleaks $version ($AS_OS/$AS_ARCH)"
    as_download \
      "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${os_asset}_${arch_asset}.tar.gz" \
      "$AS_TOOLS_DIR/gitleaks.tar.gz" ||
      as_download \
        "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${os_asset}_${arch_asset}.zip" \
        "$archive"
    as_extract "$archive" "$AS_TOOLS_DIR/bin"
  fi
  as_install_binary "gitleaks"
}

# Download and install OSV-Scanner (released as a raw binary).
install_osv_scanner() {
  local version="${AS_OSV_SCANNER_VERSION:-2.4.0}"
  local url ext
  ext="$(bin_ext)"
  if [[ ! -x "$AS_TOOLS_DIR/bin/osv-scanner$ext" ]]; then
    as_log "Installing OSV-Scanner $version ($AS_OS/$AS_ARCH)"
    url="https://github.com/google/osv-scanner/releases/download/v${version}/osv-scanner_${AS_OS}_${AS_ARCH}${ext}"
    as_download "$url" "$AS_TOOLS_DIR/bin/osv-scanner$ext"
    chmod +x "$AS_TOOLS_DIR/bin/osv-scanner$ext" 2>/dev/null || true
  fi
  as_install_binary "osv-scanner"
}

# Download and install Trivy.
install_trivy() {
  local version="${AS_TRIVY_VERSION:-0.72.0}"
  local os_asset arch_asset archive
  case "$AS_OS" in
    linux) os_asset="Linux" ;;
    darwin) os_asset="macOS" ;;
    windows) os_asset="Windows" ;;
  esac
  case "$AS_ARCH" in
    amd64) arch_asset="64bit" ;;
    arm64) arch_asset="ARM64" ;;
  esac
  archive="$AS_TOOLS_DIR/trivy.tar.gz"
  if [[ "$AS_OS" == "windows" ]]; then
    archive="$AS_TOOLS_DIR/trivy.zip"
  fi
  if [[ ! -x "$AS_TOOLS_DIR/bin/trivy$(bin_ext)" ]]; then
    as_log "Installing Trivy $version ($AS_OS/$AS_ARCH)"
    as_download \
      "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${os_asset}-${arch_asset}.tar.gz" \
      "$AS_TOOLS_DIR/trivy.tar.gz" ||
      as_download \
        "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${os_asset}-${arch_asset}.zip" \
        "$archive"
    as_extract "$archive" "$AS_TOOLS_DIR/bin"
  fi
  as_install_binary "trivy"
}

# Download and install Syft.
install_syft() {
  local version="${AS_SYFT_VERSION:-1.50.0}"
  local os_asset archive
  case "$AS_OS" in
    linux) os_asset="linux" ;;
    darwin) os_asset="darwin" ;;
    windows) os_asset="windows" ;;
  esac
  archive="$AS_TOOLS_DIR/syft.tar.gz"
  if [[ "$AS_OS" == "windows" ]]; then
    archive="$AS_TOOLS_DIR/syft.zip"
  fi
  if [[ ! -x "$AS_TOOLS_DIR/bin/syft$(bin_ext)" ]]; then
    as_log "Installing Syft $version ($AS_OS/$AS_ARCH)"
    as_download \
      "https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_${os_asset}_${AS_ARCH}.tar.gz" \
      "$AS_TOOLS_DIR/syft.tar.gz" ||
      as_download \
        "https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_${os_asset}_${AS_ARCH}.zip" \
        "$archive"
    as_extract "$archive" "$AS_TOOLS_DIR/bin"
  fi
  as_install_binary "syft"
}

# Install Semgrep via pip (works on Linux, macOS and Windows). Semgrep is
# always invoked through a generated wrapper so that Python environments
# without a user bin directory on PATH (and PEP 668 "externally managed"
# systems) work reliably.
install_semgrep() {
  local py="${1:-python3}"
  local ext
  ext="$(bin_ext)"
  local exe="$AS_TOOLS_DIR/bin/semgrep$ext"
  if [[ ! -x "$exe" ]]; then
    as_log "Installing Semgrep via pip"
    local pip_log="$AS_TOOLS_DIR/semgrep-install.log"
    if [[ "${AS_SEMGREP_VERSION:-latest}" == "latest" ]]; then
      "$py" -m pip install --quiet --disable-pip-version-check --user semgrep 2>> "$pip_log" \
        || "$py" -m pip install --quiet --disable-pip-version-check --break-system-packages --user semgrep 2>> "$pip_log"
    else
      "$py" -m pip install --quiet --disable-pip-version-check --user "semgrep==${AS_SEMGREP_VERSION}" 2>> "$pip_log" \
        || "$py" -m pip install --quiet --disable-pip-version-check --break-system-packages --user "semgrep==${AS_SEMGREP_VERSION}" 2>> "$pip_log"
    fi
    local semgrep_cmd=""
    semgrep_cmd="$(command -v semgrep 2>/dev/null || true)"
    if [[ -z "$semgrep_cmd" ]]; then
      for d in "$HOME/.local/bin" "$HOME/bin"; do
        if [[ -x "$d/semgrep$ext" ]]; then
          semgrep_cmd="$d/semgrep$ext"
          break
        fi
      done
    fi
    if [[ -n "$semgrep_cmd" ]]; then
      printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$semgrep_cmd" > "$exe"
    else
      local py_path
      py_path="$(command -v "$py")"
      printf '#!/usr/bin/env bash\nexec %q -m semgrep "$@"\n' "$py_path" > "$exe"
    fi
    chmod +x "$exe"
  fi
  printf '%s\n' "$exe"
}

# Locate a Python interpreter.
find_python() {
  local py
  for py in python3 python py; do
    if command -v "$py" >/dev/null 2>&1; then
      printf '%s\n' "$py"
      return 0
    fi
  done
  as_error "No Python interpreter found"
  return 1
}

# Locate a Node.js runtime.
find_node() {
  if command -v node >/dev/null 2>&1; then
    printf '%s\n' "node"
    return 0
  fi
  as_error "Node.js is required but was not found on PATH"
  return 1
}

# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

# Record a check-level note into the shared results meta file.
# Usage: as_record <key> <value>
as_record() {
  local meta_file="$AS_RESULTS_DIR/meta.json"
  local key="$1"
  local value="$2"
  if [[ -f "$meta_file" ]]; then
    node -e '
      const fs = require("fs");
      const [f, k, v] = process.argv.slice(1);
      const data = JSON.parse(fs.readFileSync(f, "utf8"));
      data[k] = v;
      fs.writeFileSync(f, JSON.stringify(data, null, 2));
    ' "$meta_file" "$key" "$value"
  else
    printf '{\n  "%s": %s\n}\n' "$key" "$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$value")" > "$meta_file"
  fi
}

# Emit a GitHub Actions step result (used to fail specific workflow steps).
as_set_output() {
  local name="$1"
  local value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  fi
}
