#!/usr/bin/env bash
# shellcheck shell=bash
#
# AragSoft Security - main entry point (scan stage).
#
# Runs every enabled check that does not require a separate GitHub Action
# step (CodeQL runs through github/codeql-action in action.yml). This script
# always exits 0 so that reporting can complete; failure gating happens in
# finalize.sh.

set -uo pipefail

AS_VERSION="1.0.0"
AS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/lib.sh
source "$AS_SCRIPT_DIR/lib.sh"
as_env_defaults

# shellcheck source=scripts/checks/check-secrets.sh
source "$AS_SCRIPT_DIR/checks/check-secrets.sh"
# shellcheck source=scripts/checks/check-deps.sh
source "$AS_SCRIPT_DIR/checks/check-deps.sh"
# shellcheck source=scripts/checks/check-semgrep.sh
source "$AS_SCRIPT_DIR/checks/check-semgrep.sh"
# shellcheck source=scripts/checks/check-docker.sh
source "$AS_SCRIPT_DIR/checks/check-docker.sh"
# shellcheck source=scripts/checks/check-sbom.sh
source "$AS_SCRIPT_DIR/checks/check-sbom.sh"
# shellcheck source=scripts/checks/check-licenses.sh
source "$AS_SCRIPT_DIR/checks/check-licenses.sh"
# shellcheck source=scripts/checks/check-repo.sh
source "$AS_SCRIPT_DIR/checks/check-repo.sh"

as_write_meta() {
  node -e '
    const fs = require("fs");
    const meta = {
      version: process.env.AS_VERSION || "1.0.0",
      repository: process.env.AS_REPOSITORY || "",
      sha: process.env.AS_SHA || "",
      ref: process.env.AS_REF || "",
      default_branch: process.env.AS_DEFAULT_BRANCH || "",
      event_name: process.env.AS_EVENT_NAME || "",
      run_id: process.env.AS_RUN_ID || "",
      actor: process.env.AS_ACTOR || "",
      started_at: new Date().toISOString(),
      os: process.env.AS_OS || "",
      arch: process.env.AS_ARCH || "",
      tool_versions: {
        gitleaks: process.env.AS_GITLEAKS_VERSION || "",
        osv_scanner: process.env.AS_OSV_SCANNER_VERSION || "",
        trivy: process.env.AS_TRIVY_VERSION || "",
        syft: process.env.AS_SYFT_VERSION || "",
        semgrep: process.env.AS_SEMGREP_VERSION || "",
      },
      config: {
        fail_on_secrets: process.env.AS_FAIL_ON_SECRETS || "",
        fail_on_high: process.env.AS_FAIL_ON_HIGH || "",
        fail_on_critical: process.env.AS_FAIL_ON_CRITICAL || "",
        fail_on_license: process.env.AS_FAIL_ON_LICENSE || "",
        fail_on_tool_error: process.env.AS_FAIL_ON_TOOL_ERROR || "",
        enable_secrets: process.env.AS_ENABLE_SECRETS || "",
        enable_dependencies: process.env.AS_ENABLE_DEPENDENCIES || "",
        enable_semgrep: process.env.AS_ENABLE_SEMGREP || "",
        enable_codeql: process.env.AS_ENABLE_CODEQL || "",
        enable_docker: process.env.AS_ENABLE_DOCKER || "",
        enable_license: process.env.AS_ENABLE_LICENSE || "",
        enable_sbom: process.env.AS_ENABLE_SBOM || "",
        enable_repo: process.env.AS_ENABLE_REPO || "",
        semgrep_rules: process.env.AS_SEMGREP_RULES || "",
        semgrep_severity_threshold: process.env.AS_SEMGREP_SEVERITY_THRESHOLD || "",
        sbom_format: process.env.AS_SBOM_FORMAT || "",
        docker_image: process.env.AS_DOCKER_IMAGE || "",
        docker_build: process.env.AS_DOCKER_BUILD || "",
      },
    };
    fs.writeFileSync(process.env.AS_RESULTS_DIR + "/meta.json", JSON.stringify(meta, null, 2));
  '
  as_record "reports_dir" "$AS_ARTIFACTS_DIR"
}

main() {
  as_group "AragSoft Security v$AS_VERSION"
  as_log "Repository: ${AS_REPOSITORY:-unknown}"
  as_log "Commit: ${AS_SHA:-unknown}"
  as_log "OS/Arch: $AS_OS/$AS_ARCH"
  as_log "Reports directory: $AS_ARTIFACTS_DIR"
  as_log "Debug: $(as_bool "$AS_DEBUG")"

  as_write_meta

  check_secrets
  check_dependencies
  check_semgrep
  check_docker
  check_sbom
  check_licenses
  check_repo

  as_endgroup
  as_log "Scans complete. CodeQL runs as a dedicated step; the final report, score and failure gates are computed in the finalize step."
  exit 0
}

main
