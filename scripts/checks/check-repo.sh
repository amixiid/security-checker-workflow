#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck source=./lib.sh
# Repository security configuration checks.

check_repo() {
  if [[ "$(as_bool "$AS_ENABLE_REPO")" != "true" ]]; then
    as_log "Repository security checks are disabled."
    return 0
  fi

  as_group "AragSoft Security - Repository security"

  local codeowners_ok=0 codeowners_detail="Not found"
  local security_ok=0 security_detail="Not found"
  local dependabot_ok=0 dependabot_detail="Not found"
  local branch_ok=0 branch_detail="Unknown (no token)"
  local secret_ok=0 secret_detail="Unknown (no token)"

  if [[ -f "$AS_WORKSPACE/.github/CODEOWNERS" ]]; then
    codeowners_ok=1; codeowners_detail="Found at .github/CODEOWNERS"
  elif [[ -f "$AS_WORKSPACE/CODEOWNERS" ]]; then
    codeowners_ok=1; codeowners_detail="Found at CODEOWNERS"
  elif [[ -f "$AS_WORKSPACE/docs/CODEOWNERS" ]]; then
    codeowners_ok=1; codeowners_detail="Found at docs/CODEOWNERS"
  fi

  if [[ -f "$AS_WORKSPACE/.github/SECURITY.md" ]]; then
    security_ok=1; security_detail="Found at .github/SECURITY.md"
  elif [[ -f "$AS_WORKSPACE/SECURITY.md" ]]; then
    security_ok=1; security_detail="Found at SECURITY.md"
  fi

  if [[ -f "$AS_WORKSPACE/.github/dependabot.yml" || -f "$AS_WORKSPACE/.github/dependabot.yaml" ]]; then
    dependabot_ok=1; dependabot_detail="Found at .github/dependabot.yml"
  fi

  if [[ -n "${AS_TOKEN:-}" ]]; then
    local http_code

    http_code="$(curl -sS -o "$AS_RESULTS_DIR/branch-protection.json" -w '%{http_code}' \
      -H "Authorization: Bearer $AS_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$AS_REPOSITORY/branches/$AS_DEFAULT_BRANCH/protection" \
      2>/dev/null || true)"
    case "$http_code" in
      200) branch_ok=1; branch_detail="Branch protection is enabled on $AS_DEFAULT_BRANCH" ;;
      404) branch_ok=0; branch_detail="Branch protection is not enabled on $AS_DEFAULT_BRANCH" ;;
      403) branch_ok=0; branch_detail="Branch protection status could not be read (insufficient permissions)" ;;
      *) branch_ok=0; branch_detail="Branch protection status could not be read (HTTP $http_code)" ;;
    esac

    curl -sS -o "$AS_RESULTS_DIR/repo.json.raw" \
      -H "Authorization: Bearer $AS_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$AS_REPOSITORY" \
      2>/dev/null || true
    if [[ -s "$AS_RESULTS_DIR/repo.json.raw" ]]; then
      local ss_enabled
      ss_enabled="$(node -e '
        const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
        process.stdout.write(String(!!(d && d.security_and_analysis && d.security_and_analysis.secret_scanning && d.security_and_analysis.secret_scanning.enabled)));
      ' "$AS_RESULTS_DIR/repo.json.raw" 2>/dev/null || echo "false")"
      if [[ "$ss_enabled" == "true" ]]; then
        secret_ok=1; secret_detail="Secret scanning is enabled for this repository"
      elif [[ "$ss_enabled" == "false" ]]; then
        secret_ok=0; secret_detail="Secret scanning is not enabled for this repository"
      else
        secret_ok=0; secret_detail="Secret scanning status could not be determined"
      fi
    fi
  fi

  node -e '
    const fs = require("fs");
    const [out, codeowners_ok, codeowners_detail, security_ok, security_detail,
           dependabot_ok, dependabot_detail, branch_ok, branch_detail,
           secret_ok, secret_detail] = process.argv.slice(1);
    const items = [
      { key: "codeowners", label: "CODEOWNERS", ok: codeowners_ok === "1", detail: codeowners_detail },
      { key: "security-md", label: "SECURITY.md", ok: security_ok === "1", detail: security_detail },
      { key: "dependabot", label: "Dependabot configuration", ok: dependabot_ok === "1", detail: dependabot_detail },
      { key: "branch-protection", label: "Branch protection", ok: branch_ok === "1", detail: branch_detail },
      { key: "secret-scanning", label: "Secret scanning (GitHub)", ok: secret_ok === "1", detail: secret_detail },
    ];
    const okCount = items.filter((i) => i.ok).length;
    const report = { items, counts: { ok: okCount, total: items.length } };
    fs.writeFileSync(out, JSON.stringify(report, null, 2));
  ' "$AS_RESULTS_DIR/repo.json" "$codeowners_ok" "$codeowners_detail" "$security_ok" \
    "$security_detail" "$dependabot_ok" "$dependabot_detail" "$branch_ok" "$branch_detail" \
    "$secret_ok" "$secret_detail"

  local ok_count total_count
  ok_count="$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(d.counts.ok))' "$AS_RESULTS_DIR/repo.json")"
  total_count="$(node -e 'const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));process.stdout.write(String(d.counts.total))' "$AS_RESULTS_DIR/repo.json")"
  as_log "Repository security: $ok_count/$total_count checks satisfied."
  if [[ "$ok_count" -lt "$total_count" ]]; then
    as_annotation warning "Some repository security recommendations are not met."
  else
    as_annotation notice "Repository security recommendations are satisfied."
  fi

  as_endgroup
}
