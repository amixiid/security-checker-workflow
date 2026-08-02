#!/usr/bin/env node
/**
 * AragSoft Security - aggregation and reporting engine.
 *
 * Reads the raw results produced by scripts/main.sh plus the CodeQL SARIF
 * output, computes the per-check statuses and the overall 0-100 score,
 * applies the failure gates and writes:
 *
 *   report.json     - full machine-readable report
 *   report.md       - Markdown report (also used for the PR comment)
 *   summary.md      - dashboard for GITHUB_STEP_SUMMARY
 *   report.html     - self-contained HTML dashboard
 *   security.sarif  - merged SARIF from all tools
 *
 * Prints `export AS_*` lines to stdout that finalize.sh sources to learn the
 * final score, status and exit code.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ARTIFACTS = process.argv[2] || (process.env.AS_ARTIFACTS_DIR || '');
const RESULTS = path.join(ARTIFACTS, 'results');
const SARIF_DIR = path.join(ARTIFACTS, 'sarif');
const CODEQL_DIR = path.join(ARTIFACTS, 'codeql');
const SBOM_DIR = path.join(ARTIFACTS, 'sbom');

const env = process.env;
const bool = (v, dflt) => {
  if (v === undefined || v === '') return dflt;
  return ['true', '1', 'yes', 'on'].includes(String(v).toLowerCase());
};
const str = (v, dflt = '') => (v === undefined ? dflt : String(v));

const cfg = {
  repo: str(env.AS_REPOSITORY, 'local/repository'),
  sha: str(env.AS_SHA),
  ref: str(env.AS_REF),
  defaultBranch: str(env.AS_DEFAULT_BRANCH),
  event: str(env.AS_EVENT_NAME, 'push'),
  runId: str(env.AS_RUN_ID),
  os: str(env.AS_OS),
  arch: str(env.AS_ARCH),
  version: str(env.AS_VERSION, '1.0.0'),
  title: str(env.AS_REPORT_TITLE, 'AragSoft Security Report'),
  failOnSecrets: bool(env.AS_FAIL_ON_SECRETS, true),
  failOnHigh: bool(env.AS_FAIL_ON_HIGH, false),
  failOnCritical: bool(env.AS_FAIL_ON_CRITICAL, true),
  failOnLicense: bool(env.AS_FAIL_ON_LICENSE, false),
  failOnToolError: bool(env.AS_FAIL_ON_TOOL_ERROR, false),
  enableSecrets: bool(env.AS_ENABLE_SECRETS, true),
  enableDeps: bool(env.AS_ENABLE_DEPENDENCIES, true),
  enableSemgrep: bool(env.AS_ENABLE_SEMGREP, true),
  enableCodeql: bool(env.AS_ENABLE_CODEQL, true),
  enableDocker: bool(env.AS_ENABLE_DOCKER, true),
  enableLicense: bool(env.AS_ENABLE_LICENSE, true),
  enableSbom: bool(env.AS_ENABLE_SBOM, true),
  enableRepo: bool(env.AS_ENABLE_REPO, true),
  semgrepThreshold: str(env.AS_SEMGREP_SEVERITY_THRESHOLD, 'warning').toLowerCase(),
  sbomFormat: str(env.AS_SBOM_FORMAT, 'cyclonedx'),
};

const WEIGHTS = {
  secrets: 25,
  dependencies: 20,
  code: 15,
  codeql: 15,
  docker: 10,
  licenses: 10,
  repo: 5,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function readMeta() {
  const meta = readJson(path.join(RESULTS, 'meta.json'));
  return meta || {};
}

function glob(dir, pattern) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...glob(full, pattern));
    } else if (e.name.endsWith(pattern)) {
      out.push(full);
    }
  }
  return out;
}

const statusRank = { error: 3, warning: 2, info: 1 };

function lockfileEcosystem(file) {
  const base = String(file).split(/[\\/]/).pop();
  if (/package-lock\.json|npm-shrinkwrap\.json/.test(base)) return 'npm';
  if (/pnpm-lock\.yaml/.test(base)) return 'pnpm';
  if (/yarn\.lock/.test(base)) return 'yarn';
  if (/bun\.lock|bun\.lockb/.test(base)) return 'bun';
  if (/requirements/.test(base) || /pyproject\.toml/.test(base) || /Pipfile|poetry\.lock/.test(base) || /uv\.lock/.test(base)) return 'pip';
  if (/Cargo\.lock/.test(base)) return 'cargo';
  if (/go\.sum|go\.mod|Gopkg\.lock/.test(base)) return 'go';
  if (/Gemfile\.lock/.test(base)) return 'rubygems';
  if (/composer\.lock/.test(base)) return 'composer';
  if (/mix\.lock/.test(base)) return 'hex';
  return base || 'unknown';
}

// ---------------------------------------------------------------------------
// Check evaluators
// ---------------------------------------------------------------------------

function evaluateSecrets(meta) {
  const check = { weight: WEIGHTS.secrets, findings: [] };
  if (!cfg.enableSecrets) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.secrets_error) return { ...check, status: 'error', error: meta.secrets_error };
  const data = readJson(path.join(RESULTS, 'secrets.json'));
  if (!Array.isArray(data)) return { ...check, status: 'error', error: 'No Gitleaks results' };
  check.findings = data.map((f) => ({
    rule: f.RuleID || 'unknown',
    description: f.Description || '',
    secret: f.Match ? String(f.Match).slice(0, 40) : '',
    file: f.File || '',
    line: f.StartLine || f.Line || 0,
    commit: f.Commit ? f.Commit.slice(0, 12) : '',
  }));
  check.count = check.findings.length;
  check.status = check.count > 0 ? 'fail' : 'pass';
  return check;
}

function osvSeverity(vuln) {
  const db = vuln.database_specific || {};
  const s = String(db.severity || '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE') return 'medium';
  if (s === 'LOW') return 'low';
  return 'unknown';
}

function evaluateDependencies(meta) {
  const check = { weight: WEIGHTS.dependencies, findings: [], counts: {} };
  if (!cfg.enableDeps) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.dependencies_skipped) return { ...check, status: 'skipped', skipped: meta.dependencies_skipped };
  if (meta.dependencies_error) return { ...check, status: 'error', error: meta.dependencies_error };
  const data = readJson(path.join(RESULTS, 'deps.json'));
  if (!data) return { ...check, status: 'error', error: 'No OSV-Scanner results' };

  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const seen = new Set();
  for (const result of data.results || []) {
    const ecosystem = lockfileEcosystem((result.source && result.source.path) || '');
    for (const pkg of result.packages || []) {
      const name = pkg.package && pkg.package.name;
      const version = pkg.package && pkg.package.version;
      for (const vuln of pkg.vulnerabilities || []) {
        const sev = osvSeverity(vuln);
        counts[sev] = (counts[sev] || 0) + 1;
        const key = `${vuln.id}::${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        check.findings.push({
          id: vuln.id || '',
          ecosystem,
          name: name || '',
          version: version || '',
          severity: sev,
          aliases: (vuln.aliases || []).slice(0, 5),
        });
      }
    }
  }
  check.counts = counts;
  check.count = check.findings.length;
  const critical = counts.critical || 0;
  const high = counts.high || 0;
  if (check.count === 0) check.status = 'pass';
  else if (critical + high === 0) check.status = 'warning';
  else check.status = 'fail';
  return check;
}

function semgrepSeverity(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'ERROR') return 'error';
  if (s === 'WARNING') return 'warning';
  return 'info';
}

function evaluateCode(meta) {
  const check = { weight: WEIGHTS.code, findings: [] };
  if (!cfg.enableSemgrep) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.code_error) return { ...check, status: 'error', error: meta.code_error };
  const data = readJson(path.join(RESULTS, 'semgrep.json'));
  if (!data) return { ...check, status: 'error', error: 'No Semgrep results' };

  check.findings = (data.results || []).map((r) => {
    const extra = r.extra || {};
    return {
      rule: r.check_id || '',
      severity: semgrepSeverity(extra.severity),
      message: String(extra.message || '').split('\n')[0].slice(0, 300),
      file: r.path || '',
      line: r.start ? r.start.line : 0,
    };
  });
  check.count = check.findings.length;

  const hasErrors = Array.isArray(data.errors) && data.errors.length > 0;
  if (check.count === 0 && hasErrors) {
    return { ...check, status: 'error', error: 'Semgrep reported execution errors' };
  }
  if (check.count === 0) {
    check.status = 'pass';
    return check;
  }

  const threshold = statusRank[cfg.semgrepThreshold] || statusRank.warning;
  let maxRank = 0;
  for (const f of check.findings) maxRank = Math.max(maxRank, statusRank[f.severity] || 1);
  check.status = maxRank >= threshold ? 'fail' : 'warning';
  return check;
}

function evaluateCodeql() {
  const check = { weight: WEIGHTS.codeql, findings: [] };
  if (!cfg.enableCodeql) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };

  const initOutcome = str(env.AS_CODEQL_INIT_OUTCOME, 'skipped');
  const analyzeOutcome = str(env.AS_CODEQL_ANALYZE_OUTCOME, 'skipped');
  const files = glob(CODEQL_DIR, '.sarif');

  if (files.length === 0) {
    if (initOutcome === 'failure' || initOutcome === 'error') {
      return { ...check, status: 'error', error: 'CodeQL initialization failed' };
    }
    if (initOutcome === 'success' && analyzeOutcome === 'success') {
      return { ...check, status: 'pass' };
    }
    return { ...check, status: 'error', error: 'CodeQL produced no results' };
  }

  const counts = { error: 0, warning: 0, note: 0 };
  for (const file of files) {
    const sarif = readJson(file);
    if (!sarif) continue;
    for (const run of sarif.runs || []) {
      for (const result of run.results || []) {
        const level = String(result.level || 'none').toLowerCase();
        if (counts[level] !== undefined) counts[level] += 1;
        const loc = result.locations && result.locations[0] && result.locations[0].physicalLocation;
        const uri = loc && loc.artifactLocation && loc.artifactLocation.uri;
        const region = loc && loc.region && loc.region.startLine;
        check.findings.push({
          rule: result.ruleId || '',
          level,
          message: (result.message && result.message.text) || '',
          file: uri ? decodeURIComponent(uri.replace(/^file:\/\//, '')) : '',
          line: region || 0,
        });
      }
    }
  }
  check.counts = counts;
  check.count = check.findings.length;
  if (counts.error > 0) check.status = 'fail';
  else if (counts.warning > 0) check.status = 'warning';
  else check.status = 'pass';
  return check;
}

function trivySeverity(sev) {
  const s = String(sev || '').toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s)) return s.toLowerCase();
  return 'unknown';
}

function evaluateDocker(meta) {
  const check = { weight: WEIGHTS.docker, findings: [] };
  if (!cfg.enableDocker) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.docker_skipped) return { ...check, status: 'skipped', skipped: meta.docker_skipped };
  if (meta.docker_error) return { ...check, status: 'error', error: meta.docker_error };

  const sources = [
    ['trivy-fs.json', 'filesystem'],
    ['trivy-config.json', 'config'],
    ['trivy-image.json', 'image'],
  ];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const [file, kind] of sources) {
    const data = readJson(path.join(RESULTS, file));
    if (!data) continue;
    for (const res of data.Results || []) {
      const target = res.Target || '';
      for (const v of res.Vulnerabilities || []) {
        const sev = trivySeverity(v.Severity);
        counts[sev] += 1;
        check.findings.push({
          kind,
          type: 'vulnerability',
          severity: sev,
          target,
          id: v.VulnerabilityID || '',
          pkg: v.PkgName || '',
          installed: v.InstalledVersion || '',
          fixed: v.FixedVersion || '',
        });
      }
      for (const v of res.Secrets || []) {
        counts.high += 1;
        check.findings.push({ kind, type: 'secret', severity: 'high', target, id: v.RuleID || 'SECRET' });
      }
      for (const m of res.Misconfigurations || []) {
        const sev = trivySeverity(m.Severity);
        counts[sev] += 1;
        check.findings.push({ kind, type: 'misconfiguration', severity: sev, target, id: m.ID || '', message: m.Message || '' });
      }
    }
  }
  check.counts = counts;
  check.count = check.findings.length;
  const critical = counts.critical || 0;
  const high = counts.high || 0;
  const medLow = (counts.medium || 0) + (counts.low || 0);
  if (check.count === 0) check.status = 'pass';
  else if (critical + high > 0) check.status = 'fail';
  else if (medLow > 0) check.status = 'warning';
  else check.status = 'pass';
  return check;
}

function evaluateLicenses(meta) {
  const check = { weight: WEIGHTS.licenses, findings: [] };
  if (!cfg.enableLicense) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.licenses_error) return { ...check, status: 'error', error: meta.licenses_error };
  const data = readJson(path.join(RESULTS, 'licenses.json'));
  if (!data) return { ...check, status: 'skipped', skipped: 'No license data available' };

  check.findings = (data.gpl_packages || []).map((p) => ({
    name: p.name || '',
    version: p.version || '',
    ecosystem: p.ecosystem || '',
    licenses: (p.licenses || []).join(', '),
  }));
  check.count = check.findings.length;
  if (check.count === 0) check.status = 'pass';
  else if (cfg.failOnLicense) check.status = 'fail';
  else check.status = 'warning';
  return check;
}

function evaluateRepo() {
  const check = { weight: WEIGHTS.repo, findings: [] };
  if (!cfg.enableRepo) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  const data = readJson(path.join(RESULTS, 'repo.json'));
  if (!data) return { ...check, status: 'skipped', skipped: 'No repository data available' };
  check.findings = (data.items || []).map((i) => ({
    key: i.key || '',
    label: i.label || i.key || '',
    ok: !!i.ok,
    detail: i.detail || '',
  }));
  const ok = check.findings.filter((f) => f.ok).length;
  check.counts = { ok, total: check.findings.length };
  if (check.findings.length === 0) check.status = 'skipped';
  else if (ok === check.findings.length) check.status = 'pass';
  else if (ok === 0) check.status = 'fail';
  else check.status = 'warning';
  return check;
}

function evaluateSbom(meta) {
  const check = { weight: 0, findings: [] };
  if (!cfg.enableSbom) return { ...check, status: 'skipped', skipped: 'Disabled by configuration' };
  if (meta.sbom_error) return { ...check, status: 'error', error: meta.sbom_error };
  const files = fs.existsSync(SBOM_DIR)
    ? fs.readdirSync(SBOM_DIR).filter((f) => f.endsWith('.json'))
    : [];
  check.files = files;
  check.count = files.length;
  check.status = check.count > 0 ? 'pass' : 'skipped';
  return check;
}

// ---------------------------------------------------------------------------
// SARIF merging
// ---------------------------------------------------------------------------

function mergeSarif() {
  const files = [
    ...glob(SARIF_DIR, '.sarif'),
    ...glob(CODEQL_DIR, '.sarif'),
  ];
  const runs = [];
  for (const file of files) {
    const sarif = readJson(file);
    if (!sarif || !Array.isArray(sarif.runs)) continue;
    for (const run of sarif.runs) runs.push(run);
  }
  const merged = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs,
  };
  fs.writeFileSync(path.join(ARTIFACTS, 'security.sarif'), JSON.stringify(merged, null, 2));
  return runs.length;
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

const BADGE = {
  pass: '✅ PASS',
  warning: '⚠️ WARNING',
  fail: '❌ FAIL',
  skipped: '⏭️ SKIPPED',
  error: '❔ ERROR',
};

function mdEsc(s) {
  return String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function scoreFor(check) {
  if (check.status === 'pass') return check.weight;
  if (check.status === 'warning') return Math.round(check.weight * 0.6);
  return 0;
}

function renderFindingsMd(title, check, columns) {
  const lines = [`### ${title}`];
  if (check.status === 'skipped') {
    lines.push(`\n_${mdEsc(check.skipped || 'Not applicable')}_\n`);
    return lines.join('\n');
  }
  if (check.status === 'error') {
    lines.push(`\n_Error: ${mdEsc(check.error || 'tool error')}_\n`);
    return lines.join('\n');
  }
  if (!check.count || check.count === 0) {
    lines.push('\n_No findings._\n');
    return lines.join('\n');
  }
  const header = columns.map((c) => c.label).join(' | ');
  const sep = columns.map(() => '---').join(' | ');
  lines.push(`\n| ${header} |`);
  lines.push(`| ${sep} |`);
  for (const f of check.findings.slice(0, 25)) {
    const cells = columns.map((c) => mdEsc(c.value(f)));
    lines.push(`| ${cells.join(' | ')} |`);
  }
  if (check.findings.length > 25) lines.push(`\n_...and ${check.findings.length - 25} more._`);
  lines.push('');
  return lines.join('\n');
}

function renderReportMd(report) {
  const c = report.checks;
  const rows = [
    `# ${cfg.title}`,
    '',
    `**Repository:** \`${cfg.repo}\` · **Commit:** \`${(cfg.sha || '').slice(0, 12)}\` · **Event:** ${cfg.event}`,
    '',
    `## Overall Score: **${report.score}/100** — ${BADGE[report.status]}`,
    '',
    '## Checks',
    '',
    '| Check | Result | Score |',
    '| --- | --- | --- |',
  ];
  for (const key of Object.keys(WEIGHTS)) {
    const ch = c[key];
    if (!ch) continue;
    rows.push(`| ${ch.label} | ${BADGE[ch.status]} | ${scoreFor(ch)}/${ch.weight} |`);
  }
  rows.push('');
  rows.push(renderFindingsMd('Secrets', c.secrets, [
    { label: 'Rule', value: (f) => f.rule },
    { label: 'Description', value: (f) => f.description },
    { label: 'File', value: (f) => `${f.file}:${f.line}` },
  ]));
  rows.push(renderFindingsMd('Dependencies', c.dependencies, [
    { label: 'Severity', value: (f) => f.severity },
    { label: 'ID', value: (f) => f.id },
    { label: 'Package', value: (f) => `${f.name}@${f.version}` },
    { label: 'Source', value: (f) => f.ecosystem },
  ]));
  rows.push(renderFindingsMd('Static Analysis (Semgrep)', c.code, [
    { label: 'Severity', value: (f) => f.severity },
    { label: 'Rule', value: (f) => f.rule },
    { label: 'File', value: (f) => `${f.file}:${f.line}` },
    { label: 'Message', value: (f) => f.message },
  ]));
  rows.push(renderFindingsMd('CodeQL', c.codeql, [
    { label: 'Level', value: (f) => f.level },
    { label: 'Rule', value: (f) => f.rule },
    { label: 'File', value: (f) => `${f.file}:${f.line}` },
    { label: 'Message', value: (f) => f.message },
  ]));
  rows.push(renderFindingsMd('Docker (Trivy)', c.docker, [
    { label: 'Type', value: (f) => f.type },
    { label: 'Severity', value: (f) => f.severity },
    { label: 'ID', value: (f) => f.id },
    { label: 'Target', value: (f) => f.target },
  ]));
  rows.push(renderFindingsMd('Licenses', c.licenses, [
    { label: 'Package', value: (f) => `${f.name}@${f.version}` },
    { label: 'License', value: (f) => f.licenses },
    { label: 'Ecosystem', value: (f) => f.ecosystem },
  ]));
  rows.push('### Repository Security');
  rows.push('');
  if (c.repo.findings && c.repo.findings.length) {
    rows.push('| Check | Status | Detail |');
    rows.push('| --- | --- | --- |');
    for (const f of c.repo.findings) {
      rows.push(`| ${mdEsc(f.label)} | ${f.ok ? '✅' : '❌'} | ${mdEsc(f.detail)} |`);
    }
  } else {
    rows.push('_No repository data._');
  }
  rows.push('');
  rows.push('### SBOM');
  rows.push('');
  rows.push(c.sbom.count ? `_Generated: ${c.sbom.files.join(', ')}_` : '_Not generated._');
  rows.push('');
  rows.push('---');
  rows.push(`<sub>Generated by [AragSoft Security](https://github.com/amixiid/security-checker-workflow) v${cfg.version} · Score ${report.score}/100</sub>`);
  rows.push('<!-- aragsoft-security-report -->');
  rows.push('');
  return rows.join('\n');
}

function renderSummaryMd(report) {
  const c = report.checks;
  const lines = [
    '## 🛡️ AragSoft Security',
    '',
    `**Repository:** \`${cfg.repo}\` · **Commit:** \`${(cfg.sha || '').slice(0, 12)}\``,
    '',
    `> **Overall Score: ${report.score}/100** — ${BADGE[report.status]}`,
    '',
    '| Check | Result |',
    '| --- | --- |',
  ];
  for (const key of Object.keys(WEIGHTS)) {
    const ch = c[key];
    if (ch) lines.push(`| ${ch.label} | ${BADGE[ch.status]} |`);
  }
  const counts = [];
  const cq = report.checks;
  if (cq.secrets.count) counts.push(`${cq.secrets.count} secret(s)`);
  if (cq.dependencies.count) counts.push(`${cq.dependencies.count} vulnerable dependency instance(s)`);
  if (cq.code.count) counts.push(`${cq.code.count} static finding(s)`);
  if (cq.codeql.count) counts.push(`${cq.codeql.count} CodeQL finding(s)`);
  if (cq.docker.count) counts.push(`${cq.docker.count} Docker finding(s)`);
  if (cq.licenses.count) counts.push(`${cq.licenses.count} GPL package(s)`);
  if (counts.length) lines.push('', '**Summary:** ' + counts.join(' · '));
  lines.push('', '<details>', '<summary>Full report</summary>', '', renderReportMd(report), '</details>');
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderHtml(report) {
  const c = report.checks;
  const badgeClass = { pass: 'ok', warning: 'warn', fail: 'bad', skipped: 'skip', error: 'err' };
  const rows = Object.keys(WEIGHTS)
    .map((key) => {
      const ch = c[key];
      return `<tr class="row-${ch.status}">
        <td class="label">${esc(ch.label)}</td>
        <td><span class="badge badge-${badgeClass[ch.status]}">${BADGE[ch.status]}</span></td>
        <td class="score-cell">${scoreFor(ch)}/${ch.weight}</td>
      </tr>`;
    })
    .join('\n');

  const findingBlocks = ['secrets', 'dependencies', 'code', 'codeql', 'docker', 'licenses']
    .map((key) => {
      const ch = c[key];
      let body;
      if (ch.status === 'skipped') body = `<p class="muted">${esc(ch.skipped || 'Not applicable')}</p>`;
      else if (ch.status === 'error') body = `<p class="muted">Error: ${esc(ch.error || 'tool error')}</p>`;
      else if (!ch.count) body = '<p class="muted">No findings.</p>';
      else {
        const head = key === 'secrets'
          ? ['Rule', 'Description', 'File']
          : key === 'dependencies'
            ? ['Severity', 'ID', 'Package', 'Source']
            : key === 'code'
              ? ['Severity', 'Rule', 'File', 'Message']
              : key === 'codeql'
                ? ['Level', 'Rule', 'File', 'Message']
                : key === 'docker'
                  ? ['Type', 'Severity', 'ID', 'Target']
                  : ['Package', 'License', 'Ecosystem'];
        const rowsHtml = ch.findings.slice(0, 25).map((f) => {
          const cols = head.map((h) => {
            let v = '';
            switch (h) {
              case 'Rule': v = f.rule; break;
              case 'Description': v = f.description; break;
              case 'Severity': case 'Level': v = f.severity || f.level; break;
              case 'ID': v = f.id; break;
              case 'Package': v = key === 'dependencies' ? `${f.name}@${f.version}` : `${f.name}@${f.version}`; break;
              case 'Source': v = f.ecosystem; break;
              case 'File': v = `${f.file}:${f.line}`; break;
              case 'Message': v = f.message; break;
              case 'Type': v = f.type; break;
              case 'Target': v = f.target; break;
              case 'License': v = f.licenses; break;
              case 'Ecosystem': v = f.ecosystem; break;
              default: v = '';
            }
            return `<td>${esc(v)}</td>`;
          });
          return `<tr>${cols.join('')}</tr>`;
        }).join('\n');
        body = `<table><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rowsHtml}</tbody></table>`;
        if (ch.findings.length > 25) body += `<p class="muted">...and ${ch.findings.length - 25} more.</p>`;
      }
      return `<section><h3>${c[key].label}</h3>${body}</section>`;
    })
    .join('\n');

  const repoRows = (c.repo.findings || []).map((f) =>
    `<tr><td>${f.ok ? '✅' : '❌'}</td><td>${esc(f.label)}</td><td class="muted">${esc(f.detail)}</td></tr>`,
  ).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(cfg.title)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #f6f8fa; color: #1f2328; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
  header { text-align: center; padding: 24px 0 8px; }
  header h1 { font-size: 28px; margin: 0 0 4px; }
  header .sub { color: #57606a; }
  .gauge { width: 160px; height: 160px; border-radius: 50%; margin: 24px auto; display: flex; align-items: center; justify-content: center; flex-direction: column; border: 12px solid #d0d7de; position: relative; }
  .gauge .num { font-size: 40px; font-weight: 700; }
  .gauge .den { font-size: 14px; color: #57606a; }
  .gauge.ok { border-color: #1a7f37; } .gauge.warn { border-color: #9a6700; } .gauge.bad { border-color: #cf222e; }
  .status-line { text-align: center; font-size: 18px; margin: 8px 0 24px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; margin: 12px 0; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #d0d7de; font-size: 14px; }
  th { background: #f0f2f4; font-weight: 600; }
  td.label { font-weight: 600; }
  .badge { padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge-ok { background: #dafbe1; color: #1a7f37; }
  .badge-warn { background: #fff8c5; color: #9a6700; }
  .badge-bad { background: #ffebe9; color: #cf222e; }
  .badge-skip { background: #eaeef2; color: #57606a; }
  .badge-err { background: #eaeef2; color: #57606a; }
  section { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 8px 16px 16px; margin: 20px 0; }
  section h3 { margin: 14px 0 6px; }
  .muted { color: #57606a; }
  footer { text-align: center; color: #57606a; font-size: 13px; margin-top: 32px; }
  @media (prefers-color-scheme: dark) { body { background: #0d1117; color: #e6edf3; } section, table { background: #161b22; } th { background: #21262d; } th, td { border-color: #30363d; } .sub, .muted, footer { color: #8b949e; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🛡️ ${esc(cfg.title)}</h1>
    <div class="sub">${esc(cfg.repo)} · ${esc((cfg.sha || '').slice(0, 12))} · ${esc(cfg.event)}</div>
  </header>
  <div class="gauge ${report.status}">
    <div class="num">${report.score}</div>
    <div class="den">/ 100</div>
  </div>
  <div class="status-line"><span class="badge badge-${badgeClass[report.status]}">${BADGE[report.status]}</span></div>
  <h2>Checks</h2>
  <table>
    <thead><tr><th>Check</th><th>Result</th><th>Score</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>
  <h2>Findings</h2>
${findingBlocks}
  <h2>Repository Security</h2>
  <table>
    <thead><tr><th>Status</th><th>Check</th><th>Detail</th></tr></thead>
    <tbody>
${repoRows || '<tr><td colspan="3" class="muted">No repository data.</td></tr>'}
    </tbody>
  </table>
  <footer>Generated by <a href="https://github.com/amixiid/security-checker-workflow">AragSoft Security</a> v${esc(cfg.version)} · ${esc(cfg.runId)}</footer>
</div>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const meta = readMeta();
  const checks = {
    secrets: { ...evaluateSecrets(meta), label: 'Secret Scanning (Gitleaks)' },
    dependencies: { ...evaluateDependencies(meta), label: 'Dependency Vulnerabilities' },
    code: { ...evaluateCode(meta), label: 'Static Analysis (Semgrep)' },
    codeql: { ...evaluateCodeql(), label: 'CodeQL' },
    docker: { ...evaluateDocker(meta), label: 'Docker Security (Trivy)' },
    licenses: { ...evaluateLicenses(meta), label: 'License Compliance' },
    repo: { ...evaluateRepo(), label: 'Repository Security' },
    sbom: { ...evaluateSbom(meta), label: 'SBOM (Syft)' },
  };

  // Score
  let totalWeight = 0;
  let contribution = 0;
  for (const key of Object.keys(WEIGHTS)) {
    const ch = checks[key];
    if (['pass', 'warning', 'fail'].includes(ch.status)) {
      totalWeight += ch.weight;
      contribution += scoreFor(ch);
    }
  }
  const score = totalWeight > 0 ? Math.round((100 * contribution) / totalWeight) : 0;

  // Overall status
  const statuses = Object.keys(WEIGHTS).map((k) => checks[k].status);
  let status = 'pass';
  if (statuses.includes('fail')) status = 'fail';
  else if (statuses.includes('warning')) status = 'warning';
  else if (statuses.includes('error')) status = 'error';

  // Failure gates
  let exitCode = 0;
  const reasons = [];
  if (checks.secrets.status === 'fail' && cfg.failOnSecrets) {
    exitCode = 1;
    reasons.push('secrets');
  }
  const crit = checks.dependencies.counts && checks.dependencies.counts.critical;
  const high = checks.dependencies.counts && checks.dependencies.counts.high;
  if ((crit || 0) > 0 && cfg.failOnCritical) {
    exitCode = 1;
    reasons.push('critical vulnerabilities');
  }
  if ((high || 0) > 0 && cfg.failOnHigh) {
    exitCode = 1;
    reasons.push('high vulnerabilities');
  }
  if (checks.licenses.status === 'fail' && cfg.failOnLicense) {
    exitCode = 1;
    reasons.push('restrictive licenses');
  }
  if (cfg.failOnToolError && Object.values(checks).some((ch) => ch.status === 'error')) {
    exitCode = 1;
    reasons.push('tool errors');
  }

  const report = {
    version: cfg.version,
    repository: cfg.repo,
    sha: cfg.sha,
    ref: cfg.ref,
    default_branch: cfg.defaultBranch,
    event: cfg.event,
    run_id: cfg.runId,
    os: cfg.os,
    arch: cfg.arch,
    generated_at: new Date().toISOString(),
    score,
    status,
    exit_code: exitCode,
    failure_reasons: reasons,
    config: {
      fail_on_secrets: cfg.failOnSecrets,
      fail_on_high: cfg.failOnHigh,
      fail_on_critical: cfg.failOnCritical,
      fail_on_license: cfg.failOnLicense,
      fail_on_tool_error: cfg.failOnToolError,
    },
    checks,
  };

  fs.mkdirSync(ARTIFACTS, { recursive: true });
  fs.writeFileSync(path.join(ARTIFACTS, 'report.json'), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(ARTIFACTS, 'report.md'), renderReportMd(report));
  fs.writeFileSync(path.join(ARTIFACTS, 'summary.md'), renderSummaryMd(report));
  fs.writeFileSync(path.join(ARTIFACTS, 'report.html'), renderHtml(report));
  const sarifRuns = mergeSarif();

  // Emit environment for finalize.sh
  const emit = [
    `export AS_SCORE=${score}`,
    `export AS_STATUS=${status}`,
    `export AS_EXIT_CODE=${exitCode}`,
    'export AS_SECRETS=' + checks.secrets.status,
    'export AS_DEPENDENCIES=' + checks.dependencies.status,
    'export AS_CODE=' + checks.code.status,
    'export AS_CODEQL=' + checks.codeql.status,
    'export AS_DOCKER=' + checks.docker.status,
    'export AS_LICENSES=' + checks.licenses.status,
    'export AS_REPO=' + checks.repo.status,
    'export AS_SBOM=' + checks.sbom.status,
    `export AS_SECRETS_COUNT=${checks.secrets.count || 0}`,
    `export AS_DEPENDENCIES_COUNT=${checks.dependencies.count || 0}`,
    `export AS_DEPENDENCIES_CRITICAL=${checks.dependencies.counts && checks.dependencies.counts.critical || 0}`,
    `export AS_DEPENDENCIES_HIGH=${checks.dependencies.counts && checks.dependencies.counts.high || 0}`,
    `export AS_CODE_COUNT=${checks.code.count || 0}`,
    `export AS_CODEQL_COUNT=${checks.codeql.count || 0}`,
    `export AS_DOCKER_COUNT=${checks.docker.count || 0}`,
    `export AS_LICENSES_COUNT=${checks.licenses.count || 0}`,
    `export AS_REPO_OK=${checks.repo.counts && checks.repo.counts.ok || 0}`,
    `export AS_REPO_TOTAL=${checks.repo.counts && checks.repo.counts.total || 0}`,
    `export AS_SARIF_RUNS=${sarifRuns}`,
  ];
  process.stdout.write(emit.join('\n') + '\n');
}

main();
