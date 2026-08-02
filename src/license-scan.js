#!/usr/bin/env node
/**
 * AragSoft Security - license scanner.
 *
 * Detects dependency licenses from:
 *   1. npm package-lock.json (v1/v2/v3)
 *   2. A Syft SPDX SBOM (covers python, go, rust, etc. when SBOM is enabled)
 *   3. pip-licenses JSON output (filtered against requirements.txt)
 *
 * Usage:
 *   node license-scan.js <workspace> <output.json> [options]
 *
 * Options:
 *   --spdx <file>              Path to an SPDX SBOM JSON file
 *   --pip-licenses <file>      Path to pip-licenses JSON output
 *   --pip-requirements <file>  Path to requirements.txt (used to filter pip results)
 */

const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const workspace = args[0];
const outputFile = args[1];

const opts = {};
for (let i = 2; i < args.length; i += 1) {
  if (args[i] === '--spdx') opts.spdx = args[i + 1];
  else if (args[i] === '--pip-licenses') opts.pipLicenses = args[i + 1];
  else if (args[i] === '--pip-requirements') opts.pipRequirements = args[i + 1];
}

const GPL_RE = /\b(AGPL|LGPL|GPL)([-. ]?\d(\.\d)?)?\b/i;

function isGpl(license) {
  return typeof license === 'string' && GPL_RE.test(license);
}

function normalize(license) {
  const value = String(license || '').trim();
  if (value === '' || value === 'NOASSERTION' || value === 'UNKNOWN') return null;
  return value;
}

function parseNpmLockfile(packages) {
  const result = [];
  const byName = {};
  for (const [key, info] of Object.entries(packages)) {
    if (!info || typeof info !== 'object' || !info.version) continue;
    const name = key === '' ? (info.name || 'root') : key;
    const licenses = [];
    let gpl = false;
    if (typeof info.license === 'string') {
      licenses.push(info.license);
      if (isGpl(info.license)) gpl = true;
    } else if (Array.isArray(info.licenses)) {
      for (const l of info.licenses) {
        const n = normalize(l);
        if (n) licenses.push(n);
        if (isGpl(l)) gpl = true;
      }
    }
    result.push({
      name,
      version: info.version,
      ecosystem: 'npm',
      licenses,
      gpl,
    });
    byName[name] = result[result.length - 1];
  }
  return result;
}

function parseSpdx(data) {
  const result = [];
  const seen = new Set();
  for (const pkg of data.packages || []) {
    const name = pkg.name || '';
    const version = pkg.versionInfo || '';
    const licRaw = pkg.licenseConcluded && pkg.licenseConcluded !== 'NOASSERTION'
      ? pkg.licenseConcluded
      : pkg.licenseDeclared;
    const key = `${name}@${version}${licRaw || ''}`;
    if (!name || seen.has(key)) continue;
    seen.add(key);
    const licenses = [];
    let gpl = false;
    const candidates = String(licRaw || '')
      .split(/[()\s]+/i)
      .filter(Boolean);
    for (const c of candidates) {
      const n = normalize(c.replace(/,+$/, ''));
      if (n) licenses.push(n);
      if (isGpl(c)) gpl = true;
    }
    result.push({
      name,
      version,
      ecosystem: data.spdxVersion ? 'spdx' : 'unknown',
      licenses,
      gpl,
    });
  }
  return result;
}

function parseRequirements(file) {
  const names = new Set();
  let content;
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    return names;
  }
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.split(/\s*#/)[0].trim();
    if (!line || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9_.\-\[\]]+)/);
    if (!m) continue;
    const name = m[1].toLowerCase().split('[')[0];
    if (name) names.add(name);
  }
  return names;
}

function parsePipLicenses(file, requirementsFile) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  const allowed = requirementsFile ? parseRequirements(requirementsFile) : null;
  return data
    .filter((p) => !allowed || allowed.has(String(p.Name || '').toLowerCase()))
    .map((p) => {
      const licenses = [];
      let gpl = false;
      const raw = String(p.License || '');
      for (const c of raw.split(';')) {
        const n = normalize(c);
        if (n) licenses.push(n);
        if (isGpl(c)) gpl = true;
      }
      return {
        name: p.Name || '',
        version: p.Version || '',
        ecosystem: 'pip',
        licenses,
        gpl,
      };
    });
}

function mergePackages(arrays) {
  const seen = new Set();
  const out = [];
  for (const arr of arrays) {
    for (const p of arr) {
      const key = `${p.ecosystem}::${p.name}@${p.version}::${p.licenses.join(',')}`;
      if (!p.name || seen.has(key)) continue;
      seen.add(key);
      out.push(p);
    }
  }
  return out;
}

function main() {
  const all = [];

  try {
    const lockfile = path.join(workspace, 'package-lock.json');
    if (fs.existsSync(lockfile)) {
      const data = JSON.parse(fs.readFileSync(lockfile, 'utf8'));
      if (data && data.packages) all.push(parseNpmLockfile(data.packages));
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[license-scan] npm lockfile parse failed: ${err.message}`);
  }

  if (opts.spdx && fs.existsSync(opts.spdx)) {
    try {
      all.push(parseSpdx(JSON.parse(fs.readFileSync(opts.spdx, 'utf8'))));
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[license-scan] SPDX parse failed: ${err.message}`);
    }
  }

  if (opts.pipLicenses) {
    all.push(parsePipLicenses(opts.pipLicenses, opts.pipRequirements));
  }

  const packages = mergePackages(all);
  const gplPackages = packages.filter((p) => p.gpl);

  const report = {
    packages,
    gpl_packages: gplPackages,
    counts: {
      packages: packages.length,
      gpl: gplPackages.length,
    },
  };
  fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
}

main();
