'use strict';

// Mechanical validation of findings (deterministic, no AI):
//   1. Schema conformance (ajv or built-in fallback).
//   2. Evidence plausibility: every cited file exists in the target repo and
//      cited line ranges fall inside the file's real length.
//   3. Duplicate detection within the run (same category + overlapping file
//      and line overlap) -- candidates for merging by the validator agent.
//   4. Policy checks: confirmed findings must carry severity_reasoning and a
//      rejected-attempt log in validation; secrets must not appear verbatim.
//
// Exit codes: 0 = all findings mechanically valid, 1 = validation failures.

const fs = require('fs');
const path = require('path');
const { validate, validateFindings } = require('../lib/schema-validator');
const { verifyLocation, walkFiles, toRel, redactString, REDACTED } = require('../lib/util');

function loadJsonFile(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    throw new Error(`Cannot parse ${p}: ${e.message}`);
  }
}

// Extract a plausible set of repo-relative file paths from free text so we
// can catch evidence that cites files that do not exist.
function extractPaths(text) {
  const out = new Set();
  const re = /(?:[\w.-]+\/)*[\w.-]+\.(?:js|mjs|cjs|ts|tsx|jsx|py|rb|go|rs|java|kt|php|cs|c|cpp|h|hpp|sql|env|ya?ml|json|toml|md|sh|tf|hcl|conf|ini|properties|html|css|vue|svelte|proto)/g;
  const matches = text.match(re) || [];
  for (const m of matches) out.add(m);
  return [...out];
}

function mechanicalChecks(finding, root, fileList) {
  const problems = [];
  const warnings = [];
  const fileSet = fileList instanceof Set ? fileList : new Set(fileList);

  // 1. Evidence files must exist; cited lines must be in range.
  const cited = new Set();
  for (const af of finding.affected_files || []) {
    if (af && af.path) cited.add(af.path);
  }
  for (const ev of finding.evidence || []) {
    if (ev && ev.file) cited.add(ev.file);
  }
  for (const p of extractPaths(JSON.stringify({ e: finding.evidence, r: finding.reproduction, i: finding.impact }))) {
    if (p.includes('/')) cited.add(p);
  }

  for (const rel of cited) {
    if (!fileSet.has(rel)) {
      // tolerate paths cited only in prose if they are also affected_files
      const inAffected = (finding.affected_files || []).some((af) => af.path === rel);
      if (!inAffected) {
        warnings.push(`evidence mentions file not in repo: ${rel}`);
        continue;
      }
      problems.push(`affected file does not exist: ${rel}`);
    }
  }

  for (const af of finding.affected_files || []) {
    const v = verifyLocation(root, af.path, af.lines);
    if (!v.exists) {
      problems.push(`affected file does not exist: ${af.path}`);
      continue;
    }
    if (v.lineCount > 0 && v.linesInRange === 0) {
      problems.push(`line range ${af.lines} out of bounds for ${af.path} (${v.lineCount} lines)`);
    }
    // If a symbol is claimed, check it appears near the cited lines.
    if (af.symbol) {
      const abs = path.resolve(root, af.path);
      try {
        const content = fs.readFileSync(abs, 'utf8');
        const lines = content.split('\n');
        const m = /^(\d+)(?:-(\d+))?$/.exec(af.lines || '');
        if (m) {
          const start = Math.max(0, parseInt(m[1], 10) - 2);
          const end = Math.min(lines.length, (m[2] ? parseInt(m[2], 10) : parseInt(m[1], 10)) + 2);
          const window = lines.slice(start, end).join('\n');
          if (!window.includes(af.symbol)) {
            warnings.push(`symbol "${af.symbol}" not found within ±2 lines of ${af.path}:${af.lines}`);
          }
        }
      } catch (_e) {
        warnings.push(`could not read ${af.path} for symbol check`);
      }
    }
  }

  // 2. Confirmed findings need severity reasoning and a rejection log.
  if (finding.status === 'confirmed') {
    if (!finding.severity_reasoning || String(finding.severity_reasoning).trim().length < 20) {
      problems.push('confirmed findings must include severity_reasoning (min 20 chars)');
    }
    const attempts = finding.validation && finding.validation.attempted_rejections;
    if (!attempts || !Array.isArray(attempts) || attempts.length === 0) {
      problems.push('confirmed findings must list validation.attempted_rejections');
    }
  }

  // 3. Secret leakage: redact every raw string value in the finding. If
  //    redaction masks NEW material, the hunter left secret-like text in
  //    findings.json. (Reports re-redact as defense in depth, but the JSON
  //    itself must be clean.) Values the hunter already redacted contain the
  //    marker before and after, so they produce no warning. We walk the
  //    object's string values instead of the JSON serialization because
  //    JSON-escaped quotes (\") would hide key="value" patterns.
  const strings = [];
  (function collectStrings(node) {
    if (typeof node === 'string') strings.push(node);
    else if (Array.isArray(node)) node.forEach(collectStrings);
    else if (node && typeof node === 'object') Object.values(node).forEach(collectStrings);
  })(finding);
  const markerCount = (s) => s.split(REDACTED).length - 1;
  const before = strings.reduce((n, s) => n + markerCount(s), 0);
  const after = strings.reduce((n, s) => n + markerCount(redactString(s)), 0);
  const newlyMasked = after - before;
  if (newlyMasked > 0) {
    warnings.push(`${newlyMasked} string segment(s) contain secret-like material -- redact evidence quotes in findings.json`);
  }

  return { problems, warnings };
}

function validateAllFindings(findingsPath, targetRoot, options) {
  const opts = options || {};
  const doc = loadJsonFile(findingsPath);
  const list = Array.isArray(doc) ? doc : doc.findings;
  if (!Array.isArray(list)) throw new Error('findings file must be an array or { findings: [...] }');

  const fileList = walkFiles(targetRoot).map((f) => toRel(targetRoot, f));
  const fileSet = new Set(fileList);

  const schemaResults = validateFindings(list);
  const results = [];
  for (let i = 0; i < list.length; i++) {
    const f = list[i];
    const { problems, warnings } = mechanicalChecks(f, targetRoot, fileSet);
    const schemaResult = schemaResults[i] || { valid: false, errors: [{ message: 'schema result missing' }] };
    results.push({
      id: f.id || `(item ${i})`,
      schema_valid: schemaResult.valid,
      schema_errors: schemaResult.errors,
      schema_mode: schemaResult.mode,
      problems,
      warnings,
      ok: schemaResult.valid && problems.length === 0,
    });
  }

  // Cross-finding duplicate candidates
  const dupes = [];
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const a = list[i];
      const b = list[j];
      if (!a || !b || a.category !== b.category) continue;
      const aF = (a.affected_files || [])[0];
      const bF = (b.affected_files || [])[0];
      if (!aF || !bF || aF.path !== bF.path) continue;
      const overlap = rangesOverlap(aF.lines, bF.lines);
      if (overlap) {
        dupes.push({ a: a.id, b: b.id, file: aF.path, reason: `same category and overlapping lines (${overlap})` });
      }
    }
  }

  // Coverage leakage across the whole file
  const raw = fs.readFileSync(findingsPath, 'utf8');
  const leaked = raw.includes('-----BEGIN') && !raw.includes(REDACTED);

  return {
    file: findingsPath,
    finding_count: list.length,
    all_valid: results.every((r) => r.ok),
    results,
    duplicate_candidates: dupes,
    possible_pem_leak: leaked,
    warnings_count: results.reduce((n, r) => n + r.warnings.length, 0),
  };
}

function rangesOverlap(a, b) {
  const pa = /^(\d+)(?:-(\d+))?$/.exec(a || '');
  const pb = /^(\d+)(?:-(\d+))?$/.exec(b || '');
  if (!pa || !pb) return false;
  const a1 = parseInt(pa[1], 10);
  const a2 = pa[2] ? parseInt(pa[2], 10) : a1;
  const b1 = parseInt(pb[1], 10);
  const b2 = pb[2] ? parseInt(pb[2], 10) : b1;
  return Math.max(a1, b1) <= Math.min(a2, b2);
}

module.exports = { validateAllFindings, mechanicalChecks, rangesOverlap };

// CLI entry: node scripts/validate-findings.js findings.json --target ./repo
if (require.main === module) {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  const targetIdx = args.indexOf('--target');
  const target = targetIdx >= 0 ? args[targetIdx + 1] : process.cwd();
  if (!file) {
    console.error('Usage: node scripts/validate-findings.js <findings.json> [--target <repo-root>]');
    process.exit(2);
  }
  try {
    const report = validateAllFindings(file, path.resolve(target));
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.all_valid ? 0 : 1);
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
}
