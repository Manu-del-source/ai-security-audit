'use strict';

// Coverage verification. Deterministic checks over coverage-ledger.json:
//   - every selected category from the plan appears exactly once
//   - statuses are legal
//   - partial/blocked entries must document gaps
//   - claims of 'complete' with zero files examined are flagged
// The final report uses this ledger to distinguish "audited, nothing found"
// from "not examined" -- that distinction is the product.

const fs = require('fs');

const LEGAL_STATUSES = ['complete', 'partial', 'not_applicable', 'blocked', 'needs_validation'];

function verifyCoverage(ledger, plan) {
  const problems = [];
  const warnings = [];

  if (!ledger || typeof ledger !== 'object') {
    return { ok: false, problems: ['coverage ledger missing or malformed'], warnings };
  }
  const cats = Array.isArray(ledger.categories) ? ledger.categories : [];

  // 1. Legal statuses
  for (const c of cats) {
    if (!c || typeof c !== 'object') {
      problems.push('malformed category entry');
      continue;
    }
    if (!c.category) problems.push('category entry missing name');
    if (!LEGAL_STATUSES.includes(c.status)) {
      problems.push(`illegal status '${c.status}' for category '${c.category}'`);
    }
  }

  // 2. Exactly-once per selected category
  const selected = (plan && plan.selected_categories) || [];
  const seen = {};
  for (const c of cats) {
    if (!c.category) continue;
    seen[c.category] = (seen[c.category] || 0) + 1;
  }
  for (const sel of selected) {
    if (!seen[sel]) problems.push(`selected category '${sel}' missing from coverage ledger`);
  }
  for (const [name, count] of Object.entries(seen)) {
    if (count > 1) problems.push(`category '${name}' appears ${count} times (must appear exactly once)`);
  }
  for (const c of cats) {
    if (c.category && selected.length && !selected.includes(c.category) && !(plan && plan.excluded_categories && plan.excluded_categories[c.category])) {
      warnings.push(`category '${c.category}' is in the ledger but was not in the plan selection`);
    }
  }

  // 3. Gap documentation
  for (const c of cats) {
    if (c.status === 'partial' || c.status === 'blocked') {
      const gaps = c.gaps || [];
      if (gaps.length === 0) {
        problems.push(`category '${c.category}' is ${c.status} but documents no gaps`);
      }
    }
    if (c.status === 'complete' && (c.files_examined || 0) === 0 && c.status !== 'not_applicable') {
      warnings.push(`category '${c.category}' marked complete with 0 files examined -- verify this is genuinely an empty area`);
    }
    if (c.status === 'not_applicable' && !c.notes) {
      warnings.push(`category '${c.category}' marked not_applicable without a reason in notes`);
    }
  }

  return { ok: problems.length === 0, problems, warnings };
}

function loadJsonSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (_e) {
    return null;
  }
}

module.exports = { verifyCoverage, LEGAL_STATUSES };

if (require.main === module) {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('Usage: node scripts/validate-coverage.js <coverage-ledger.json> [--plan audit-plan.json]');
    process.exit(2);
  }
  const ledger = loadJsonSafe(file);
  if (!ledger) {
    console.error(`Cannot parse ${file}`);
    process.exit(2);
  }
  const planIdx = args.indexOf('--plan');
  const plan = planIdx >= 0 ? loadJsonSafe(args[planIdx + 1]) : null;
  const result = verifyCoverage(ledger, plan);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}
