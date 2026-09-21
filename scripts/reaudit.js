'use strict';

// Re-audit engine: compare a previous audit's findings against a new audit of
// the same repository. A finding is only marked resolved after independent
// re-validation -- a code change alone never implies resolution.
//
// Matching is deterministic: same category + overlapping affected file/lines
// => candidate match; titles/symbols refine it. The re-audit agent performs
// the actual re-validation of each matched pair (see validation/finding-validator.md).

const fs = require('fs');
const path = require('path');
const { rangesOverlap } = require('./validate-findings');

function loadFindings(p) {
  const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
  return Array.isArray(doc) ? doc : doc.findings || [];
}

function findingsMatch(a, b) {
  if (a.category !== b.category) return false;
  const aFiles = (a.affected_files || []).map((f) => f.path);
  const bFiles = (b.affected_files || []).map((f) => f.path);
  const shared = aFiles.filter((p) => bFiles.includes(p));
  if (shared.length === 0) return false;
  for (const p of shared) {
    const aF = (a.affected_files || []).find((f) => f.path === p);
    const bF = (b.affected_files || []).find((f) => f.path === p);
    if (aF && bF && rangesOverlap(aF.lines, bF.lines)) return true;
  }
  // Same file, non-overlapping lines: treat as a match candidate if titles agree
  const titleA = (a.title || '').toLowerCase();
  const titleB = (b.title || '').toLowerCase();
  if (titleA && titleA === titleB) return true;
  return false;
}

function compareAudits(previousPath, currentPath) {
  const previous = loadFindings(previousPath).filter((f) => f.status === 'confirmed' || f.status === 'needs_validation');
  const current = loadFindings(currentPath);

  const resolved = [];
  const regressions = [];
  const unchanged = [];
  const newFindings = [];
  const matchedCurrent = new Set();

  for (const prev of previous) {
    const match = current.find((cur) => !matchedCurrent.has(cur.id) && findingsMatch(prev, cur));
    if (!match) {
      resolved.push({
        id: prev.id,
        title: prev.title,
        note: 'No matching finding in the new audit. NOT automatically resolved: re-validate against current code before closing.',
        requires_revalidation: true,
      });
      continue;
    }
    matchedCurrent.add(match.id);
    const prevSeverity = prev.severity;
    const curSeverity = match.severity;
    const entry = {
      previous_id: prev.id,
      current_id: match.id,
      title: match.title,
      severity_change: prevSeverity !== curSeverity ? `${prevSeverity} -> ${curSeverity}` : 'unchanged',
    };
    if (match.status === 'confirmed') {
      entry.relation = 'unchanged';
      entry.note = 'Still present and still confirmed. Re-validate only if the fix was claimed.';
      unchanged.push(entry);
    } else if (match.status === 'candidate' || match.status === 'needs_validation') {
      entry.relation = 'changed';
      entry.note = 'Matched area still flagged but with reduced confidence. Re-validate before resolving.';
      unchanged.push(entry);
    } else if (match.status === 'rejected') {
      entry.relation = 'resolved';
      entry.note = 'New audit actively rejected the finding (control found). Verify the fix commit before closing.';
      resolved.push(entry);
    }
  }

  for (const cur of current) {
    if (matchedCurrent.has(cur.id)) continue;
    const isConfirmed = cur.status === 'confirmed';
    newFindings.push({
      id: cur.id,
      title: cur.title,
      severity: cur.severity,
      status: cur.status,
      note: isConfirmed
        ? 'New finding not present in the previous audit.'
        : 'Candidate finding; await validation.',
    });
  }

  // Regressions: previous audit had rejected/resolved these, new audit re-confirms them.
  const previousRejected = loadFindings(previousPath).filter((f) => f.status === 'rejected');
  for (const prev of previousRejected) {
    const match = current.find((cur) => findingsMatch(prev, cur) && cur.status === 'confirmed');
    if (match) {
      regressions.push({
        previous_id: prev.id,
        current_id: match.id,
        title: match.title,
        note: 'Previously rejected finding re-confirmed. Code change may have reintroduced the issue.',
      });
    }
  }

  return {
    previous: previousPath,
    current: currentPath,
    summary: {
      previous_confirmed_or_needs_validation: previous.length,
      resolved: resolved.length,
      unchanged: unchanged.length,
      new: newFindings.length,
      regressions: regressions.length,
    },
    resolved,
    unchanged,
    new: newFindings,
    regressions,
  };
}

module.exports = { compareAudits, findingsMatch };

if (require.main === module) {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  if (args.length < 2) {
    console.error('Usage: node scripts/reaudit.js <previous-findings.json> <current-findings.json>');
    process.exit(2);
  }
  try {
    const result = compareAudits(path.resolve(args[0]), path.resolve(args[1]));
    console.log(JSON.stringify(result, null, 2));
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
}
