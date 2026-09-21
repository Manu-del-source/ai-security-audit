'use strict';

// Deterministic report rendering. No AI involvement: take findings.json and
// coverage-ledger.json, emit REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md.
// Secrets are redacted on the way out. "No vulnerability found" is only
// claimed for categories marked complete; others are reported as coverage gaps.

const fs = require('fs');
const path = require('path');
const { redactString } = require('../lib/util');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function sevRank(s) {
  return { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }[s] ?? 5;
}

function esc(s) {
  return redactString(String(s == null ? '' : s));
}

function renderFindingRow(f) {
  const loc = (f.affected_files || [])
    .map((af) => `\`${af.path}:${af.lines}\``)
    .join(', ');
  return `| ${f.id} | ${esc(f.title)} | ${f.severity} | ${loc} |`;
}

function renderFindingDetail(f) {
  const lines = [];
  lines.push(`### ${f.id} — ${esc(f.title)}`);
  lines.push('');
  lines.push(`- **Severity:** ${f.severity}  `);
  lines.push(`- **Confidence:** ${f.confidence || 'n/a'}  `);
  lines.push(`- **Status:** ${f.status}  `);
  lines.push(`- **Category:** ${f.category}  `);
  lines.push('');
  lines.push(`**Attack surface:** ${esc(f.attack_surface)}`);
  lines.push('');
  lines.push(`**Attacker (threat model):** ${esc(f.attacker)}`);
  lines.push('');
  if (f.preconditions && f.preconditions.length) {
    lines.push('**Preconditions:**');
    for (const p of f.preconditions) lines.push(`- ${esc(p)}`);
    lines.push('');
  }
  lines.push('**Evidence:**');
  for (const e of f.evidence || []) {
    const loc = e.file ? ` (\`${e.file}${e.lines ? ':' + e.lines : ''}\`)` : '';
    lines.push(`- ${esc(e.detail)}${loc}`);
  }
  lines.push('');
  if (f.data_flow && f.data_flow.length) {
    lines.push('**Data flow:**');
    f.data_flow.forEach((step, i) => lines.push(`${i + 1}. ${esc(step)}`));
    lines.push('');
  }
  lines.push(`**Impact:** ${esc(f.impact)}`);
  lines.push('');
  if (f.reproduction && f.reproduction.length) {
    lines.push('**Reproduction (non-destructive):**');
    f.reproduction.forEach((r, i) => lines.push(`${i + 1}. ${esc(r)}`));
    lines.push('');
  }
  if (f.severity_reasoning) {
    lines.push(`**Severity reasoning:** ${esc(f.severity_reasoning)}`);
    lines.push('');
  }
  if (f.validation && (f.validation.attempted_rejections || []).length) {
    lines.push('**Validator attempts to disprove:**');
    for (const r of f.validation.attempted_rejections) lines.push(`- ${esc(r)}`);
    lines.push('');
  }
  if (f.remediation && (f.remediation.summary || (f.remediation.steps || []).length)) {
    lines.push('**Remediation:**');
    if (f.remediation.summary) lines.push(esc(f.remediation.summary));
    for (const s of f.remediation.steps || []) lines.push(`- ${esc(s)}`);
    lines.push('');
  }
  if (f.references && f.references.length) {
    lines.push(`**References:** ${f.references.map(esc).join(', ')}`);
    lines.push('');
  }
  return lines.join('\n');
}

function renderCoverageTable(coverage) {
  const rows = [
    '| Category | Status | Files | Routes | Candidates | Notes |',
    '|---|---|---|---|---|---|',
  ];
  for (const c of coverage.categories || []) {
    rows.push(
      `| ${c.category} | ${c.status} | ${c.files_examined ?? '—'} | ${c.routes_examined ?? '—'} | ${c.candidates_found ?? 0} | ${esc((c.notes || '').slice(0, 120))} |`
    );
  }
  return rows.join('\n');
}

function renderReport(ctx) {
  const { stack, findings, coverage, meta } = ctx;
  const confirmed = findings
    .filter((f) => f.status === 'confirmed')
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const needsValidation = findings.filter((f) => f.status === 'needs_validation' || f.status === 'candidate');
  const rejected = findings.filter((f) => f.status === 'rejected');

  const out = [];
  out.push('# Security Audit Report');
  out.push('');
  out.push(`- **Target:** \`${meta.targetRoot}\``);
  out.push(`- **Audit date:** ${meta.generatedAt}`);
  out.push(`- **Audit ID:** ${meta.auditId || 'n/a'}`);
  if (stack && stack.summary) {
    out.push(`- **Detected stack:** ${stack.summary.primaryLanguages.join(', ')}${stack.frameworks.length ? `; ${[...new Set(stack.frameworks.map((f) => f.name))].join(', ')}` : ''}`);
  }
  out.push(`- **Scope:** ${meta.scopeNotes || 'Full repository'}`);
  out.push('');

  out.push('## Executive summary');
  out.push('');
  if (confirmed.length === 0) {
    out.push('**No confirmed vulnerabilities.** This does not mean the application is secure:');
    const incomplete = (coverage.categories || []).filter((c) => c.status !== 'complete' && c.status !== 'not_applicable');
    if (incomplete.length) {
      out.push(`coverage was incomplete for: ${incomplete.map((c) => `**${c.category}** (${c.status})`).join(', ')}.`);
    } else {
      out.push('all planned categories were audited to completion, but AI audits have inherent blind spots. Re-run with --deep and rotate hunter models where possible.');
    }
  } else {
    const crit = confirmed.filter((f) => f.severity === 'critical').length;
    const high = confirmed.filter((f) => f.severity === 'high').length;
    out.push(`**${confirmed.length} confirmed finding(s)**: ${crit} critical, ${high} high, ${confirmed.length - crit - high} medium/low/informational.`);
    out.push(`Additionally, ${needsValidation.length} finding(s) could not be fully validated and need human review.`);
  }
  out.push('');

  out.push('## Coverage');
  out.push('');
  out.push(renderCoverageTable(coverage));
  out.push('');
  const gaps = (coverage.categories || []).filter((c) => (c.gaps || []).length);
  if (gaps.length) {
    out.push('### Known coverage gaps');
    out.push('');
    for (const g of gaps) {
      out.push(`- **${g.category}:** ${g.gaps.map(esc).join('; ')}`);
    }
    out.push('');
  }

  out.push('## Confirmed findings');
  out.push('');
  if (confirmed.length === 0) {
    out.push('_None._');
  } else {
    out.push('| ID | Title | Severity | Location |');
    out.push('|---|---|---|---|');
    for (const f of confirmed) out.push(renderFindingRow(f));
    out.push('');
    out.push('## Remediation priorities');
    out.push('');
    out.push('Ordered by severity, then by reachability from untrusted input:');
    out.push('');
    confirmed.forEach((f, i) => {
      out.push(`${i + 1}. **${f.id}** (${f.severity}) — ${esc(f.title)}`);
      if (f.remediation && f.remediation.summary) out.push(`   - Fix: ${esc(f.remediation.summary)}`);
    });
  }
  out.push('');
  out.push(`Full technical detail: see \`FINDINGS-DETAIL.md\`.`);
  if (needsValidation.length) {
    out.push(`Unresolved candidates: see \`NEEDS-VALIDATION.md\` (${needsValidation.length} item(s)).`);
  }
  out.push('');
  out.push('## Limitations');
  out.push('');
  out.push('- Static, AI-assisted review; no guarantee of completeness.');
  out.push('- Runtime behavior, external services and production configuration were not exercised unless explicitly noted.');
  out.push('- Findings marked `needs_validation` are hypotheses with evidence, not confirmed exploits.');
  if (rejected.length) {
    out.push(`- ${rejected.length} candidate(s) were rejected during validation and are listed in \`findings.json\` for transparency.`);
  }
  out.push('');
  return out.join('\n');
}

function renderNeedsValidation(findings) {
  const items = findings.filter((f) => f.status === 'needs_validation' || f.status === 'candidate');
  const out = [];
  out.push('# Needs Validation');
  out.push('');
  out.push('These findings could not be fully confirmed or refuted with the available evidence.');
  out.push('They are hypotheses with concrete evidence attached — treat them as *leads*, not vulnerabilities.');
  out.push('');
  if (items.length === 0) {
    out.push('_No unresolved candidates._');
    return out.join('\n');
  }
  for (const f of items) {
    out.push(renderFindingDetail(f));
    out.push('---');
    out.push('');
  }
  return out.join('\n');
}

function renderFindingsDetail(findings) {
  const confirmed = findings.filter((f) => f.status === 'confirmed');
  const out = [];
  out.push('# Findings Detail');
  out.push('');
  if (confirmed.length === 0) {
    out.push('_No confirmed findings._');
    return out.join('\n');
  }
  for (const f of confirmed) {
    out.push(renderFindingDetail(f));
    out.push('---');
    out.push('');
  }
  return out.join('\n');
}

function generateReports(outputDir, options) {
  const opts = options || {};
  const findingsPath = path.join(outputDir, 'findings.json');
  const coveragePath = path.join(outputDir, 'coverage-ledger.json');
  const findings = loadJson(findingsPath);
  const list = Array.isArray(findings) ? findings : findings.findings || [];
  const coverage = loadJson(coveragePath);
  const stack = fs.existsSync(path.join(outputDir, 'stack.json'))
    ? loadJson(path.join(outputDir, 'stack.json'))
    : null;

  const meta = {
    targetRoot: opts.targetRoot || coverage.target && coverage.target.root || 'unknown',
    generatedAt: coverage.generated_at || new Date().toISOString(),
    auditId: opts.auditId,
    scopeNotes: opts.scopeNotes || (coverage.target && coverage.target.scope_notes),
  };

  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'REPORT.md'), renderReport({ stack, findings: list, coverage, meta }));
  fs.writeFileSync(path.join(outputDir, 'FINDINGS-DETAIL.md'), renderFindingsDetail(list));
  fs.writeFileSync(path.join(outputDir, 'NEEDS-VALIDATION.md'), renderNeedsValidation(list));
  return { written: ['REPORT.md', 'FINDINGS-DETAIL.md', 'NEEDS-VALIDATION.md'] };
}

module.exports = { generateReports, renderReport, renderFindingsDetail, renderNeedsValidation };

if (require.main === module) {
  const args = process.argv.slice(2);
  const outputDir = args.find((a) => !a.startsWith('--')) || '.audit';
  const targetIdx = args.indexOf('--target');
  try {
    const res = generateReports(outputDir, { targetRoot: targetIdx >= 0 ? args[targetIdx + 1] : undefined });
    console.log(`Wrote: ${res.written.join(', ')} in ${outputDir}`);
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
}
