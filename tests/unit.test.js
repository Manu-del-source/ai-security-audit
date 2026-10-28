'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { walkFiles, toRel, verifyLocation, redactString, looksLikeSecret, shannonEntropy, REDACTED } = require('../lib/util');
const { CATEGORIES, CATEGORY_IDS, QUICK_SET, isCategory } = require('../lib/categories');
const { validate, validateFindings, loadSchema } = require('../lib/schema-validator');
const { buildPlan } = require('../lib/plan');
const { detectStack } = require('../scripts/detect-stack');
const { validateAllFindings, mechanicalChecks, rangesOverlap } = require('../scripts/validate-findings');
const { verifyCoverage, LEGAL_STATUSES } = require('../scripts/validate-coverage');
const { compareAudits, findingsMatch } = require('../scripts/reaudit');
const { generateReports, renderReport } = require('../scripts/report');

const VULN = path.join(__dirname, 'fixtures', 'vulnerable-app');
const SAFE = path.join(__dirname, 'fixtures', 'safe-app');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `asa-${prefix}-`));
}

// ---------------------------------------------------------------------------
// Shared finding factory — passes BOTH the ajv and the fallback validator.
// Line numbers refer to tests/fixtures/vulnerable-app/server.js (IDOR route).
// ---------------------------------------------------------------------------

function makeFinding(overrides = {}) {
  return {
    id: 'ASA-AUTHZ-001',
    title: 'Invoice endpoint returns other tenants invoices',
    severity: 'high',
    status: 'confirmed',
    category: 'authorization',
    confidence: 'high',
    affected_files: [{ path: 'server.js', lines: '43-48', symbol: "'/api/invoices/:id'" }],
    affected_components: ['GET /api/invoices/:id'],
    attack_surface: 'GET /api/invoices/:id with an arbitrary :id path parameter',
    attacker:
      'An authenticated user of tenant A; they control only the :id path parameter and do not control the server process.',
    evidence: [
      {
        source: 'code',
        file: 'server.js',
        lines: '43-48',
        detail: 'Query filters by id alone; there is no user_id or tenant predicate in the WHERE clause.',
      },
    ],
    impact: 'Any authenticated user can read invoices belonging to every other tenant.',
    severity_reasoning:
      'Reachable by any low-privilege account with no special preconditions; full cross-tenant read of billing data.',
    validation: {
      status: 'confirmed',
      attempted_rejections: [
        'Checked for global auth middleware that might scope queries - none exists in the fixture.',
      ],
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// lib/categories.js
// ---------------------------------------------------------------------------

test('categories: ids, uniqueness and agent playbook paths', () => {
  assert.ok(CATEGORY_IDS.length >= 17, 'expected at least 17 categories');
  assert.equal(new Set(CATEGORY_IDS).size, CATEGORY_IDS.length, 'category ids must be unique');
  for (const id of CATEGORY_IDS) {
    assert.ok(isCategory(id));
    assert.match(CATEGORIES[id].agent, /^agents\/[a-z0-9-]+\.md$/);
  }
  for (const id of QUICK_SET) {
    assert.ok(isCategory(id), 'QUICK_SET ids must be real categories');
  }
  assert.ok(!isCategory('nonexistent'));
});

// ---------------------------------------------------------------------------
// lib/util.js
// ---------------------------------------------------------------------------

test('util: verifyLocation range math', () => {
  const ok = verifyLocation(VULN, 'server.js', '43-48');
  assert.equal(ok.exists, true);
  assert.ok(ok.lineCount > 48);
  assert.equal(ok.linesInRange, 6);

  const single = verifyLocation(VULN, 'server.js', '1');
  assert.equal(single.linesInRange, 1);

  const oob = verifyLocation(VULN, 'server.js', '99999');
  assert.equal(oob.exists, true);
  assert.equal(oob.linesInRange, 0);

  const missing = verifyLocation(VULN, 'nope/missing.js', '1-2');
  assert.equal(missing.exists, false);
});

test('util: verifyLocation rejects traversal, absolute paths, and symlink escapes', () => {
  const root = tmpDir('verify-root');
  const outside = tmpDir('verify-outside');
  const outsideFile = path.join(outside, 'private.js');
  try {
    fs.writeFileSync(path.join(root, 'inside.js'), 'const ok = true;\\n');
    fs.writeFileSync(outsideFile, 'const privateValue = "not part of target";\\n');
    fs.symlinkSync(outsideFile, path.join(root, 'escape.js'));

    assert.equal(verifyLocation(root, path.relative(root, outsideFile), '1').exists, false);
    assert.equal(verifyLocation(root, outsideFile, '1').exists, false);
    assert.equal(verifyLocation(root, 'escape.js', '1').exists, false);
    assert.equal(verifyLocation(root, 'inside.js', '1').exists, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('util: redactString masks known secret shapes', () => {
  const cases = [
    ['postgres://admin:supersecret123@db.internal:5432/prod', 'supersecret123'],
    ['-----BEGIN RSA PRIVATE KEY-----\nMIIEpA\n-----END RSA PRIVATE KEY-----', 'MIIEpA'],
    ['password: "hunter2hunter2"', 'hunter2hunter2'],
    ['token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"', 'ghp_ABCDEFGH'],
    ['key AKIAIOSFODNN7EXAMPLE in text', 'AKIAIOSFODNN7'],
    ['set 61f8a2c4e9b03d7f81a5c6e2b4d9f0a1 as key', '61f8a2c4e9b03d7f81a5c6e2b4d9f0a1'],
  ];
  for (const [input, mustNotContain] of cases) {
    const out = redactString(input);
    assert.ok(out.includes(REDACTED), `expected redaction marker in: ${out}`);
    assert.ok(!out.includes(mustNotContain), `secret leaked: ${out}`);
  }
  // Normal text must survive redaction untouched.
  const plain = 'The invoice endpoint returns rows for any tenant id.';
  assert.equal(redactString(plain), plain);
});

test('util: looksLikeSecret signal heuristic', () => {
  assert.equal(looksLikeSecret('hTgY7uJ2kP9qW3zR5xLm'), true);
  assert.equal(looksLikeSecret('/usr/local/bin/node'), false, 'paths are not secrets');
  assert.equal(looksLikeSecret('password123'), false, 'too short / low entropy');
  assert.equal(shannonEntropy('aaaa') < shannonEntropy('aB3xK9mQ'), true);
});

test('util: walkFiles skips ignores and sorts output', () => {
  const files = walkFiles(SAFE).map((f) => toRel(SAFE, f));
  assert.ok(files.includes('server.js'));
  assert.ok(files.includes('routes/webhooks-stripe.js'));
  assert.ok(files.includes('.env.example'));
  assert.ok(!files.some((f) => f.includes('node_modules')));
  const sorted = [...files].sort();
  assert.deepEqual(files, sorted);
});

// ---------------------------------------------------------------------------
// lib/schema-validator.js
// ---------------------------------------------------------------------------

test('schema-validator: valid finding passes in the active mode', () => {
  const result = validate(makeFinding(), 'finding');
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
  assert.ok(['ajv', 'fallback'].includes(result.mode), `unexpected mode ${result.mode}`);
});

test('schema-validator: garbage finding is rejected in any mode', () => {
  const result = validate({}, 'finding');
  assert.equal(result.valid, false);
  assert.ok(result.errors.length > 0);
});

test('schema-validator: id/title/evidence minimums are enforced', () => {
  const bad = makeFinding({ id: 'nope', title: 'short', evidence: [] });
  const result = validate(bad, 'finding');
  assert.equal(result.valid, false);
  const messages = JSON.stringify(result.errors);
  assert.ok(messages.includes('id'));
  assert.ok(messages.includes('title'));
});

test('schema-validator: coverage and composite audit documents', () => {
  const ledger = {
    version: '1',
    generated_at: '2026-01-01T00:00:00Z',
    target: { root: '/tmp/x' },
    categories: [{ category: 'authorization', status: 'complete', files_examined: 2 }],
  };
  assert.equal(validate(ledger, 'coverage').valid, true);

  const badLedger = { ...ledger, categories: [{ category: 'authorization', status: 'bogus' }] };
  assert.equal(validate(badLedger, 'coverage').valid, false);

  const auditDoc = {
    version: '1',
    generated_at: '2026-01-01T00:00:00Z',
    target: { root: '/tmp/x' },
    findings: [makeFinding()],
    coverage: ledger,
  };
  const auditResult = validate(auditDoc, 'audit');
  assert.equal(auditResult.valid, true, JSON.stringify(auditResult.errors));

  // loadSchema returns parsed schemas for all three names
  for (const name of ['finding', 'coverage', 'audit']) {
    assert.equal(typeof loadSchema(name), 'object');
  }
  assert.throws(() => loadSchema('nonexistent'));
});

// ---------------------------------------------------------------------------
// scripts/detect-stack.js
// ---------------------------------------------------------------------------

test('detect-stack: vulnerable-app stack picture', () => {
  const stack = detectStack(VULN);
  assert.equal(stack.languages[0].lang, 'javascript');
  const fwNames = stack.frameworks.map((f) => f.name);
  for (const expected of ['Express', 'JWT', 'Payments', 'AI/LLM', 'File Upload', 'Password Hashing']) {
    assert.ok(fwNames.includes(expected), `expected framework ${expected}, got ${fwNames.join(', ')}`);
  }
  assert.equal(stack.webhooks.detected, true);
  assert.equal(stack.ai.detected, true);
  assert.equal(stack.summary.hasBackend, true);
  assert.equal(stack.summary.hasAI, true);
  assert.equal(stack.summary.hasWebhooks, true);
  assert.ok(stack.databases.some((d) => d.name === 'PostgreSQL'));
  assert.ok(stack.config.envFiles.includes('.env'), 'real .env must be detected');
  assert.ok(stack.auth.mechanisms.includes('JWT'));
});

test('detect-stack: safe-app has no AI, keeps webhook surface, ignores .env.example', () => {
  const stack = detectStack(SAFE);
  assert.equal(stack.ai.detected, false);
  assert.equal(stack.summary.hasAI, false);
  assert.equal(stack.webhooks.detected, true, 'webhook route strings should still be found');
  assert.equal(stack.config.envFiles.length, 0, '.env.example must not count as env file');
  assert.equal(stack.summary.hasBackend, true);
});

test('detect-stack: empty project produces a valid but minimal stack', () => {
  const dir = tmpDir('empty');
  fs.writeFileSync(path.join(dir, 'README.md'), '# nothing here\n');
  const stack = detectStack(dir);
  assert.equal(stack.languages.length, 0);
  assert.equal(stack.frameworks.length, 0);
  assert.equal(stack.summary.hasAI, false);
  assert.equal(stack.summary.fileCount, 1);
});

// ---------------------------------------------------------------------------
// lib/plan.js
// ---------------------------------------------------------------------------

test('plan: always-on core plus stack-adaptive categories', () => {
  const stack = detectStack(VULN);
  const plan = buildPlan(stack, {});
  const selected = plan.selected_categories;
  for (const core of ['authentication', 'authorization', 'api-security', 'business-logic', 'injection', 'secrets', 'dependencies']) {
    assert.ok(selected.includes(core), `core category ${core} must always be selected`);
  }
  for (const adaptive of ['ai-llm-security', 'webhook-security', 'client-side', 'file-storage', 'cryptography', 'resource-exhaustion']) {
    assert.ok(selected.includes(adaptive), `expected ${adaptive} for the vulnerable fixture`);
  }
  // Manifest without lockfile still selects supply-chain (manifest branch).
  assert.ok(selected.includes('supply-chain'));
  assert.ok((plan.reasoning || []).length > 0, 'plan must record reasoning');
});

test('plan: minimal stack excludes non-applicable categories with reasons', () => {
  const dir = tmpDir('bare');
  fs.writeFileSync(path.join(dir, 'README.md'), '# bare\n');
  const plan = buildPlan(detectStack(dir), {});
  assert.ok(plan.selected_categories.includes('configuration'), 'configuration is always in scope');
  assert.ok(!plan.selected_categories.includes('ai-llm-security'));
  assert.ok(!plan.selected_categories.includes('supply-chain'));
  assert.ok(!plan.selected_categories.includes('webhook-security'));
  for (const [id, reason] of Object.entries(plan.excluded_categories)) {
    assert.ok(typeof reason === 'string' && reason.length > 0, `exclusion of ${id} needs a reason`);
  }
});

test('plan: quick mode trims to the quick set; category option overrides', () => {
  const stack = detectStack(VULN);
  const quick = buildPlan(stack, { quick: true });
  assert.deepEqual(
    [...quick.selected_categories].sort(),
    [...QUICK_SET].sort()
  );
  const narrowed = buildPlan(stack, { category: ['injection'] });
  assert.deepEqual(narrowed.selected_categories, ['injection']);
});

// ---------------------------------------------------------------------------
// scripts/validate-findings.js
// ---------------------------------------------------------------------------

test('validate-findings: mechanically valid confirmed finding passes', () => {
  const dir = tmpDir('good');
  const file = path.join(dir, 'findings.json');
  fs.writeFileSync(file, JSON.stringify({ findings: [makeFinding()] }));
  const report = validateAllFindings(file, VULN);
  assert.equal(report.finding_count, 1);
  assert.equal(report.all_valid, true, JSON.stringify(report.results, null, 2));
  assert.equal(report.possible_pem_leak, false);
});

test('validate-findings: nonexistent evidence file fails', () => {
  const dir = tmpDir('badfile');
  const file = path.join(dir, 'findings.json');
  const bad = makeFinding({
    id: 'ASA-AUTHZ-002',
    status: 'candidate',
    affected_files: [{ path: 'does-not-exist.js', lines: '1-2' }],
  });
  fs.writeFileSync(file, JSON.stringify([bad]));
  const report = validateAllFindings(file, VULN);
  assert.equal(report.all_valid, false);
  const problems = JSON.stringify(report.results[0].problems);
  assert.ok(problems.includes('does-not-exist.js'));
});

test('validate-findings: out-of-bounds line range fails; wrong symbol warns', () => {
  const dir = tmpDir('oob');
  const file = path.join(dir, 'findings.json');
  const oob = makeFinding({
    id: 'ASA-AUTHZ-003',
    status: 'candidate',
    affected_files: [{ path: 'server.js', lines: '99999' }],
  });
  const wrongSymbol = makeFinding({
    id: 'ASA-AUTHZ-004',
    status: 'candidate',
    affected_files: [{ path: 'server.js', lines: '43-48', symbol: 'this_symbol_is_absent' }],
  });
  fs.writeFileSync(file, JSON.stringify([oob, wrongSymbol]));
  const report = validateAllFindings(file, VULN);
  assert.equal(report.results[0].ok, false);
  assert.ok(report.results[0].problems.some((p) => p.includes('out of bounds')));
  assert.equal(report.results[1].ok, true, 'wrong symbol is a warning, not a problem');
  assert.ok(report.results[1].warnings.some((w) => w.includes('this_symbol_is_absent')));
});

test('validate-findings: confirmed policy requires severity reasoning + rejection log', () => {
  const noReasoning = makeFinding({ severity_reasoning: undefined });
  const r1 = mechanicalChecks(noReasoning, VULN, new Set(['server.js']));
  assert.ok(r1.problems.some((p) => p.includes('severity_reasoning')));

  const noLog = makeFinding({ validation: {} });
  const r2 = mechanicalChecks(noLog, VULN, new Set(['server.js']));
  assert.ok(r2.problems.some((p) => p.includes('attempted_rejections')));
});

test('validate-findings: secret-like material in evidence is flagged', () => {
  const dir = tmpDir('leak');
  const file = path.join(dir, 'findings.json');
  const leaky = makeFinding({
    status: 'candidate',
    evidence: [
      {
        source: 'code',
        file: 'server.js',
        detail: 'Hardcoded credential present: password = "hunter2secret-value".',
      },
    ],
  });
  fs.writeFileSync(file, JSON.stringify({ findings: [leaky] }));
  const report = validateAllFindings(file, VULN);
  const warnings = JSON.stringify(report.results[0].warnings);
  assert.ok(warnings.includes('secret-like material'), `expected leak warning, got: ${warnings}`);
});

test('validate-findings: unredacted PEM in findings.json trips the file-level leak check', () => {
  const dir = tmpDir('pem');
  const file = path.join(dir, 'findings.json');
  const pemFinding = makeFinding({
    status: 'candidate',
    attacker: 'Attacker holding -----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY----- material.',
  });
  fs.writeFileSync(file, JSON.stringify({ findings: [pemFinding] }));
  const report = validateAllFindings(file, VULN);
  assert.equal(report.possible_pem_leak, true);
});

test('validate-findings: duplicate candidates share category and overlapping lines', () => {
  assert.equal(rangesOverlap('43-48', '45-50'), true);
  assert.equal(rangesOverlap('43-48', '50-60'), false);
  assert.equal(rangesOverlap('43', '43'), true);
  assert.equal(rangesOverlap('bogus', '1-2'), false);

  const a = makeFinding({ id: 'ASA-AUTHZ-010' });
  const b = makeFinding({ id: 'ASA-AUTHZ-011' });
  const dir = tmpDir('dup');
  const file = path.join(dir, 'findings.json');
  fs.writeFileSync(file, JSON.stringify({ findings: [a, b] }));
  const report = validateAllFindings(file, VULN);
  assert.equal(report.duplicate_candidates.length, 1);
  assert.equal(report.duplicate_candidates[0].a, 'ASA-AUTHZ-010');
});

// ---------------------------------------------------------------------------
// scripts/validate-coverage.js
// ---------------------------------------------------------------------------

test('validate-coverage: ledger must match the plan exactly-once', () => {
  const plan = { selected_categories: ['authorization', 'injection'], excluded_categories: {} };
  const good = {
    categories: [
      { category: 'authorization', status: 'complete', files_examined: 3 },
      { category: 'injection', status: 'partial', gaps: ['stored procedures not reviewed'] },
    ],
  };
  const ok = verifyCoverage(good, plan);
  assert.equal(ok.ok, true, JSON.stringify(ok.problems));

  const missing = verifyCoverage({ categories: [good.categories[0]] }, plan);
  assert.ok(missing.problems.some((p) => p.includes("'injection' missing")));

  const dup = verifyCoverage(
    { categories: [good.categories[0], { ...good.categories[0] }, good.categories[1]] },
    plan
  );
  assert.ok(dup.problems.some((p) => p.includes('2 times')));
});

test('validate-coverage: gap documentation and status rules', () => {
  const plan = { selected_categories: ['authorization'], excluded_categories: {} };
  const result = verifyCoverage(
    {
      categories: [
        { category: 'authorization', status: 'blocked', gaps: [] },
        { category: 'injection', status: 'definitely-audited' },
        { category: 'secrets', status: 'complete', files_examined: 0 },
        { category: 'dependencies', status: 'not_applicable' },
      ],
    },
    plan
  );
  assert.ok(result.problems.some((p) => p.includes('authorization') && p.includes('no gaps')));
  assert.ok(result.problems.some((p) => p.includes('definitely-audited')));
  assert.ok(result.warnings.some((p) => p.includes('secrets')));
  assert.ok(result.warnings.some((p) => p.includes('dependencies')));
  assert.deepEqual(LEGAL_STATUSES, ['complete', 'partial', 'not_applicable', 'blocked', 'needs_validation']);
});

// ---------------------------------------------------------------------------
// scripts/reaudit.js
// ---------------------------------------------------------------------------

test('reaudit: matching confirmed finding is unchanged; rejection resolves', () => {
  const prev = { findings: [makeFinding()] };
  const curSame = { findings: [makeFinding()] };
  const r = compareAudits(JSON.stringify(prev) && writeTemp(prev), writeTemp(curSame));
  assert.equal(r.summary.unchanged, 1);
  assert.equal(r.summary.resolved, 0);

  const curRejected = { findings: [makeFinding({ status: 'rejected' })] };
  const r2 = compareAudits(writeTemp(prev), writeTemp(curRejected));
  assert.equal(r2.summary.resolved, 1);
  assert.equal(r2.resolved[0].previous_id, 'ASA-AUTHZ-001');
});

test('reaudit: missing match requires revalidation before resolution', () => {
  const prev = { findings: [makeFinding()] };
  const cur = { findings: [] };
  const r = compareAudits(writeTemp(prev), writeTemp(cur));
  assert.equal(r.summary.resolved, 1);
  assert.equal(r.resolved[0].requires_revalidation, true);
});

test('reaudit: new findings and regressions are detected', () => {
  const prev = { findings: [makeFinding()] };
  const cur = {
    findings: [
      makeFinding({ status: 'candidate' }),
      makeFinding({
        id: 'ASA-INJEC-001',
        category: 'injection',
        title: 'SQL built from untrusted sort parameter',
        affected_files: [{ path: 'server.js', lines: '50-58' }],
      }),
    ],
  };
  const r = compareAudits(writeTemp(prev), writeTemp(cur));
  assert.equal(r.summary.new, 1);
  assert.equal(r.summary.regressions, 0);

  // Regression: previously rejected area re-confirmed now.
  const prevRejected = { findings: [makeFinding({ status: 'rejected' })] };
  const curConfirmed = { findings: [makeFinding()] };
  const r2 = compareAudits(writeTemp(prevRejected), writeTemp(curConfirmed));
  assert.equal(r2.summary.regressions, 1);
});

test('reaudit: matcher requires same category', () => {
  const a = makeFinding();
  const b = makeFinding({ category: 'injection' });
  assert.equal(findingsMatch(a, b), false);
});

// ---------------------------------------------------------------------------
// scripts/report.js
// ---------------------------------------------------------------------------

test('report: renders confirmed findings, redacts secrets, marks gaps', () => {
  const dir = tmpDir('report');
  const findings = {
    findings: [
      makeFinding({
        impact: 'Exfiltrates postgres://user:hunter2secret@db:5432/app connection details.',
      }),
      makeFinding({
        id: 'ASA-AUTHZ-002',
        status: 'needs_validation',
        validation: {},
      }),
    ],
  };
  const coverage = {
    version: '1',
    generated_at: '2026-01-01T00:00:00Z',
    target: { root: '/tmp/target' },
    categories: [
      { category: 'authorization', status: 'complete', files_examined: 5, candidates_found: 1, notes: '' },
      { category: 'injection', status: 'partial', files_examined: 2, candidates_found: 0, gaps: ['queue consumers not reviewed'] },
    ],
  };
  fs.writeFileSync(path.join(dir, 'findings.json'), JSON.stringify(findings));
  fs.writeFileSync(path.join(dir, 'coverage-ledger.json'), JSON.stringify(coverage));

  const res = generateReports(dir, { targetRoot: '/tmp/target', auditId: 'T-1' });
  assert.deepEqual(res.written, ['REPORT.md', 'FINDINGS-DETAIL.md', 'NEEDS-VALIDATION.md']);

  const report = fs.readFileSync(path.join(dir, 'REPORT.md'), 'utf8');
  assert.ok(report.includes('1 confirmed finding(s)'));
  assert.ok(report.includes('ASA-AUTHZ-001'));
  assert.ok(!report.includes('hunter2secret'), 'connection-string password must be redacted in reports');
  assert.ok(report.includes('queue consumers not reviewed'), 'coverage gaps must appear in the report');

  const detail = fs.readFileSync(path.join(dir, 'FINDINGS-DETAIL.md'), 'utf8');
  assert.ok(detail.includes('hunter2secret') === false, 'detail must be redacted too');
  assert.ok(detail.includes('[REDACTED]'), 'impact text containing the secret renders in detail view');
  assert.ok(detail.includes('disprove'));
  const needs = fs.readFileSync(path.join(dir, 'NEEDS-VALIDATION.md'), 'utf8');
  assert.ok(needs.includes('ASA-AUTHZ-002'));
});

test('report: zero-confirmed report must distinguish clean from unaudited', () => {
  const coverage = {
    version: '1',
    generated_at: '2026-01-01T00:00:00Z',
    target: { root: '/tmp/target' },
    categories: [
      { category: 'authorization', status: 'complete', files_examined: 9 },
      { category: 'injection', status: 'blocked', gaps: ['no time budget'] },
    ],
  };
  const md = renderReport({
    stack: null,
    findings: [],
    coverage,
    meta: { targetRoot: '/tmp/target', generatedAt: '2026-01-01T00:00:00Z' },
  });
  assert.ok(md.includes('No confirmed vulnerabilities'));
  assert.ok(md.includes('injection'), 'blocked category must be surfaced as a caveat');
  assert.ok(md.includes('blocked'));
});

// ---------------------------------------------------------------------------

function writeTemp(data) {
  const dir = tmpDir('reaudit');
  const file = path.join(dir, 'findings.json');
  fs.writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data));
  return file;
}
