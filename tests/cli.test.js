'use strict';

// CLI smoke tests: run bin/security-audit.js as a subprocess against the
// fixtures and exercise the full command surface end-to-end.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'security-audit.js');
const VULN = path.join(ROOT, 'tests', 'fixtures', 'vulnerable-app');
const SAFE = path.join(ROOT, 'tests', 'fixtures', 'safe-app');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(process.env.TMPDIR || process.env.TMP || '/tmp', `asa-cli-${prefix}-`));
}

function runCli(args, opts = {}) {
  return execFileSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    ...opts,
  });
}

function runCliExpectFailure(args) {
  try {
    execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
    assert.fail(`expected CLI to exit non-zero for: ${args.join(' ')}`);
  } catch (e) {
    assert.ok(typeof e.status === 'number' && e.status !== 0, `expected non-zero exit, got ${e.status}`);
    return (e.stdout || '') + (e.stderr || '');
  }
  return '';
}

// ---------------------------------------------------------------------------
// help / version
// ---------------------------------------------------------------------------

test('cli: help and version', () => {
  const help = runCli([]);
  assert.ok(help.includes('security-audit'));
  assert.ok(help.includes('recon'));
  assert.ok(help.includes('reaudit'));
  assert.ok(help.includes('Authorized use only'));
  assert.equal(runCli(['--version']).trim(), '0.1.0');
  const unknown = runCliExpectFailure(['definitely-not-a-command']);
  assert.ok(unknown.includes('Unknown command'));
});

// ---------------------------------------------------------------------------
// recon
// ---------------------------------------------------------------------------

test('cli: recon detects the vulnerable fixture stack and writes artifacts', () => {
  const outDir = tmpDir('recon');
  const out = runCli(['recon', VULN, '--output', outDir, '--scope', 'unit test scope']);
  assert.ok(out.includes('Recon complete'));
  assert.ok(out.includes('Express'));

  const stack = JSON.parse(fs.readFileSync(path.join(outDir, 'stack.json'), 'utf8'));
  assert.equal(stack.summary.hasBackend, true);
  assert.equal(stack.summary.hasAI, true);
  assert.ok(stack.frameworks.some((f) => f.name === 'Express'));

  const plan = JSON.parse(fs.readFileSync(path.join(outDir, 'audit-plan.json'), 'utf8'));
  assert.ok(plan.selected_categories.includes('ai-llm-security'));
  assert.ok(plan.selected_categories.includes('webhook-security'));
  assert.equal(plan.framework_filter, undefined);
});

test('cli: recon --quick trims the plan; missing target exits non-zero', () => {
  const outDir = tmpDir('quick');
  runCli(['recon', VULN, '--output', outDir, '--quick']);
  const plan = JSON.parse(fs.readFileSync(path.join(outDir, 'audit-plan.json'), 'utf8'));
  assert.ok(plan.quick === true);
  assert.ok(plan.selected_categories.length < 17, 'quick mode must trim categories');

  const err = runCliExpectFailure(['recon', path.join(ROOT, 'no', 'such', 'dir')]);
  assert.ok(err.includes('Target does not exist'));
});

// ---------------------------------------------------------------------------
// audit (scaffolding command)
// ---------------------------------------------------------------------------

test('cli: audit writes run instructions and prints next steps', () => {
  const outDir = tmpDir('audit');
  const out = runCli(['audit', VULN, '--output', outDir, '--deep']);
  assert.ok(out.includes('Next step'));
  const instructions = fs.readFileSync(path.join(outDir, 'RUN-INSTRUCTIONS.md'), 'utf8');
  assert.ok(instructions.includes('threat-model.json'));
  assert.ok(instructions.includes('agents/authorization.md'));
  assert.ok(instructions.includes('attempted_rejections'));
  assert.ok(instructions.includes('DEEP'));
});

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

test('cli: validate passes a well-formed findings file and fails a bad one', () => {
  const outDir = tmpDir('validate');
  fs.mkdirSync(outDir, { recursive: true });

  fs.writeFileSync(
    path.join(outDir, 'findings.json'),
    JSON.stringify({
      findings: [
        {
          id: 'ASA-AUTHZ-001',
          title: 'Invoice endpoint returns other tenants invoices',
          severity: 'high',
          status: 'candidate',
          category: 'authorization',
          confidence: 'high',
          affected_files: [{ path: 'server.js', lines: '43-48' }],
          attack_surface: 'GET /api/invoices/:id with arbitrary :id',
          attacker:
            'An authenticated tenant user; they control the :id path parameter and do not control the server process.',
          evidence: [
            {
              source: 'code',
              file: 'server.js',
              lines: '43-48',
              detail: 'Query has no user_id or tenant predicate in the WHERE clause.',
            },
          ],
          impact: 'Cross-tenant invoice disclosure to any authenticated user.',
        },
      ],
    })
  );

  const out = runCli(['validate', outDir, VULN]);
  assert.ok(out.includes('[OK ]'), 'well-formed finding should pass');
  assert.ok(fs.existsSync(path.join(outDir, 'validation-report.json')));

  // Now break it: evidence file that does not exist.
  const badDir = tmpDir('validate-bad');
  fs.mkdirSync(badDir, { recursive: true });
  fs.writeFileSync(
    path.join(badDir, 'findings.json'),
    JSON.stringify([
      {
        id: 'ASA-AUTHZ-002',
        title: 'Fabricated evidence should fail validation',
        severity: 'high',
        status: 'candidate',
        category: 'authorization',
        confidence: 'high',
        affected_files: [{ path: 'not-a-real-file.js', lines: '1-2' }],
        attack_surface: 'GET /nowhere',
        attacker: 'An authenticated user; they control nothing relevant here.',
        evidence: [{ source: 'code', file: 'not-a-real-file.js', detail: 'Cites a file that does not exist.' }],
        impact: 'This finding must be rejected by mechanical validation.',
      },
    ])
  );
  const err = runCliExpectFailure(['validate', badDir, VULN]);
  assert.ok(err.includes('[FAIL]'));
  assert.ok(err.includes('not-a-real-file.js'));
});

test('cli: validate without findings.json errors out', () => {
  const outDir = tmpDir('validate-empty');
  fs.mkdirSync(outDir, { recursive: true });
  const err = runCliExpectFailure(['validate', outDir, VULN]);
  assert.ok(err.includes('No findings.json'));
});

// ---------------------------------------------------------------------------
// coverage
// ---------------------------------------------------------------------------

test('cli: coverage verifies a complete ledger and rejects an incomplete one', () => {
  const stack = JSON.parse(
    fs.readFileSync(
      (() => {
        const d = tmpDir('coverage-stack');
        runCli(['recon', VULN, '--output', d]);
        return path.join(d, 'stack.json');
      })(),
      'utf8'
    )
  );
  // Rebuild the plan deterministically for the selected list.
  const { buildPlan } = require('../lib/plan');
  const plan = buildPlan(stack, {});
  const selected = plan.selected_categories;

  const outDir = tmpDir('coverage');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, 'audit-plan.json'),
    JSON.stringify(plan)
  );
  fs.writeFileSync(
    path.join(outDir, 'coverage-ledger.json'),
    JSON.stringify({
      version: '1',
      generated_at: '2026-01-01T00:00:00Z',
      target: { root: VULN },
      categories: selected.map((c) => ({ category: c, status: 'complete', files_examined: 1 })),
    })
  );

  const out = runCli(['coverage', outDir]);
  assert.ok(out.includes('PASS'));
  assert.ok(fs.existsSync(path.join(outDir, 'coverage-report.json')));

  // Incomplete ledger: drop one selected category.
  const badDir = tmpDir('coverage-bad');
  fs.mkdirSync(badDir, { recursive: true });
  fs.writeFileSync(path.join(badDir, 'audit-plan.json'), JSON.stringify(plan));
  fs.writeFileSync(
    path.join(badDir, 'coverage-ledger.json'),
    JSON.stringify({
      version: '1',
      generated_at: '2026-01-01T00:00:00Z',
      target: { root: VULN },
      categories: selected.slice(1).map((c) => ({ category: c, status: 'complete', files_examined: 1 })),
    })
  );
  const err = runCliExpectFailure(['coverage', badDir]);
  assert.ok(err.includes('FAIL'));
  assert.ok(err.includes('missing from coverage ledger'));
});

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

test('cli: report renders the three markdown artifacts', () => {
  const outDir = tmpDir('report');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, 'findings.json'),
    JSON.stringify({
      findings: [
        {
          id: 'ASA-AUTHZ-001',
          title: 'Invoice endpoint returns other tenants invoices',
          severity: 'high',
          status: 'confirmed',
          category: 'authorization',
          confidence: 'high',
          affected_files: [{ path: 'server.js', lines: '43-48' }],
          attack_surface: 'GET /api/invoices/:id with arbitrary :id',
          attacker:
            'An authenticated tenant user; they control the :id path parameter and do not control the server process.',
          evidence: [
            { source: 'code', file: 'server.js', lines: '43-48', detail: 'No ownership predicate in the query.' },
          ],
          impact: 'Cross-tenant invoice disclosure to any authenticated user.',
          severity_reasoning: 'Any account can read all invoices; no preconditions beyond authentication.',
          validation: { attempted_rejections: ['Checked for scoping middleware; none exists in the fixture.'] },
        },
      ],
    })
  );
  fs.writeFileSync(
    path.join(outDir, 'coverage-ledger.json'),
    JSON.stringify({
      version: '1',
      generated_at: '2026-01-01T00:00:00Z',
      target: { root: VULN },
      categories: [{ category: 'authorization', status: 'complete', files_examined: 4, candidates_found: 1 }],
    })
  );

  const out = runCli(['report', outDir, VULN]);
  assert.ok(out.includes('REPORT.md'));
  assert.ok(out.includes('FINDINGS-DETAIL.md'));
  assert.ok(out.includes('NEEDS-VALIDATION.md'));

  const report = fs.readFileSync(path.join(outDir, 'REPORT.md'), 'utf8');
  assert.ok(report.includes('1 confirmed finding(s)'));
  assert.ok(report.includes('ASA-AUTHZ-001'));
  const detail = fs.readFileSync(path.join(outDir, 'FINDINGS-DETAIL.md'), 'utf8');
  assert.ok(detail.includes('Disprove') || detail.includes('disprove'));
  const needs = fs.readFileSync(path.join(outDir, 'NEEDS-VALIDATION.md'), 'utf8');
  assert.ok(needs.includes('No unresolved candidates.'));
});

// ---------------------------------------------------------------------------
// reaudit
// ---------------------------------------------------------------------------

test('cli: reaudit compares previous and current findings', () => {
  const outDir = tmpDir('reaudit');
  fs.mkdirSync(outDir, { recursive: true });

  const finding = (id, status) => ({
    id,
    title: 'Invoice endpoint returns other tenants invoices',
    severity: 'high',
    status,
    category: 'authorization',
    confidence: 'high',
    affected_files: [{ path: 'server.js', lines: '43-48' }],
    attack_surface: 'GET /api/invoices/:id with arbitrary :id',
    attacker: 'An authenticated tenant user; they control the :id parameter.',
    evidence: [{ source: 'code', file: 'server.js', lines: '43-48', detail: 'No ownership predicate in the query.' }],
    impact: 'Cross-tenant invoice disclosure to any authenticated user.',
  });

  const prevPath = path.join(outDir, 'prev.json');
  const curPath = path.join(outDir, 'cur.json');
  fs.writeFileSync(prevPath, JSON.stringify({ findings: [finding('ASA-AUTHZ-001', 'confirmed')] }));
  fs.writeFileSync(curPath, JSON.stringify({ findings: [finding('ASA-AUTHZ-001', 'confirmed')] }));

  const out = runCli(['reaudit', prevPath, curPath, '--output', outDir]);
  assert.ok(out.includes('unchanged:         1'));
  assert.ok(
    out.includes('require re-validation') || out.includes('requires_revalidation'),
    `reaudit output should mention re-validation: ${out}`
  );
  assert.ok(fs.existsSync(path.join(outDir, 'reaudit-report.json')));

  const err = runCliExpectFailure(['reaudit', prevPath, path.join(outDir, 'missing.json')]);
  assert.ok(err.includes('Usage'));
});

// ---------------------------------------------------------------------------
// End-to-end: safe fixture should survive the deterministic gates
// ---------------------------------------------------------------------------

test('cli: end-to-end recon+validate+coverage+report on the safe fixture', () => {
  const outDir = tmpDir('e2e-safe');
  runCli(['audit', SAFE, '--output', outDir]);

  const { buildPlan } = require('../lib/plan');
  const stack = JSON.parse(fs.readFileSync(path.join(outDir, 'stack.json'), 'utf8'));
  const plan = buildPlan(stack, {});
  fs.writeFileSync(path.join(outDir, 'audit-plan.json'), JSON.stringify(plan));

  // A clean audit: no findings, every selected category complete.
  fs.writeFileSync(path.join(outDir, 'findings.json'), JSON.stringify({ findings: [] }));
  fs.writeFileSync(
    path.join(outDir, 'coverage-ledger.json'),
    JSON.stringify({
      version: '1',
      generated_at: '2026-01-01T00:00:00Z',
      target: { root: SAFE },
      categories: plan.selected_categories.map((c) => ({
        category: c,
        status: 'complete',
        files_examined: 3,
      })),
    })
  );

  const v = runCli(['validate', outDir, SAFE]);
  assert.ok(v.includes('finding(s), mode='));
  runCli(['coverage', outDir]);
  runCli(['report', outDir, SAFE]);
  const report = fs.readFileSync(path.join(outDir, 'REPORT.md'), 'utf8');
  assert.ok(report.includes('No confirmed vulnerabilities'));
});
