#!/usr/bin/env node
'use strict';

// security-audit CLI.
//
// The deterministic core (recon, plan, mechanical validation, coverage
// checks, report rendering, re-audit diffing) lives here. The AI-driven
// phases (hunting, adversarial validation) are executed by the coding agent
// following SKILL.md; the CLI prepares their inputs and checks their outputs.
//
// Commands:
//   security-audit recon <target>                  Detect stack, write stack.json
//   security-audit audit <target>                  Full pipeline scaffolding + docs
//   security-audit validate <outputDir> <target>   Mechanically check findings.json
//   security-audit coverage <outputDir> [--plan]   Verify coverage ledger
//   security-audit report <outputDir>              Render markdown reports
//   security-audit reaudit <prev> <cur>            Compare two audits
//
// Options: --scope <note> --output <dir> --framework <name> --category <id>
//          --severity <level> --deep --quick

const fs = require('fs');
const path = require('path');
const { detectStack } = require('../scripts/detect-stack');
const { buildPlan } = require('../lib/plan');
const { validateAllFindings } = require('../scripts/validate-findings');
const { verifyCoverage } = require('../scripts/validate-coverage');
const { compareAudits } = require('../scripts/reaudit');
const { generateReports } = require('../scripts/report');
const { nowIso } = require('../lib/util');

const VERSION = '0.1.0';

function parseArgs(argv) {
  const args = { _: [], flags: {}, options: {} };
  const OPTION_KEYS = ['scope', 'output', 'framework', 'category', 'severity'];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--deep' || a === '--quick') {
      args.flags[a.slice(2)] = true;
    } else if (a.startsWith('--')) {
      const key = a.slice(2);
      if (OPTION_KEYS.includes(key)) {
        const values = [];
        // support repeated flags: --category x --category y
        while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
          values.push(argv[++i]);
        }
        args.options[key] = args.options[key] ? args.options[key].concat(values) : values;
      } else {
        args.flags[key] = true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function readJsonSafe(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (_e) {
    return null;
  }
}

function writeJson(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n');
}

function cmdRecon(args) {
  const target = path.resolve(args._[0] || '.');
  if (!fs.existsSync(target)) {
    console.error(`Target does not exist: ${target}`);
    process.exit(2);
  }
  const stack = detectStack(target);
  const outDir = path.resolve(args.options.output && args.options.output[0] || '.audit');
  writeJson(path.join(outDir, 'stack.json'), stack);

  const plan = buildPlan(stack, {
    quick: args.flags.quick,
    deep: args.flags.deep,
    category: args.options.category,
  });
  plan.framework_filter = args.options.framework && args.options.framework[0];
  writeJson(path.join(outDir, 'audit-plan.json'), plan);

  console.log(`Recon complete for ${target}`);
  console.log(`  languages:      ${stack.summary.primaryLanguages.join(', ') || 'none detected'}`);
  console.log(`  frameworks:     ${[...new Set(stack.frameworks.map((f) => f.name))].join(', ') || 'none detected'}`);
  console.log(`  plan:           ${plan.selected_categories.length} categories selected`);
  console.log(`  artifacts:      ${path.join(outDir, 'stack.json')}, ${path.join(outDir, 'audit-plan.json')}`);
}

function cmdAudit(args) {
  const target = path.resolve(args._[0] || '.');
  if (!fs.existsSync(target)) {
    console.error(`Target does not exist: ${target}`);
    process.exit(2);
  }
  const outDir = path.resolve(args.options.output && args.options.output[0] || '.audit');
  fs.mkdirSync(outDir, { recursive: true });

  // Stage 1: recon + plan (deterministic)
  cmdRecon(args);

  // Stage 2: agent instructions
  const stack = readJsonSafe(path.join(outDir, 'stack.json'));
  const plan = readJsonSafe(path.join(outDir, 'audit-plan.json'));
  const instructions = buildRunInstructions(target, outDir, stack, plan, args);
  fs.writeFileSync(path.join(outDir, 'RUN-INSTRUCTIONS.md'), instructions);

  console.log('');
  console.log('Next step (AI-driven):');
  console.log(`  1. Follow ${path.join(outDir, 'RUN-INSTRUCTIONS.md')} — build the threat model,`);
  console.log('     run hunters per category, then adversarially validate each candidate.');
  console.log('  2. Write findings.json and coverage-ledger.json into ' + outDir);
  console.log(`  3. Run: security-audit validate ${outDir} ${target}`);
  console.log(`     then: security-audit report  ${outDir}`);
}

function buildRunInstructions(target, outDir, stack, plan, args) {
  const cats = plan.selected_categories.map((c) => `- ${c} (playbook: agents/${c}.md)`).join('\n');
  const excl = Object.entries(plan.excluded_categories || {})
    .map(([k, v]) => `- ${k}: ${v}`)
    .join('\n') || '- none';
  return `# Audit Run Instructions

Target: \`${target}\`
Artifacts directory: \`${outDir}\`
Mode: ${plan.quick ? 'QUICK' : plan.deep ? 'DEEP' : 'standard'}
Generated: ${nowIso()}

## 1. Threat model (Phase 2 of SKILL.md)

Extend \`${outDir}/stack.json\` into \`${outDir}/threat-model.json\`: trust boundaries,
actor types, entry points. Answer: *what can an untrusted actor control, and which
security-sensitive operations can that input eventually influence?*

## 2. Hunters (Phase 3)

Run one hunting session per selected category:

${cats}

Excluded categories (do not hunt, cite the reason in coverage instead):

${excl}

Each hunter writes candidate findings into \`${outDir}/findings.json\` conforming to
\`schemas/finding.schema.json\`. Rules of evidence are in \`SKILL.md § Evidence\`.
Hunters must NOT validate their own findings.

## 3. Independent validation (Phase 4)

For every candidate, a separate validation pass following
\`validation/finding-validator.md\` must attempt to DISPROVE the finding.
Only candidates that survive get status "confirmed". Log every disproof attempt
in \`validation.attempted_rejections\`.

## 4. Coverage (Phase 5)

Write \`${outDir}/coverage-ledger.json\` per \`schemas/coverage.schema.json\`.
Every selected category appears exactly once with an honest status.

## 5. Deterministic gates (Phase 6)

\`\`\`bash
security-audit validate ${outDir} ${target}
security-audit coverage ${outDir}
security-audit report ${outDir}
\`\`\`

${args.options.scope ? `Scope note: ${args.options.scope.join(' ')}\n` : ''}`;
}

function cmdValidate(args) {
  const outDir = path.resolve(args._[0] || '.audit');
  const target = path.resolve(args._[1] || '.');
  const findingsPath = path.join(outDir, 'findings.json');
  if (!fs.existsSync(findingsPath)) {
    console.error(`No findings.json in ${outDir}. Hunters must write it first (see RUN-INSTRUCTIONS.md).`);
    process.exit(2);
  }
  const result = validateAllFindings(findingsPath, target);
  writeJson(path.join(outDir, 'validation-report.json'), result);

  console.log(`Mechanical validation: ${result.finding_count} finding(s), mode=${result.results[0] ? result.results[0].schema_mode : 'n/a'}`);
  for (const r of result.results) {
    const status = r.ok ? 'OK ' : 'FAIL';
    console.log(`  [${status}] ${r.id} (schema ${r.schema_valid ? 'valid' : 'invalid'})`);
    for (const p of r.schema_errors || []) console.log(`         schema: ${p.path} ${p.message}`);
    for (const p of r.problems) console.log(`         problem: ${p}`);
    for (const w of r.warnings) console.log(`         warning: ${w}`);
  }
  if (result.duplicate_candidates.length) {
    console.log('  Possible duplicates (validator should merge):');
    for (const d of result.duplicate_candidates) {
      console.log(`         ${d.a} ~ ${d.b} (${d.reason})`);
    }
  }
  if (result.possible_pem_leak) {
    console.log('  WARNING: possible unredacted PEM block in findings.json');
  }
  process.exit(result.all_valid ? 0 : 1);
}

function cmdCoverage(args) {
  const outDir = path.resolve(args._[0] || '.audit');
  const ledger = readJsonSafe(path.join(outDir, 'coverage-ledger.json'));
  if (!ledger) {
    console.error(`No coverage-ledger.json in ${outDir}`);
    process.exit(2);
  }
  const plan = readJsonSafe(path.join(outDir, 'audit-plan.json'));
  const result = verifyCoverage(ledger, plan);
  writeJson(path.join(outDir, 'coverage-report.json'), result);
  console.log(`Coverage verification: ${result.ok ? 'PASS' : 'FAIL'}`);
  for (const p of result.problems) console.log(`  problem: ${p}`);
  for (const w of result.warnings) console.log(`  warning: ${w}`);
  process.exit(result.ok ? 0 : 1);
}

function cmdReport(args) {
  const outDir = path.resolve(args._[0] || '.audit');
  const targetIdx = args._[1];
  const res = generateReports(outDir, { targetRoot: targetIdx });
  console.log(`Reports written to ${outDir}:`);
  for (const f of res.written) console.log(`  ${f}`);
}

function cmdReaudit(args) {
  const prev = path.resolve(args._[0]);
  const cur = path.resolve(args._[1]);
  if (!fs.existsSync(prev) || !fs.existsSync(cur)) {
    console.error('Usage: security-audit reaudit <previous-findings.json> <current-findings.json>');
    process.exit(2);
  }
  const result = compareAudits(prev, cur);
  const outDir = path.resolve(args.options.output && args.options.output[0] || '.audit');
  writeJson(path.join(outDir, 'reaudit-report.json'), result);
  const s = result.summary;
  console.log(`Re-audit comparison:`);
  console.log(`  previous findings: ${s.previous_confirmed_or_needs_validation}`);
  console.log(`  resolved (pending re-validation): ${s.resolved}`);
  console.log(`  unchanged:         ${s.unchanged}`);
  console.log(`  new:               ${s.new}`);
  console.log(`  regressions:       ${s.regressions}`);
  console.log(`  details: ${path.join(outDir, 'reaudit-report.json')}`);
  console.log('  NOTE: "resolved" items require re-validation per validation/finding-validator.md before closing.');
}

function main() {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);
  const command = args._[0];

  if (args.flags.version) {
    console.log(VERSION);
    process.exit(0);
  }
  if (!command || args.flags.help) {
    printHelp();
    process.exit(0);
  }

  // shift command off positional list
  args._.shift();

  switch (command) {
    case 'recon': return cmdRecon(args);
    case 'audit': return cmdAudit(args);
    case 'validate': return cmdValidate(args);
    case 'coverage': return cmdCoverage(args);
    case 'report': return cmdReport(args);
    case 'reaudit': return cmdReaudit(args);
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(2);
  }
}

function printHelp() {
  console.log(`security-audit v${VERSION} — general-purpose AI security audit skill

Usage:
  security-audit <command> [args] [options]

Commands:
  recon <target>                     Detect stack and build an adaptive audit plan
  audit <target>                     Full pipeline: recon + plan + run instructions
  validate <outDir> <target>         Mechanically verify findings.json
  coverage <outDir>                  Verify coverage-ledger.json against the plan
  report <outDir> [target]           Render REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md
  reaudit <prev.json> <cur.json>     Compare audits: resolved / new / regressions

Options:
  --scope <note>       Scope annotation recorded in artifacts
  --output <dir>       Artifacts directory (default: .audit)
  --framework <name>   Focus hint passed to hunters
  --category <id>      Restrict to categories (repeatable)
  --severity <level>   Report filter hint
  --quick              Trim to highest-yield categories
  --deep               Instruct hunters to trace second-order flows

Authorized use only: audit repositories you own or are explicitly permitted to test.`);
}

main();
