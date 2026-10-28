'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const VALIDATOR = path.join(ROOT, 'scripts', 'validate-skills.js');

test('modular agent skills have valid metadata, workflow, safety guidance, and resolvable references', () => {
  const output = execFileSync(process.execPath, [VALIDATOR], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.match(output, /Skill validation passed: 5 modular skills checked\./);
});


test('manifest exposes every focused skill with useful discovery triggers and category-specific guidance', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'skills', 'manifest.json'), 'utf8'));
  const catalog = fs.readFileSync(path.join(ROOT, 'skills', 'README.md'), 'utf8');
  const expected = {
    'security-recon': [/trust boundaries/i, /audit-plan\.json/i],
    'security-api': [/authorization/i, /webhook/i],
    'security-ai-llm': [/prompt injection/i, /tenant/i],
    'security-secrets': [/redact/i, /credential/i],
    'security-supply-chain': [/lockfiles?/i, /CI/i],
  };

  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.skills.length, Object.keys(expected).length);
  for (const [name, checks] of Object.entries(expected)) {
    const entry = manifest.skills.find((skill) => skill.name === name);
    assert.ok(entry, `manifest is missing ${name}`);
    assert.equal(entry.path, `skills/${name}/SKILL.md`);
    assert.ok(entry.triggers.length > 0, `${name} needs discovery triggers`);
    assert.ok(catalog.includes(name), `catalog is missing ${name}`);
    const skillText = fs.readFileSync(path.join(ROOT, entry.path), 'utf8');
    for (const check of checks) assert.match(skillText, check, `${name} is missing expected audit guidance ${check}`);
  }
});

test('validator rejects a missing skill entrypoint', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'skills-validator-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  fs.mkdirSync(path.join(fixture, 'skills', 'example-skill'), { recursive: true });

  const result = spawnSync(process.execPath, [VALIDATOR, '--root', fixture], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /example-skill: missing SKILL.md/);
});

test('validator rejects broken or out-of-repository references and missing safety checks', (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'skills-validator-'));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  const skillDir = path.join(fixture, 'skills', 'example-skill');
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'SKILL.md'), [
    '---',
    'name: example-skill',
    'description: A test skill with a sufficiently descriptive summary for validation.',
    '---',
    '',
    '# Example',
    '',
    '## Workflow',
    'Inspect the example workflow.',
    '',
    '## References',
    '`../../../../outside.md`',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(fixture, 'skills', 'manifest.json'), JSON.stringify({ schema_version: 1, skills: [{ name: 'example-skill', path: 'skills/example-skill/SKILL.md', focus: 'Example skill used to test validator rejection behavior.', triggers: ['test validator'] }] }));
  fs.writeFileSync(path.join(fixture, 'skills', 'README.md'), '# Skills catalog\n\n`example-skill`\n');

  const result = spawnSync(process.execPath, [VALIDATOR, '--root', fixture], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /broken or out-of-repository reference/);
  assert.match(result.stderr, /missing authorization or safe-testing guidance/);
  assert.match(result.stderr, /missing finding-validation guidance/);
});
