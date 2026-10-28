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
    'Do the work.',
    '',
    '## References',
    '`../../../../outside.md`',
    '',
  ].join('\n'));

  const result = spawnSync(process.execPath, [VALIDATOR, '--root', fixture], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /broken or out-of-repository reference/);
  assert.match(result.stderr, /missing authorization or safe-testing guidance/);
  assert.match(result.stderr, /missing finding-validation guidance/);
});
