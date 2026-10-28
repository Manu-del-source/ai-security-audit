'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

test('modular agent skills have valid metadata and resolvable local references', () => {
  const output = execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'validate-skills.js')], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.match(output, /Skill validation passed: 5 modular skills checked\./);
});
