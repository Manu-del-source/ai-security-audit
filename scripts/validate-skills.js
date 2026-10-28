#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function parseArgs(argv) {
  let root = path.resolve(__dirname, '..');
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--root') {
      if (!argv[index + 1]) throw new Error('--root requires a directory path');
      root = path.resolve(argv[++index]);
    } else {
      throw new Error(`Unknown argument: ${argv[index]}`);
    }
  }
  return root;
}

let ROOT;
try {
  ROOT = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  process.exit(2);
}

const SKILLS_DIR = path.join(ROOT, 'skills');
const errors = [];
const skillDirs = fs.existsSync(SKILLS_DIR)
  ? fs.readdirSync(SKILLS_DIR, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()
  : [];

if (skillDirs.length === 0) errors.push('No skill directories found under skills/.');

for (const dir of skillDirs) {
  const skillFile = path.join(SKILLS_DIR, dir, 'SKILL.md');
  if (!fs.existsSync(skillFile)) {
    errors.push(`${dir}: missing SKILL.md`);
    continue;
  }

  const content = fs.readFileSync(skillFile, 'utf8');
  const frontmatter = content.match(/^---\\r?\\n([\\s\\S]*?)\\r?\\n---(?:\\r?\\n|$)/);
  if (!frontmatter) {
    errors.push(`${dir}: missing YAML frontmatter`);
    continue;
  }

  const name = frontmatter[1].match(/^name:\\s*([^\\r\\n]+)\\s*$/m)?.[1]?.trim();
  const description = frontmatter[1].match(/^description:\\s*([\\s\\S]*?)(?=^[A-Za-z_][\\w-]*:\\s*|\\s*$)/m)?.[1]?.trim();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(dir)) errors.push(`${dir}: directory name must be lowercase kebab-case`);
  if (name !== dir) errors.push(`${dir}: frontmatter name must match directory (got ${name || 'missing'})`);
  if (!description || description.length < 20 || description.length > 1024) {
    errors.push(`${dir}: description must contain 20–1024 characters`);
  }
  if (!/^## Workflow\\s*$/m.test(content)) errors.push(`${dir}: missing ## Workflow section`);
  if (!/^## References\\s*$/m.test(content)) errors.push(`${dir}: missing ## References section`);
  if (!/authorized|scope|non-destructive/i.test(content)) errors.push(`${dir}: missing authorization or safe-testing guidance`);
  if (!/validat|disprov|false positive|candidate/i.test(content)) errors.push(`${dir}: missing finding-validation guidance`);

  // Validate repository-relative paths explicitly referenced as inline code.
  const refs = [...content.matchAll(/`(\\.\\.\\/\\.\\.\\/[^ `]+)`/g)].map((match) => match[1]);
  for (const ref of refs) {
    const fileRef = ref.split('#')[0];
    const resolved = path.resolve(path.dirname(skillFile), fileRef);
    const relative = path.relative(ROOT, resolved);
    if (relative.startsWith('..' + path.sep) || relative === '..' || path.isAbsolute(relative) || !fs.existsSync(resolved)) {
      errors.push(`${dir}: broken or out-of-repository reference ${ref}`);
    }
  }
}

if (errors.length) {
  console.error('Skill validation failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Skill validation passed: ${skillDirs.length} modular skills checked.`);
