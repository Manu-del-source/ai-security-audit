#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
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
  const frontmatter = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!frontmatter) {
    errors.push(`${dir}: missing YAML frontmatter`);
    continue;
  }

  const name = frontmatter[1].match(/^name:\s*([^\r\n]+)\s*$/m)?.[1]?.trim();
  const description = frontmatter[1].match(/^description:\s*([\s\S]*?)(?=^[A-Za-z_][\w-]*:\s*|\s*$)/m)?.[1]?.trim();
  if (name !== dir) errors.push(`${dir}: frontmatter name must match directory (got ${name || 'missing'})`);
  if (!description) errors.push(`${dir}: frontmatter description is required`);

  // Local file references written as inline code must resolve within this repo.
  const refs = [...content.matchAll(/`(\.\.\/\.\.\/[^ `]+)`/g)].map((match) => match[1]);
  for (const ref of refs) {
    const fileRef = ref.split('#')[0];
    const resolved = path.resolve(path.dirname(skillFile), fileRef);
    if (!resolved.startsWith(ROOT + path.sep) || !fs.existsSync(resolved)) {
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
