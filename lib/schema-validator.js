'use strict';

// Schema validation with two modes:
//   1. ajv (optional dependency) when installed — full JSON Schema draft-07.
//   2. a built-in structural fallback so the skill still works when ajv is
//      unavailable (offline installs, minimal environments).
// Both modes must REJECT clearly invalid findings. The fallback checks the
// same required fields, enums, types and minimum lengths; it is stricter
// about structure and does not attempt full draft-07 semantics.

const fs = require('fs');
const path = require('path');

const SCHEMA_DIR = path.join(__dirname, '..', 'schemas');
const SCHEMAS = {
  finding: 'finding.schema.json',
  coverage: 'coverage.schema.json',
  audit: 'audit.schema.json',
};

let ajvInstance = null;
let ajvTried = false;

function getAjv() {
  if (ajvTried) return ajvInstance;
  ajvTried = true;
  try {
    // Optional dependency; may be absent.
    const Ajv = require('ajv');
    const AjvFormats = tryRequire('ajv-formats');
    const ajv = new Ajv({ allErrors: true, strict: false });
    if (AjvFormats) ajv.addFormat('date-time', true);
    ajvInstance = ajv;
  } catch (_e) {
    ajvInstance = null;
  }
  return ajvInstance;
}

function tryRequire(name) {
  try {
    return require(name);
  } catch (_e) {
    return null;
  }
}

function loadSchema(name) {
  const file = SCHEMAS[name];
  if (!file) throw new Error(`Unknown schema: ${name}`);
  return JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, file), 'utf8'));
}

// ---------------------------------------------------------------------------
// Built-in fallback validation
// ---------------------------------------------------------------------------

const FINDING_REQUIRED = [
  'id', 'title', 'severity', 'status', 'category',
  'confidence', 'affected_files', 'attack_surface', 'attacker', 'evidence', 'impact',
];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const STATUSES = ['candidate', 'confirmed', 'needs_validation', 'rejected'];
const CONFIDENCES = ['high', 'medium', 'low'];

function fail(errors, pathStr, message) {
  errors.push({ path: pathStr, message });
}

function checkFindingFallback(f, errors) {
  for (const key of FINDING_REQUIRED) {
    if (f[key] === undefined) fail(errors, `/${key}`, 'is required');
  }
  if (errors.length) return;

  if (typeof f.id !== 'string' || !/^ASA-[A-Z0-9]{2,8}-[0-9]{3}$/.test(f.id)) {
    fail(errors, '/id', 'must match ^ASA-[A-Z0-9]{2,8}-[0-9]{3}$');
  }
  if (typeof f.title !== 'string' || f.title.length < 10) {
    fail(errors, '/title', 'must be a string of at least 10 characters');
  }
  if (!SEVERITIES.includes(f.severity)) fail(errors, '/severity', `must be one of ${SEVERITIES.join('|')}`);
  if (!STATUSES.includes(f.status)) fail(errors, '/status', `must be one of ${STATUSES.join('|')}`);
  if (!CONFIDENCES.includes(f.confidence)) fail(errors, '/confidence', `must be one of ${CONFIDENCES.join('|')}`);
  if (typeof f.category !== 'string' || f.category.length < 3) {
    fail(errors, '/category', 'must be a non-empty category string');
  }

  if (!Array.isArray(f.affected_files) || f.affected_files.length === 0) {
    fail(errors, '/affected_files', 'must be a non-empty array');
  } else {
    f.affected_files.forEach((af, i) => {
      const p = `/affected_files/${i}`;
      if (typeof af !== 'object' || af === null) return fail(errors, p, 'must be an object');
      if (typeof af.path !== 'string' || !af.path) fail(errors, `${p}/path`, 'must be a non-empty string');
      if (typeof af.lines !== 'string' || !/^[0-9]+(-[0-9]+)?$/.test(af.lines)) {
        fail(errors, `${p}/lines`, "must be a string like '42' or '42-58'");
      }
    });
  }

  if (typeof f.attack_surface !== 'string' || f.attack_surface.length < 5) {
    fail(errors, '/attack_surface', 'must describe the reachable entry point (min 5 chars)');
  }
  if (typeof f.attacker !== 'string' || f.attacker.length < 20) {
    fail(errors, '/attacker', 'must be a concrete threat model (min 20 chars): who, what they control, what they are not');
  }
  if (!Array.isArray(f.evidence) || f.evidence.length === 0) {
    fail(errors, '/evidence', 'must be a non-empty array');
  } else {
    f.evidence.forEach((ev, i) => {
      const p = `/evidence/${i}`;
      if (typeof ev !== 'object' || ev === null) return fail(errors, p, 'must be an object');
      if (typeof ev.source !== 'string' || !ev.source) fail(errors, `${p}/source`, 'must be a non-empty string');
      if (typeof ev.detail !== 'string' || ev.detail.length < 10) {
        fail(errors, `${p}/detail`, 'must be a specific description (min 10 chars)');
      }
    });
  }
  if (typeof f.impact !== 'string' || f.impact.length < 15) {
    fail(errors, '/impact', 'must describe concrete impact (min 15 chars)');
  }
}

function checkCoverageFallback(c, errors) {
  for (const key of ['version', 'generated_at', 'target', 'categories']) {
    if (c[key] === undefined) fail(errors, `/${key}`, 'is required');
  }
  if (errors.length) return;
  if (!Array.isArray(c.categories) || c.categories.length === 0) {
    fail(errors, '/categories', 'must be a non-empty array');
    return;
  }
  c.categories.forEach((cat, i) => {
    const p = `/categories/${i}`;
    if (typeof cat !== 'object' || cat === null) return fail(errors, p, 'must be an object');
    if (typeof cat.category !== 'string' || !cat.category) fail(errors, `${p}/category`, 'is required');
    const STATUSES_C = ['complete', 'partial', 'not_applicable', 'blocked', 'needs_validation'];
    if (!STATUSES_C.includes(cat.status)) fail(errors, `${p}/status`, `must be one of ${STATUSES_C.join('|')}`);
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function validate(data, type) {
  const ajv = getAjv();
  if (ajv) {
    try {
      const schema = loadSchema(type);
      if (type === 'audit') {
        // audit.schema.json $refs its sibling schemas by relative path.
        // Register them by their $id so ajv resolves the refs offline.
        ajv.addSchema(loadSchema('finding'));
        ajv.addSchema(loadSchema('coverage'));
      }
      const validateFn = ajv.compile(schema);
      const ok = validateFn(data);
      if (ok) return { valid: true, errors: [], mode: 'ajv' };
      return {
        valid: false,
        mode: 'ajv',
        errors: validateFn.errors.map((e) => ({
          path: e.instancePath || '/',
          message: e.message || 'invalid',
        })),
      };
    } catch (_e) {
      // ajv path failed (unresolvable refs, bad schema...). Fall through to
      // the built-in validator — validation must never silently pass.
    }
  }

  const errors = [];
  if (type === 'finding') checkFindingFallback(data, errors);
  else if (type === 'coverage') checkCoverageFallback(data, errors);
  else if (type === 'audit') {
    const covErrors = [];
    checkCoverageFallback(data.coverage || {}, covErrors);
    covErrors.forEach((e) => errors.push({ ...e, path: `/coverage${e.path}` }));
    (data.findings || []).forEach((f, i) => {
      const fErrors = [];
      checkFindingFallback(f, fErrors);
      fErrors.forEach((e) => errors.push({ ...e, path: `/findings/${i}${e.path}` }));
    });
  } else {
    throw new Error(`Unknown schema type: ${type}`);
  }
  return { valid: errors.length === 0, errors, mode: 'fallback' };
}

function validateFindings(findings) {
  const results = [];
  for (const f of findings || []) {
    const r = validate(f, 'finding');
    results.push({ id: f && f.id ? f.id : '(missing id)', valid: r.valid, errors: r.errors, mode: r.mode });
  }
  return results;
}

module.exports = { validate, validateFindings, loadSchema };
