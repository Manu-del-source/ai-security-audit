'use strict';

// Shared helpers: repo walking, line-range verification, secret redaction.
// Redaction is applied to every string that leaves the audit before it is
// written to findings or reports. High-entropy assignment values, PEM blocks,
// connection strings with credentials and long hex/base64 tokens are masked.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_IGNORES = new Set([
  '.git', 'node_modules', 'vendor', 'dist', 'build', 'out', 'coverage',
  '__pycache__', '.venv', 'venv', '.tox', 'target', '.next', '.nuxt',
  '.turbo', '.cache', '.parcel-cache', 'bower_components', '.gradle',
  '.idea', '.vscode', '.terraform', '.serverless', '.pytest_cache',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff',
  '.pdf', '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.jar',
  '.war', '.class', '.exe', '.dll', '.so', '.dylib', '.a', '.o', '.bin',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4', '.mov',
  '.avi', '.mkv', '.sqlite', '.db', '.pdb', '.wasm', '.node', '.pyc',
]);

function shouldIgnore(name, extraIgnores) {
  if (DEFAULT_IGNORES.has(name)) return true;
  if (extraIgnores && extraIgnores.has(name)) return true;
  if (name.endsWith('.min.js') || name.endsWith('.min.css')) return true;
  return false;
}

function isBinaryFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return true;
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(1024);
    const bytes = fs.readSync(fd, buf, 0, 1024, 0);
    fs.closeSync(fd);
    for (let i = 0; i < bytes; i++) {
      if (buf[i] === 0) return true;
    }
  } catch (_e) {
    return true;
  }
  return false;
}

// Recursively list readable text files under root, honoring .gitignore-ish
// conventions conservatively (name-based only; we do not parse gitignore
// globs — the AI agent can extend the walk itself when needed).
function walkFiles(root, extraIgnores, maxFiles) {
  const limit = maxFiles || 20000;
  const out = [];
  const stack = [root];
  while (stack.length && out.length < limit) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_e) {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (shouldIgnore(entry.name, extraIgnores)) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) {
        if (!isBinaryFile(full)) out.push(full);
        if (out.length >= limit) break;
      }
    }
  }
  return out.sort();
}

function toRel(root, p) {
  return path.relative(root, p).split(path.sep).join('/');
}

// Verify that path exists and that the 1-indexed line range is plausible
// for the file's actual length. Returns { exists, lineCount, linesInRange }.
function verifyLocation(root, relPath, lines) {
  let rootAbs;
  let abs;
  try {
    // Resolve the trusted target root first, then confine evidence paths to it.
    rootAbs = fs.realpathSync(root);
    abs = path.resolve(rootAbs, relPath);
  } catch (_e) {
    return { exists: false, lineCount: 0, linesInRange: 0 };
  }

  const relativePath = path.relative(rootAbs, abs);
  if (
    !relativePath ||
    relativePath === '..' ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    return { exists: false, lineCount: 0, linesInRange: 0 };
  }

  // Do not follow symlinks while resolving evidence paths. walkFiles() skips
  // symlinks too, so validation must use the same boundary.
  let current = rootAbs;
  for (const segment of relativePath.split(path.sep)) {
    current = path.join(current, segment);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) {
        return { exists: false, lineCount: 0, linesInRange: 0 };
      }
    } catch (_e) {
      return { exists: false, lineCount: 0, linesInRange: 0 };
    }
  }

  let stat;
  try {
    stat = fs.statSync(abs);
  } catch (_e) {
    return { exists: false, lineCount: 0, linesInRange: 0 };
  }
  if (!stat.isFile()) return { exists: false, lineCount: 0, linesInRange: 0 };
  let content;
  try {
    content = fs.readFileSync(abs, 'utf8');
  } catch (_e) {
    return { exists: true, lineCount: 0, linesInRange: 0 };
  }
  const lineCount = content.split('\\n').length;
  let linesInRange = 0;
  const m = /^(\\d+)(?:-(\\d+))?$/.exec(lines || '');
  if (m) {
    const startLine = parseInt(m[1], 10);
    const endLine = m[2] ? parseInt(m[2], 10) : startLine;
    const clampedStart = Math.max(1, startLine);
    const clampedEnd = Math.min(lineCount, endLine);
    if (clampedEnd >= clampedStart) linesInRange = clampedEnd - clampedStart + 1;
  }
  return { exists: true, lineCount, linesInRange };
}

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------

const REDACTED = '[REDACTED]';

const REDACTION_RULES = [
  // PEM private keys (entire block collapses to the marker)
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: REDACTED },
  // scheme://user:password@host connection strings
  { re: /\b(\w[\w+.-]*):\/\/([^:/\s@]+):([^@/\s]+)@/g, replacement: (_m, scheme, user) => `${scheme}://${user}:${REDACTED}@` },
  // key = value style where the key names a secret
  {
    re: /\b(api[_-]?key|apikey|secret|secret[_-]?key|secret[_-]?token|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|credentials)\b(\s*[:=]\s*)(['"])(?:(?!\3).{8,})\3/gi,
    replacement: (_m, key, sep, quote) => `${key}${sep}${quote}${REDACTED}${quote}`,
  },
  // GitHub tokens
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, replacement: REDACTED },
  // AWS access keys
  { re: /\bAKIA[0-9A-Z]{16}\b/g, replacement: REDACTED },
  // Slack tokens
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, replacement: REDACTED },
  // Google API keys
  { re: /\bAIza[0-9A-Za-z_-]{30,}\b/g, replacement: REDACTED },
  // JWTs (three base64url segments)
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, replacement: REDACTED },
  // Long hex (>= 32) and base64-ish (>= 40) blobs: likely keys
  { re: /\b[a-fA-F0-9]{32,}\b/g, replacement: REDACTED },
  { re: /\b[A-Za-z0-9+/]{40,}={0,2}\b(?![\w+/=]*\/)/g, replacement: REDACTED },
];

function redactString(str) {
  if (typeof str !== 'string') return str;
  let out = str;
  for (const rule of REDACTION_RULES) {
    out = out.replace(rule.re, rule.replacement);
  }
  return out;
}

// High-entropy heuristic used by the secrets hunter as a *signal only*.
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const ch of Object.keys(freq)) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikeSecret(value) {
  if (!value || typeof value !== 'string') return false;
  if (value.length < 16 || value.length > 512) return false;
  // Skip obvious non-secrets: URLs, paths, template placeholders, locales.
  if (/^(https?:\/\/|\/|\.\.?\/|\$\{|%[A-Za-z0-9_]+%|<[a-zA-Z])/.test(value)) return false;
  const entropy = shannonEntropy(value);
  const hasMixedCase = /[a-z]/.test(value) && /[A-Z0-9]/.test(value);
  return entropy >= 3.5 && hasMixedCase;
}

function detectSecretKind(keyName, value) {
  const k = (keyName || '').toLowerCase();
  const v = (value || '').toLowerCase();
  if (/private[_-]?key|BEGIN (RSA |EC |OPENSSH )?PRIVATE/.test(k + ' ' + (value || ''))) return 'private-key';
  if (/aws|akia/.test(k) || /^AKIA/.test(value || '')) return 'aws-credential';
  if (/github|ghp_|gho_/.test(k + ' ' + v)) return 'github-token';
  if (/slack|xox/.test(k + v)) return 'slack-token';
  if (/stripe|sk_live|pk_live/.test(k + v)) return 'payment-credential';
  if (/database|db|postgres|mysql|mongo/.test(k) && /:\/\//.test(value || '')) return 'database-url';
  if (/jwt|session/.test(k)) return 'session-signing-key';
  if (/api|key|token|secret/.test(k)) return 'api-credential';
  return 'unknown-secret';
}

function nowIso() {
  return new Date().toISOString();
}

function fileSha256(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

module.exports = {
  DEFAULT_IGNORES,
  walkFiles,
  toRel,
  verifyLocation,
  redactString,
  looksLikeSecret,
  shannonEntropy,
  detectSecretKind,
  nowIso,
  fileSha256,
  REDACTED,
};
