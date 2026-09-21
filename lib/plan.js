'use strict';

// Adaptive audit-plan generation. Given a detected stack, decide which
// hunter categories apply, how thoroughly, and record the reasoning so the
// coverage ledger can explain every inclusion/exclusion.

const { CATEGORIES, CATEGORY_IDS, QUICK_SET } = require('./categories');

function buildPlan(stack, options) {
  const opts = options || {};
  const summary = stack.summary || {};
  const reasons = [];
  const included = new Set();
  const excluded = {};
  const notes = {};

  // --- Always-on core categories ---
  for (const id of CATEGORY_IDS) {
    if (CATEGORIES[id].weight === 'core') included.add(id);
  }
  reasons.push('Core categories (authentication, authorization, api-security, business-logic, injection, secrets, dependencies) are always audited.');

  // --- Stack-adaptive categories ---
  // setCat takes distinct inclusion and exclusion texts: an excluded category
  // must be told why it is OUT of scope, not why it would have been in scope.
  function setCat(id, applicable, includeReason, excludeReason) {
    if (applicable) {
      included.add(id);
      reasons.push(includeReason);
    } else {
      excluded[id] = excludeReason;
    }
  }

  setCat(
    'client-side',
    summary.hasFrontend || stack.languages.some((l) => l.lang === 'javascript' || l.lang === 'typescript' || l.lang === 'vue' || l.lang === 'svelte'),
    'Frontend/browser code detected; auditing client-side risks (XSS, DOM injection, storage misuse).',
    'No browser/frontend code detected; nothing renders in a browser or persists to client storage.'
  );
  setCat(
    'file-storage',
    summary.hasBackend || hasFramework(stack, 'upload') || hasFramework(stack, 'media') || hasFramework(stack, 'cloud'),
    'Backend or upload/storage capability detected; auditing file handling and object storage.',
    'No backend, upload or object-storage capability detected; nothing reads or writes files on behalf of users.'
  );
  setCat(
    'webhook-security',
    !!summary.hasWebhooks,
    'Webhook endpoints or providers detected; auditing signature verification and replay protection.',
    'No inbound webhooks detected; no third party can push events into the application.'
  );
  setCat(
    'ai-llm-security',
    !!summary.hasAI,
    'AI/LLM integration detected; auditing prompt injection, tool authorization and data exfiltration.',
    'No AI/LLM integration detected; there is no model, prompt or tool-calling surface.'
  );
  setCat(
    'infrastructure',
    !!summary.hasContainer || !!summary.hasCI || stack.infra.cicd.length > 0 || stack.infra.deployment.length > 0,
    'Container/CI/deployment configuration detected; auditing build and deploy security.',
    'No Docker, CI or deployment configuration found; build and deploy surfaces are out of scope for this repo.'
  );
  setCat(
    'configuration',
    true,
    'Configuration and environment handling is audited in every project.',
    '' // never excluded
  );
  setCat(
    'cloud-security',
    !!summary.hasCloud || hasFramework(stack, 'cloud'),
    'Cloud SDK, cloud credentials or deployment platform detected; auditing IAM, storage exposure and managed-service misuse.',
    'No cloud SDKs or deployment platforms detected; no managed-service IAM or storage surface.'
  );
  setCat(
    'cryptography',
    hasFramework(stack, 'auth') || hasFramework(stack, 'payments') || summary.hasAuth ||
      stack.languages.some((l) => ['go', 'rust', 'java', 'csharp'].includes(l.lang)),
    'Auth/payment primitives present or systems language detected; auditing crypto usage.',
    'No auth/payment crypto primitives or systems languages detected; crypto usage is out of scope.'
  );
  const hasPackageManager = stack.packageManagers.length > 0;
  const hasManifest = (stack.manifestFiles || []).length > 0;
  setCat(
    'supply-chain',
    hasPackageManager || hasManifest,
    hasPackageManager
      ? 'Package manager/lockfile present; auditing dependency integrity beyond known CVEs.'
      : 'Dependency manifest without a lockfile; auditing dependency pinning and install scripts.',
    'No package manifest or lockfile found; there is no dependency tree to audit.'
  );
  setCat(
    'resource-exhaustion',
    summary.hasBackend || !!summary.hasAI,
    'Server or AI workload detected; auditing unbounded operations and cost-based denial of service.',
    'No server or AI workload detected; unbounded-operation risk is limited to the client.'
  );

  // --- Quick mode trims to the high-yield core set ---
  let selected;
  if (opts.quick) {
    selected = CATEGORY_IDS.filter((id) => QUICK_SET.has(id));
    reasons.push('--quick: trimmed to the highest-yield core categories.');
  } else {
    selected = CATEGORY_IDS.filter((id) => included.has(id));
  }

  // --- Explicit overrides ---
  if (opts.category && opts.category.length) {
    const wanted = new Set(opts.category);
    selected = CATEGORY_IDS.filter((id) => wanted.has(id));
    reasons.push(`Explicit category selection: ${[...wanted].join(', ')}.`);
  }

  // Deep mode sharpens notes rather than changing selection.
  if (opts.deep) {
    reasons.push('--deep: hunters should trace second-order flows (proxies, queues, workers, stored payloads).');
  }

  return {
    selected_categories: selected,
    excluded_categories: excluded,
    quick: !!opts.quick,
    deep: !!opts.deep,
    notes,
    reasoning: reasons,
  };
}

function hasFramework(stack, kind) {
  return (stack.frameworks || []).some((f) => f.kind === kind);
}

module.exports = { buildPlan };
