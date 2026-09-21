'use strict';

// Single source of truth for audit categories, their default applicability
// and their display metadata. The CLI keys off this list when building an
// audit plan; agent playbooks live in agents/<category>.md.

const CATEGORIES = {
  authentication: { agent: 'agents/authentication.md', weight: 'core' },
  authorization: { agent: 'agents/authorization.md', weight: 'core' },
  'api-security': { agent: 'agents/api-security.md', weight: 'core' },
  'business-logic': { agent: 'agents/business-logic.md', weight: 'core' },
  injection: { agent: 'agents/injection.md', weight: 'core' },
  'client-side': { agent: 'agents/client-side.md', weight: 'web' },
  secrets: { agent: 'agents/secrets.md', weight: 'core' },
  dependencies: { agent: 'agents/dependencies.md', weight: 'core' },
  'supply-chain': { agent: 'agents/supply-chain.md', weight: 'extended' },
  'file-storage': { agent: 'agents/file-storage.md', weight: 'web' },
  cryptography: { agent: 'agents/cryptography.md', weight: 'extended' },
  infrastructure: { agent: 'agents/infrastructure.md', weight: 'extended' },
  configuration: { agent: 'agents/configuration.md', weight: 'extended' },
  'cloud-security': { agent: 'agents/cloud-security.md', weight: 'extended' },
  'webhook-security': { agent: 'agents/webhook-security.md', weight: 'web' },
  'ai-llm-security': { agent: 'agents/ai-llm-security.md', weight: 'web' },
  'resource-exhaustion': { agent: 'agents/resource-exhaustion.md', weight: 'extended' },
};

const CATEGORY_IDS = Object.keys(CATEGORIES);

// Categories that stay in the plan when --quick trims it.
const QUICK_SET = new Set([
  'authorization',
  'injection',
  'secrets',
  'authentication',
  'api-security',
  'dependencies',
]);

function isCategory(id) {
  return Object.prototype.hasOwnProperty.call(CATEGORIES, id);
}

module.exports = { CATEGORIES, CATEGORY_IDS, QUICK_SET, isCategory };
