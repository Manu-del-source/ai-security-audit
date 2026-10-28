# Modular security skills

This directory exposes focused, discoverable entrypoints for common audit tasks. Each folder contains an Agent Skills-compatible `SKILL.md`. Use the core repository skill for full audits; use a focused skill when the task is deliberately limited.

## Available skills

For agent tooling and automated discovery, use [`manifest.json`](manifest.json), which records each skill's entrypoint, focus, and example trigger phrases. The manifest is validated against the actual skill directories and this catalog in CI.

| Skill | Use when | Existing playbooks |
|---|---|---|
| `security-recon` | Establish project scope, stack, trust boundaries, and audit plan | `agents/reconnaissance.md`, `lib/plan.js` |
| `security-api` | Review API routes, authorization, validation, and business logic | `agents/api-security.md`, `agents/authorization.md`, `agents/business-logic.md` |
| `security-ai-llm` | Review model integrations, prompts, retrieval, and tool execution | `agents/ai-llm-security.md`, `agents/injection.md`, `rules/ai.md` |
| `security-secrets` | Find and safely report credential exposure and secret-handling flaws | `agents/secrets.md`, `agents/configuration.md` |
| `security-supply-chain` | Review dependency integrity, install lifecycle scripts, and build provenance | `agents/supply-chain.md`, `agents/dependencies.md`, `agents/infrastructure.md` |

## Installation and use

Install or clone the **entire repository** into your agent's skills directory so shared playbooks, schemas, rules, and CLI files remain available. See the root [README](../README.md#install) for agent-specific locations.

Ask your coding agent to use a focused skill by name, for example: `Use the security-ai-llm skill to audit this repository's LLM integration.`

## Shared quality bar

Focused skills inherit the core project's rules:

- Audit only systems and repositories the user is authorized to test.
- Prefer static analysis and non-destructive local validation.
- Treat suspicious patterns as candidates, not confirmed vulnerabilities.
- Cite exact file and line evidence and trace input to sensitive operation.
- Check existing controls and record limitations.
- Redact secrets; never include live credentials in reports.
- Do not claim comprehensive coverage when files or checks were skipped.

Focused audits should clearly state their scope and must not imply that unexamined categories were audited.
