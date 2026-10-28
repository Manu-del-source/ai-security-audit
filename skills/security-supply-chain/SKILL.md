---
name: security-supply-chain
description: Review dependency and software supply-chain risks including lockfile integrity, dependency confusion, install scripts, vulnerable packages, CI permissions, untrusted build inputs, and release provenance. Use for dependency or build pipeline security reviews.
---

# Software Supply-Chain Security Audit

Review the path from dependency declaration to build and release. A package warning alone is not proof of an exploitable vulnerability.

## Workflow

1. Inventory package manifests, lockfiles, package registries, install scripts, build scripts, CI workflows, release automation, container definitions, and deployment configuration.
2. Check whether lockfiles are committed and consistent, versions are pinned appropriately, registries are trusted, lifecycle scripts run with unnecessary privileges, and dependency updates are reviewed.
3. Inspect CI triggers and permissions, pull-request trust boundaries, token scopes, secret availability to forked/untrusted code, artifact handling, cache keys, and release/tag protection.
4. Assess known advisories using available local audit tools when configured. Record package, affected range, installed version, advisory source, reachability/context, and remediation. Do not invent current CVE status if no advisory data was checked.
5. Trace untrusted build inputs into scripts, shell commands, artifact publication, or deployment credentials. Prefer static review and safe local tests.
6. Separate confirmed weaknesses from general hardening advice and ecosystem warnings. Avoid installing or executing untrusted packages just to investigate them.
7. Independently validate candidates, redact credentials, and state whether dependency resolution and advisory databases were actually checked.

## References

- Core workflow: `../../SKILL.md`
- Supply-chain playbook: `../../agents/supply-chain.md`
- Dependency playbook: `../../agents/dependencies.md`
- Infrastructure playbook: `../../agents/infrastructure.md`
- AI-specific supply-chain checks: `../../rules/ai.md`
