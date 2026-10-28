---
name: security-api
description: Audit application APIs for broken authorization, unsafe input handling, injection, excessive data exposure, webhook trust failures, and business-logic abuse. Use for API or backend security reviews.
---

# API Security Audit

Perform a focused, evidence-driven review of API and backend entry points. This skill is not a substitute for a full repository audit.

## Workflow

1. Identify route registration, middleware, authentication/session handling, authorization guards, schemas, ORM/database calls, serializers, and webhook handlers.
2. Build a route inventory with method, path, authentication requirement, authorization rule, user-controlled fields, sensitive operations, and tenant/owner boundaries.
3. Trace untrusted input from request parameters, headers, cookies, body, uploaded files, and webhook payloads to database queries, file operations, external requests, and privileged actions.
4. Check object-level and function-level authorization, tenant isolation, mass assignment, validation, injection, pagination/body limits, error leakage, idempotency, rate limiting, and webhook signature/replay controls where applicable.
5. Check controls in shared middleware, database constraints, schemas, service layers, and deployment configuration before treating a suspicious pattern as a finding.
6. Record candidate findings with exact file/line evidence, attacker prerequisites, concrete impact, and a non-destructive reproduction path.
7. Independently attempt to disprove each candidate using `../../validation/finding-validator.md`. Keep unproven leads as `needs_validation`; do not mark them confirmed without evidence.
8. State what was and was not reviewed. Run the core CLI validation when findings are represented in the repository's standard schema.

## References

- Core rules: `../../SKILL.md`
- API playbook: `../../agents/api-security.md`
- Authorization playbook: `../../agents/authorization.md`
- Business logic playbook: `../../agents/business-logic.md`
- Finding schema: `../../schemas/finding.schema.json`
