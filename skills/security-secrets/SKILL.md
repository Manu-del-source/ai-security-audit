---
name: security-secrets
description: Audit a repository for exposed credentials, unsafe secret storage, accidental secret logging, environment/configuration mistakes, and credential leakage in generated reports. Use for secret-scanning and secret-management reviews.
---

# Secrets Security Audit

Focus on whether credentials can be exposed, misused, committed, logged, or included in audit artifacts. Do not reveal discovered secret values.

## Workflow

1. Inspect repository history and current tracked files where authorized, including source, configuration, examples, CI workflows, build artifacts, logs, and documentation. Avoid dumping secret values into terminal output or chat.
2. Distinguish actual credential candidates from placeholders, examples, public identifiers, and test fixtures. Confirm context and whether the value is tracked or reachable.
3. Review environment variable handling, secret-manager integration, client/server boundaries, debug endpoints, error reporting, logging, CI permissions, and generated audit reports.
4. Never authenticate with a discovered credential, test it against a live service, or transmit it elsewhere. Report only the file/line, secret type, exposure context, and safe remediation; redact the value.
5. Recommend revocation/rotation for likely live credentials, followed by history cleanup only where appropriate and coordinated with repository owners.
6. Review report artifacts for accidental secret leakage and make sure redaction happens before display or persistence.
7. Record false positives and scope limitations. Treat a match as a candidate until its context and exposure are verified.

## References

- Core evidence standard: `../../SKILL.md`
- Secrets playbook: `../../agents/secrets.md`
- Configuration playbook: `../../agents/configuration.md`
- Redaction utilities: `../../lib/util.js`
- Validation scripts: `../../scripts/validate-findings.js`
