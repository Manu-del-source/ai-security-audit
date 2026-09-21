# Security Audit Report

- **Target:** `{{TARGET}}`
- **Audit date:** {{DATE}}
- **Audit ID:** {{AUDIT_ID}}
- **Detected stack:** {{STACK_SUMMARY}}
- **Scope:** {{SCOPE}}
- **Auditor:** AI security audit (skill v{{VERSION}}), validated per independent-validation protocol

## Executive summary

{{#CONFIRMED_COUNT}}
**{{CONFIRMED_COUNT}} confirmed finding(s)** — {{CRITICAL_COUNT}} critical, {{HIGH_COUNT}} high, {{OTHER_COUNT}} medium/low.
{{/CONFIRMED_COUNT}}
{{^CONFIRMED_COUNT}}
**No confirmed vulnerabilities.** Note: this statement is only meaningful for
categories whose coverage status is `complete`. Categories marked `partial`,
`blocked` or `needs_validation` were not fully audited and may still contain
vulnerabilities.
{{/CONFIRMED_COUNT}}

Unresolved candidates: {{NEEDS_VALIDATION_COUNT}} (see `NEEDS-VALIDATION.md`).
Rejected candidates kept for transparency: {{REJECTED_COUNT}}.

## Detected stack

{{STACK_TABLE}}

## Coverage

{{COVERAGE_TABLE}}

### Coverage gaps

{{COVERAGE_GAPS}}

## Confirmed findings

{{CONFIRMED_TABLE}}

## Remediation priorities

{{REMEDIATION_PRIORITIES}}

## Limitations

- Static, AI-assisted review; no completeness guarantee.
- Runtime behavior, external services and production configuration were not exercised unless noted.
- `needs_validation` items are evidence-backed hypotheses, not confirmed exploits.
- The audit reflects the code at commit `{{COMMIT}}`; later changes are not covered.

## Method

1. Reconnaissance and stack detection (`stack.json`).
2. Trust-boundary mapping and threat model (`threat-model.json`).
3. Adaptive plan (`audit-plan.json`) — selected/excluded categories with reasons.
4. Per-category hunting per playbooks in `agents/`.
5. Independent adversarial validation per `validation/finding-validator.md`.
6. Mechanical gates: schema, evidence-path, redaction checks (`validation-report.json`).
7. Coverage verification (`coverage-report.json`).
