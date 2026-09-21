# ai-security-audit

General-purpose, evidence-driven **AI security audit skill** for arbitrary
software repositories. The system first understands the target, then decides
how to audit it: reconnaissance → trust-boundary mapping → adaptive plan →
specialized hunters → independent adversarial validation → coverage ledger →
structured findings and reports → re-audit.

**Design principle: evidence over speculation.** A suspicious pattern starts a
*candidate*; only an independent validator that failed to disprove it makes it
*confirmed*. A report with zero confirmed findings is a fine outcome if the
audit was genuine — and the coverage ledger always distinguishes "audited,
nothing found" from "not examined".

## What it produces

For a target repository, an audit run writes an artifacts directory
(default `.audit/`) containing:

| Artifact | Source | Purpose |
|---|---|---|
| `stack.json` | recon script | Detected languages, frameworks, databases, auth, infra, webhooks, AI, config |
| `audit-plan.json` | recon script | Selected/excluded audit categories **with reasons** |
| `threat-model.json` | audit agent | Trust boundaries, actors, entry points |
| `findings.json` | hunters + validator | All findings: candidate → confirmed / needs_validation / rejected |
| `coverage-ledger.json` | audit agent | What was actually examined, per category, honestly |
| `validation-report.json` | CLI | Mechanical checks: schema, evidence file/line existence, secret leakage |
| `REPORT.md` / `FINDINGS-DETAIL.md` / `NEEDS-VALIDATION.md` | CLI | Human-readable output, secrets redacted |
| `reaudit-report.json` | CLI | Diff between two audits: resolved / new / regressions |

Findings conform to `schemas/finding.schema.json` (validated with `ajv` when
installed, with a built-in structural fallback otherwise). Confirmed findings
must carry `severity_reasoning` and a log of `validation.attempted_rejections`
— the disproof attempts that failed to kill them.

## Install

```bash
npm install -g .        # exposes the `security-audit` CLI
# or use it in place:
node bin/security-audit.js --help
```

Zero required runtime dependencies; `ajv` is an optional enhancement.

## Usage

```bash
security-audit recon <target>                  # stack detection + adaptive plan
security-audit audit <target>                  # recon + plan + agent run instructions
security-audit validate <outDir> <target>      # mechanical checks on findings.json
security-audit coverage <outDir>               # ledger-vs-plan consistency
security-audit report <outDir> [target]        # render markdown reports
security-audit reaudit <prev.json> <cur.json>  # compare two audits
```

Options: `--output <dir>` `--scope <note>` `--framework <name>`
`--category <id>` (repeatable) `--severity <level>` `--quick` `--deep`.

Example — full pipeline on a local project:

```bash
security-audit audit ~/code/my-app --output .audit
# …the AI agent then follows .audit/RUN-INSTRUCTIONS.md:
#   threat model → hunters per category → adversarial validation →
#   findings.json + coverage-ledger.json …
security-audit validate .audit ~/code/my-app
security-audit coverage .audit
security-audit report .audit
```

After fixes land:

```bash
security-audit audit ~/code/my-app --output .audit-2
# …second hunt + validation pass…
security-audit reaudit .audit/findings.json .audit-2/findings.json
```

A finding is only *resolved* when the new audit's validator actively
re-examined it against current code — a nearby code change never counts as a
fix by itself. Regressions (previously rejected, re-confirmed now) are
reported explicitly.

## How the audit adapts

`scripts/detect-stack.js` classifies the repository: languages, backend and
frontend frameworks, ORMs, caches and queues, auth mechanisms, databases
(including vector DBs), webhooks, AI/LLM integrations, payments, containers,
CI/CD, IaC, serverless targets, env/config files, mobile components.
`lib/plan.js` turns that into a plan: seven categories are always in scope
(authentication, authorization, api-security, business-logic, injection,
secrets, dependencies); the rest are included or excluded based on the
detected stack, each with a recorded reason. `--quick` trims to the
high-yield core; `--deep` instructs hunters to trace second-order flows.

Hunter playbooks (`agents/*.md`) are per-category procedures with evidence
requirements and false-positive traps. Stack rules (`rules/*.md`) add
framework-specific checks (Node, Next.js, React, Python, Django, databases,
cloud, AI) keyed off what recon found.

## Validation and false-positive control

1. **Mechanical gate** (`scripts/validate-findings.js`): schema conformance,
   cited files exist, cited line ranges are in bounds, symbols appear near the
   cited lines, confirmed findings carry severity reasoning + rejection logs,
   secret-like material is flagged, duplicate candidates detected.
2. **Adversarial validator** (`validation/finding-validator.md`): a separate
   pass with fresh context receives the candidate + cited code + threat model
   (never the hunter's reasoning) and tries to **disprove** it: is the path
   real end-to-end, is the attacker genuinely untrusted, is the control really
   missing, is the impact real for this domain? Outcomes: `CONFIRMED`,
   `NEEDS_VALIDATION`, `REJECTED` (kept in findings.json for transparency).

## Test fixtures and false-positive rejection

```bash
npm test        # 40 unit + CLI tests
```

- `tests/fixtures/vulnerable-app/` — deliberately vulnerable Express app with
  planted flaws per category: IDOR, SQL injection, reflected XSS, command
  injection, path traversal, SSRF, negative-quantity business logic, unsigned
  webhook, hardcoded secret, oversized body limit, prompt injection,
  cross-tenant retrieval, unvalidated upload.
- `tests/fixtures/safe-app/` — the *same-looking* patterns with real controls
  (signature verification, allowlisted sort columns, HTML escaping, argument
  arrays instead of shells, canonicalization checks, env-only secrets). A
  correct audit files candidates here and the validator rejects them.

## Extending

- **New category**: add it to `lib/categories.js`, drop a playbook in
  `agents/`, add the enum value to `schemas/finding.schema.json` and
  `schemas/coverage.schema.json`.
- **New stack**: add detection hints in `scripts/detect-stack.js` and a rules
  file in `rules/`.
- **New check**: mechanical checks live in `scripts/validate-findings.js` and
  `scripts/validate-coverage.js`; add tests in `tests/`.

## Safety and authorized use

This skill is for **authorized security testing** of repositories you own or
are explicitly permitted to test. It performs static analysis and describes
non-destructive local reproduction paths; it does not attack third-party
systems. Real secrets discovered during an audit are never reproduced in
reports — every rendered string passes redaction. See `LICENSE` (MIT).

## Layout

```
ai-security-audit/
├── SKILL.md              # agent entrypoint: the phase workflow
├── bin/security-audit.js # CLI
├── lib/                  # categories, plan builder, schema validator, utils
├── scripts/              # detect-stack, validate-findings, validate-coverage, report, reaudit
├── agents/               # 18 hunter/recon playbooks
├── validation/           # adversarial validator protocol
├── schemas/              # finding / coverage / audit JSON Schema
├── rules/                # stack-specific checklists
├── templates/            # report templates
└── tests/                # fixtures + unit/CLI test suites
```
