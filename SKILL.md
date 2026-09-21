---
name: ai-security-audit
description: >
  General-purpose, evidence-driven security audit of a software repository.
  Reconnaissance and stack detection, trust-boundary mapping, adaptive audit
  planning, per-category hunting, independent adversarial validation, a
  coverage ledger, structured findings (JSON-schema validated) and markdown
  reports, plus re-audit support. Use when asked to "audit the security of
  this repo/project/application", "find vulnerabilities", "review this code
  from a security perspective", or before a release when a security review
  is requested. Authorized security testing only.
---

# AI Security Audit

You are running a multi-phase security audit on a repository. Your product is
**evidence**, not vulnerability count. A report with zero confirmed findings is
a fine outcome if the audit was genuine. Every finding you file must survive an
adversarial validator whose only job is to disprove it.

**Prime directive:** never classify code as a confirmed vulnerability merely
because it looks suspicious. Suspicion starts a candidate; evidence and
independent validation make it confirmed.

**Safety:** this skill is for authorized security testing of repositories you
own or are permitted to test. Never attack systems outside the target, never
exfiltrate real secrets or user data, prefer static analysis and local,
non-destructive PoCs. Redact every secret in every artifact.

## Phase 0 — Setup

```bash
security-audit audit <target> --output .audit
```

This writes `.audit/stack.json`, `.audit/audit-plan.json` and
`.audit/RUN-INSTRUCTIONS.md`. If the CLI is unavailable, run the phases
manually; the plan builder logic is described in `lib/plan.js` and the
categories in `lib/categories.js`.

Artifacts live in the output directory:

| File | Written by | Purpose |
|---|---|---|
| `stack.json` | recon script | Detected languages, frameworks, infra |
| `audit-plan.json` | recon script | Selected/excluded categories + reasons |
| `threat-model.json` | audit agent | Trust boundaries and entry points (Phase 2) |
| `findings.json` | hunters + validator | All findings in all statuses |
| `coverage-ledger.json` | audit agent | What was examined, honestly |
| `validation-report.json` | CLI | Mechanical validation results |
| `REPORT.md` etc. | CLI | Human-readable reports |

## Phase 1 — Reconnaissance (done, verify it)

Read `stack.json` and sanity-check it against the repository. The detector is
heuristic: if it missed a framework you can see (e.g. a Django app detected
only as "python"), note it in `threat-model.json` and adjust the plan.
Do not assume the stack; verify with your own eyes on key files
(`package.json`, `requirements.txt`, route definitions, `Dockerfile`).

## Phase 2 — Architecture, trust boundaries, threat model

Write `.audit/threat-model.json` with this structure:

```json
{
  "architecture_summary": "…",
  "actors": [
    { "name": "anonymous", "can_control": "…", "cannot": "…" },
    { "name": "authenticated-user", "can_control": "…", "cannot": "…" },
    { "name": "admin", "can_control": "…", "cannot": "…" }
  ],
  "trust_boundaries": [
    { "name": "browser → server", "crossings": ["HTTP request body", "headers", "cookies"] },
    { "name": "server → database", "crossings": ["parameterized queries"] },
    { "name": "external-service → server", "crossings": ["webhook POST /api/webhooks/stripe"] }
  ],
  "entry_points": [
    { "location": "src/routes/*.ts", "kind": "http", "auth": "session cookie", "notes": "…" }
  ],
  "domain": "e-commerce | saas | api | agent | cli | library | …",
  "key_questions": [
    "What can an untrusted actor control?",
    "What security-sensitive operation can that input eventually influence?"
  ]
}
```

The two `key_questions` drive every hunt. Every candidate finding must be able
to answer both, concretely, with file/line evidence.

## Phase 3 — Adaptive hunting

For each **selected** category in `audit-plan.json`, run a hunting session
following the playbook in `agents/<category>.md`. The playbooks contain:
what to look for, where to look for this category, evidence requirements,
and explicit false-positive traps for that category.

Hard rules for hunters:

1. **Threat model first.** Before filing anything, state who the attacker is,
   what they control, and which boundary they cross. If you cannot state it,
   you do not have a finding — you have a code-style note.
2. **Trace the flow.** A finding must connect untrusted input to a
   security-sensitive operation through real code. Record the chain as
   `data_flow` steps with file:line at each hop.
3. **No category-name findings.** "The auth may be flawed" is banned. Name the
   exact weakness: e.g. "PUT /api/users/:id accepts `role` from the request
   body and persists it without an admin check".
4. **Check the control before claiming it is missing.** Middleware, guards,
   ORM layers, route-level wrappers, and deploy config can all neutralize a
   pattern that looks dangerous in isolation. If a control exists, the
   pattern is not a finding.
5. **Hunt, do not reformat.** You are attacking the code, not reviewing style.
   But you file only what crosses a trust boundary.
6. **Respect scope.** Files that are examples, tests, fixtures, or docs are
   out of scope unless they ship to production. Note them in coverage instead.
7. **One root cause, one finding.** If three routes share the same missing
   guard, file one finding listing all three; do not file three.

## Phase 4 — Independent validation

Validation is a **separate pass from hunting**, ideally a separate agent
session with fresh context. Give the validator: the candidate finding, the
cited source excerpts, and the threat model — but not the hunter's reasoning.
The validator's protocol is in `validation/finding-validator.md`; supporting
material in `validation/exploitability.md` and `validation/false-positive-analysis.md`.

The validator's job is to **disprove** each candidate:

- Is the attack path real end-to-end, through actual code?
- Can the stated attacker actually reach the entry point?
- Is the attacker genuinely untrusted at that boundary?
- Is the control truly missing, or just elsewhere (middleware, DB constraint, deploy config)?
- Is the impact real for this application's domain?

Outcomes: `CONFIRMED` (status → confirmed), `NEEDS_VALIDATION` (real-looking
but unproven — e.g. needs runtime access), `REJECTED` (disproven; keep it in
findings.json with the rejection reason).

A validator may never file new findings. If it spots something new, it writes
a new *candidate* and the pipeline validates that separately.

## Phase 5 — Coverage ledger

Write `.audit/coverage-ledger.json` per `schemas/coverage.schema.json`.
Every category selected in the plan appears **exactly once**, with an honest
status: `complete`, `partial`, `not_applicable`, `blocked`, or
`needs_validation`. `partial` and `blocked` entries **must** list specific
gaps ("did not examine the legacy `/admin` routes; they are behind VPN
per deploy config"). Counts (`files_examined`, `routes_examined`) should be
real counts, not guesses.

## Phase 6 — Deterministic gates

```bash
security-audit validate .audit <target>   # schema + evidence + redaction checks
security-audit coverage .audit            # plan-vs-ledger consistency
security-audit report .audit              # renders REPORT.md + detail files
```

`validate` fails on: schema violations, cited files/lines that do not exist,
confirmed findings without severity reasoning or rejection attempts, and
probable unredacted secrets. Fix findings until the gates pass. Do not edit
the schemas to make failing findings pass.

## Phase 7 — Reporting and handoff

The CLI renders `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`.
Present the executive summary to the user: target, stack, coverage, confirmed
findings, unresolved leads, limitations, remediation priorities. Never hide
uncertainty; `NEEDS-VALIDATION.md` exists precisely to carry it.

## Re-audits

After fixes are applied, re-run:

```bash
security-audit audit <target> --output .audit-2
# …hunt + validate again into .audit-2/findings.json …
security-audit reaudit .audit/findings.json .audit-2/findings.json
```

Classification rules:

- **resolved** — only when the new audit's validator actively re-examined the
  old finding against current code and found the control present. A code
  change near the finding is *not* sufficient; revalidate, then resolve.
- **regression** — a previously rejected finding re-confirmed now.
- **unchanged / new** — self-explanatory; the diff in `reaudit-report.json`
  records each unchanged finding's `previous_id` lineage, and per the schema a
  finding may carry a `reaudit` object linking it back to its predecessor.

## Evidence standard (applies to every hunter)

Every finding must contain: exact file(s) and line(s); the affected
function/route/component; the attacker-controlled input; the trust boundary
crossed; the vulnerable operation; the control that should exist; the control
that is actually missing/broken; concrete impact; and a reproduction path
(static reasoning or non-destructive local test). If any element is missing,
the finding is not ready — mark it `needs_validation` with what is missing,
or drop it.

## Severity discipline

Severity is computed from: exploitability, required privileges, attack
complexity, affected assets, C-I-A impact, and blast radius — **not** from the
category name. An XSS in an admin-only page is not automatically "high".
Document the reasoning in `severity_reasoning`; the mechanical gate enforces
its presence on confirmed findings. Do not manufacture severity from thin
evidence; when in doubt, lower severity and raise the validation bar.

## Anti-goals

- Do not inflate the finding count to look thorough.
- Do not file "hardening suggestions" as vulnerabilities (use `informational`
  severity sparingly, with evidence).
- Do not chain hypothetical exploits through code that does not exist.
- Do not edit schemas or the CLI to accept invalid findings.
- Do not run destructive commands against the target or anything else.
