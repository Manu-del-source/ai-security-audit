# Needs Validation

These candidates have concrete evidence but could not be fully confirmed or
refuted during this audit. **They are leads, not vulnerabilities.** Common
reasons: exploitation depends on runtime state, production configuration, an
external service's behavior, or domain knowledge the auditor lacks.

For each item, the fastest path to a verdict is listed. A finding leaves this
list only when someone either (a) demonstrates the attack path in a controlled
environment, or (b) identifies the missing control that disproves it.

{{#EACH_ITEM}}

---

## {{ID}} — {{TITLE}}

| Field | Value |
|---|---|
| Severity (provisional) | {{SEVERITY}} |
| Confidence | {{CONFIDENCE}} |
| Category | {{CATEGORY}} |
| Status | {{STATUS}} |
| Location | {{LOCATIONS}} |

### What the evidence shows

{{EVIDENCE_LIST}}

### Why it could not be resolved

{{OPEN_QUESTIONS}}

### Fastest path to a verdict

{{NEXT_STEPS}}

{{/EACH_ITEM}}

{{^EACH_ITEM}}
_No unresolved candidates._
{{/EACH_ITEM}}
