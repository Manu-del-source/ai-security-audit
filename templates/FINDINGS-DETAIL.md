# Findings Detail

Technical detail for confirmed findings. Every item carries a complete threat
model, an evidence chain with file:line, the validator's disproof attempts, and
remediation. Secrets are redacted as `[REDACTED]`.

{{#EACH_FINDING}}

---

## {{ID}} — {{TITLE}}

| Field | Value |
|---|---|
| Severity | {{SEVERITY}} |
| Confidence | {{CONFIDENCE}} |
| Category | {{CATEGORY}} |
| Status | {{STATUS}} |
| Attack surface | {{ATTACK_SURFACE}} |

### Threat model

**Attacker:** {{ATTACKER}}

**Preconditions:**
{{PRECONDITIONS}}

### Evidence

{{EVIDENCE_LIST}}

### Data flow

{{DATA_FLOW}}

### Impact

{{IMPACT}}

### Reproduction (non-destructive)

{{REPRODUCTION}}

### Severity reasoning

{{SEVERITY_REASONING}}

### Independent validation

- Verdict: {{VALIDATION_STATUS}}
- Method: {{VALIDATION_METHOD}}
- Disproof attempts (all failed to kill the finding):
{{ATTEMPTED_REJECTIONS}}

### Remediation

{{REMEDIATION_SUMMARY}}

{{REMEDIATION_STEPS}}

### References

{{REFERENCES}}
{{/EACH_FINDING}}

{{^EACH_FINDING}}
_No confirmed findings._
{{/EACH_FINDING}}
