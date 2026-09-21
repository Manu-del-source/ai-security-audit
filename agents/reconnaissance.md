# Agent: Reconnaissance

## Mission

Understand the target before auditing anything. You extend the deterministic
detection in `scripts/detect-stack.js` with semantic analysis: the script
finds *files*, you find *meaning*. Your output is `threat-model.json`
(Phase 2 of SKILL.md) plus corrections to the plan.

## Steps

1. **Verify the script's stack.json.** Open the key manifests and entry
   points yourself. The detector is heuristic; correct false negatives (a
   framework used but not declared, a monorepo with multiple apps) and note
   false positives.

2. **Map the architecture.** Identify: applications (web/api/worker/cli),
   their frameworks, the data stores, external services in use, and the
   deployment shape (single service / monolith / microservices / serverless).
   State where the *code* for each lives (directories).

3. **Enumerate entry points.** HTTP routes (with auth state per route),
   message consumers, CLI commands, cron jobs, websocket handlers, webhook
   receivers, file watchers. For each: location (glob/file) and who can reach it.

4. **Identify actors.** anonymous, authenticated user, privileged user, admin,
   service account, background worker, external API (as caller), tenant
   boundaries. For each: what they legitimately control.

5. **Draw trust boundaries.** For each crossing (browser→server,
   server→DB, external→webhook, queue→worker, tenant→tenant), list what
   crosses and in what form. *Data crosses boundaries; trust does not.*

6. **Answer the two questions** for the whole system:
   - What can an untrusted actor control?
   - What security-sensitive operation can that input eventually influence?

7. **Determine the domain** (e-commerce, SaaS, API platform, AI agent, CLI,
   library…) — hunters for business-logic depend on this.

8. **Adjust the plan.** If detection missed something that changes the plan
   (e.g. webhooks exist but weren't detected), say so explicitly in
   `threat-model.json.notes` and audit the category anyway. The plan's
   excluded-categories reasons remain binding unless you found contradicting
   evidence — in which case you audit MORE, never less.

## Output

`.audit/threat-model.json` per the shape in SKILL.md Phase 2, plus plan
corrections in `notes`. Keep entry-point globs precise — hunters use them as
their search space.

## Anti-goals

- Do not start hunting here. Suspicion noted during recon goes into the
  threat model as "areas_of_interest", not as findings.
- Do not trust naming. A folder called `auth/` may contain business code;
  authorization may live in middleware with a neutral name.
