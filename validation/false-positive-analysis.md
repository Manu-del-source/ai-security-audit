# False-Positive Analysis

A rejected candidate is a *success of the process*, not wasted effort. This
catalog lists the recurring shapes of false positives so validators can kill
them fast. Hunters should internalize it too: it is cheaper not to file these.

## Taxonomy

### 1. Phantom vulnerability (pattern without path)
Dangerous sink, no attacker-reachable path. Classic: `eval` in a script that
is never built/shipped; SQL concatenation in a deleted migration; "vulnerable
endpoint" that is registered only in test bootstrap.
**Kill with:** reachability check from real entry points.

### 2. Control elsewhere
The control exists but not at the cited line: router-level middleware, DI
interceptors, DB constraints/triggers, RLS, edge/platform config, WAF, the
reverse proxy, the framework's defaults (Django CSRF middleware, React
auto-escaping).
**Kill with:** trace the *actual* request path end-to-end; find the control.

### 3. Trusted attacker
The "attacker" needs privileges that make the finding circular: admin can
admin, service account can service. Includes findings where the exploit
requires an already-full compromise (root on host ⇒ "RCE").
**Kill with:** compare attacker's stated powers against the threat model.

### 4. Tautological findings
"The database can be queried with SQL", "exec() executes commands",
"secrets are readable by the process holding them". No boundary crossed.
**Kill with:** require a specific untrusted source in the data_flow.

### 5. Wrong-context escaping
Escaping *is* present but for the wrong output context (HTML-escaped into an
attribute, URL-encoded into HTML body). Also: sanitizer allowlists that
actually permit the payload used.
**Kill with:** check the exact render context; test the sanitizer's actual
allowlist.

### 6. Stale or fabricated evidence
Cited lines don't exist, symbol not on those lines, file from another branch,
"reproduction" steps that reference code paths that don't exist.
**Kill with:** mechanical check (CLI does this) + open the file yourself.

### 7. Inflated severity/impact
Real bug, but impact described as the category's worst case instead of the
attainable one. IDOR on preference settings labeled "critical".
**Kill with:** exploitability.md's impact factors; downgrade with justification.

### 8. Dedup artifacts
Same root cause filed 4× by different hunters (missing auth middleware seen
from four routes). Not wrong, but noise; also *inverted* risk: merging two
distinct bugs because both touch the same file.
**Kill with:** merge by root cause; verify the merge keeps both paths' evidence.

### 9. Config-shape assumptions
"Missing rate limit" when the platform enforces it; "cookie without Secure"
when the edge rewrites cookies; "public bucket" that's behind authenticated
CDN.
**Kill with:** inspect deploy config before confirming; else needs_validation.

### 10. Test/dev contamination
Vulnerability exists only in test fixtures, seed scripts, example apps, or
dev-only branches of env checks (`NODE_ENV !== 'production'`).
**Kill with:** establish the production path; move to coverage notes otherwise.

## Hunter-side checklist (before filing)

- Did I state who the attacker is and what boundary they cross?
- Did I read the middleware/router wiring *upstream* of my sink?
- Did I check DB constraints/migrations for the invariant I claim is missing?
- Is my impact the attainable one, not the category's worst case?
- Would a validator find the control I missed in under five minutes?
- Am I filing this because it's a real path, or because the hunt found nothing else?

## Metrics hygiene

Track rejected counts per category. High rejection rates signal hunter drift
(us over-filing a category's pet patterns), which the next run's prompt
should correct. This is how the skill improves: rejections are feedback, not
failure.
