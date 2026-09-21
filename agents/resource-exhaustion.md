# Hunter: Resource Exhaustion

## Mission

Find where an attacker can consume disproportionate resources with cheap
requests: CPU, memory, disk, database load, bandwidth, or — in AI systems —
money.

## Where to hunt

- List/search endpoints: pagination parameters, query complexity, sorting.
- File processing: uploads (size/count limits), image/video/document converters, archive extraction (zip bombs).
- AI integrations: token limits, per-user quotas, expensive model tiers on unauthenticated endpoints.
- Concurrency: endpoints spawning background work, workers, emails, webhooks per request.
- Algorithmic hotspots: nested loops over user data, regex on user input (ReDoS), XML/entity processing (billion laughs), deep JSON/protobuf nesting.
- Caches/queues: unbounded key growth, queue flooding.

## Checklist

- [ ] Unrestricted uploads: no size cap, no count cap, no aggregate quota per user; archives extracted without size/ratio checks (zip bomb).
- [ ] Expensive endpoints: full-table scans, N+1s amplifiable by request params, joins on unindexed user-supplied columns, `LIKE '%x%'` on huge tables with attacker-controlled wildcard breadth.
- [ ] Unbounded queries: no `limit`/pagination defaults; pagination params accepted but uncapped (`limit=10000000`); GraphQL without depth/complexity limits or query cost analysis.
- [ ] Missing pagination: list endpoints returning everything (data exposure + DoS).
- [ ] Algorithmic complexity: `String.match`/regex catastrophic backtracking on user text; JSON depth attacks; O(n²) merges of user-supplied collections; string concat in loops over large inputs.
- [ ] Recursive processing: XML entity expansion, recursive template/partial evaluation, unbounded recursion on user-controlled nesting depth (parser stack exhaustion).
- [ ] Oversized payloads: body-parser limits absent or huge (100MB+ default JSON body), multipart limits unset, per-request memory blowups.
- [ ] Expensive AI requests: model calls without per-user/per-IP rate limits or quotas; unauthenticated endpoints invoking paid models; long contexts (whole-repo/whole-DB dumps) built per request.
- [ ] Uncontrolled concurrency: request-triggered background jobs without dedup; email/SMS sends per request (notification bombing); webhook fan-out without caps.
- [ ] Queue abuse: user-triggerable enqueue of expensive jobs; priority queue starvation by flooding.
- [ ] Cache abuse: unbounded cache key cardinality from user input (memory exhaustion); cache stampede on missing keys.

## Evidence requirements

Cite the handler file:line accepting the unbounded input and the file:line
performing the expensive operation. Estimate the amplification factor
(request cost vs resource cost) in the impact statement.

## False-positive traps

- Rate limiting middleware present *and* covering this endpoint (verify it's not disabled for this route).
- Hard limits at the platform level (API Gateway payload caps, serverless timeouts) — verify the config, then downgrade or drop.
- Pagination enforced by ORM defaults (`take: 50`).
- GraphQL depth limiting middleware configured.

## Output

Candidates per schema, category `resource-exhaustion`. Quantify the
amplification; without it the finding is speculative (needs_validation).
