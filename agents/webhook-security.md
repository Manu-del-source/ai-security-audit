# Hunter: Webhooks

## Mission

Webhooks are unauthenticated *by definition* — the signature is the
authentication. Find endpoints where that authentication is missing, weak,
or bypassable, and where event handling is not idempotent.

## Where to hunt

- Routes under `/webhook`, `/webhooks`, `/hooks`, `/callbacks`, provider-specific paths (`/api/stripe`, `/api/github`).
- Signature verification: `stripe.webhooks.constructEvent`, `crypto.verify` of `X-Hub-Signature`, `X-Signature` headers, HMAC comparisons.
- Raw-body handling: whether verification reads the raw body (JSON-parsed bodies break HMACs and often lead to disabled verification).
- Event/route dispatch tables for provider events.

## Checklist

- [ ] Missing signature verification: handler trusts the body wholesale (`req.body.event` drives privileged state changes).
- [ ] Bypassable verification: signature optional (skipped when header absent), comparison not timing-safe, signature checked against user-controlled secret (header-derived key).
- [ ] Wrong secret: verification against a hardcoded/dev secret, or secret supplied in the request.
- [ ] Replay protection: no timestamp/window check (Stripe `tolerance`, GitHub `X-GitHub-Delivery` dedup), events replayable hours/days later.
- [ ] Timestamp validation: signed timestamps trusted without freshness window.
- [ ] Event authenticity: event `type`/`id` taken from body to authorize *actions* without verifying they are in the provider's signed payload semantics; provider ID confusion (GitHub webhook handled by Slack handler).
- [ ] Idempotency: same delivery ID processed twice → duplicate fulfillment/emails/payouts (no dedup table, no unique constraint).
- [ ] Event authorization: webhook for tenant A's events mutating tenant B's objects (event payload object IDs not re-scoped to the webhook endpoint's tenant).
- [ ] State-transition validation: webhook can move objects into states the public API forbids (cancel paid orders, mark unpaid as shipped).
- [ ] Response handling: handler does side effects before verifying; errors return 200 masking failures (availability note) or 500s enabling provider lockout.
- [ ] SSRF via webhook config: user-configured webhook *targets* fetched server-side without SSRF guards (cross-check; file here when the product feature is webhooks-out).

## Evidence requirements

Cite the handler file:line receiving the webhook, the verification
present/absent file:line, and the state-changing call file:line. Name the
provider if the route mimics one.

## False-positive traps

- Verification present but in middleware (read the router wiring).
- Replay protection via dedup table on delivery/event IDs.
- Signature schemes where the timestamp is covered by the signature and window-checked.
- Queue-based processing with consumer-side re-verification.

## Output

Candidates per schema, category `webhook-security`. Severity scales with what
the webhook can trigger (payments/payouts/provisioning = high; notifications = lower).
