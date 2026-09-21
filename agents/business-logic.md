# Hunter: Business Logic

## Mission

Find abuse of *legitimate* functionality: the app does exactly what the code
says, and that is the problem. Adapt to the detected domain from
`threat-model.json` — do not assume e-commerce. Below, translate "order" to
the domain's valuable state transition (booking, invoice, transfer,
redemption, subscription, quota, vote, payout).

## Where to hunt

- State machines: order/workflow status fields and the transitions allowed.
- Money-adjacent fields: prices, discounts, balances, refunds, payouts, credits.
- Identifier-bearing mutations: anything accepting entity IDs in the body.
- Idempotency: payment/webhook/submission handlers.
- Concurrency-sensitive flows: limited stock, one-per-user offers, balance updates.
- Coupon/promo/voucher redemption logic.

## Checklist

- [ ] Price/amount fields accepted from the client and persisted or used for charge calculation.
- [ ] Ownership/recipient identifiers client-controlled (change payee, shipping address on someone else's order).
- [ ] Replay: same operation accepted twice where it must be once (payment capture, redeem code, vote, transfer).
- [ ] Workflow-state bypass: transitions skipped via direct API calls (cancel after delivery, approve own request, skip payment step by hitting the next endpoint directly).
- [ ] Duplicate transactions: no idempotency key; double-submit creates double charge/double entry.
- [ ] Negative/zero/overflow quantities or amounts accepted (negative refund, 0.01 price, -1 quantity increasing stock).
- [ ] Race conditions: check-then-act on balances/stock/limits without transaction/lock (TOCTOU on `if balance >= amount then debit`).
- [ ] Coupon abuse: reusable single-use codes, stackable discounts, percentage coupons on zero-value items, coupon applies before/after tax inconsistently, coupon codes enumerable.
- [ ] Balance/credit manipulation: concurrent withdrawals, deposit confirmation trusted from client, rounding always in user's favor.
- [ ] Order-state manipulation: status field updatable by client; cancel/refund only checked at UI; partial-refund accumulation exceeding original amount.
- [ ] Approval bypass: self-approval, approver identity from client input, approval token reused.

## Method

1. From the threat model, list the domain's 5–10 most valuable state transitions.
2. For each, list: what fields the request accepts, what the server validates, what it assumes.
3. "What the server assumes" is your attack surface: assumptions about price, count, state, sequence, identity, and time.

## Evidence requirements

Cite the handler file:line accepting the tainted field and the file:line
persisting it. For race conditions, cite the non-transactional read/write pair.

## False-positive traps

- Server-side recalculation of prices from trusted data (client field ignored).
- Idempotency keys or DB unique constraints preventing replay (check migrations/constraints).
- Transactions/row locks (`SELECT ... FOR UPDATE`, `db.transaction`, optimistic locking version columns) around check-then-act.
- Workflow enforced by state-machine library or DB check constraints.

## Output

Candidates per schema, category `business-logic`. State the domain assumption
violated in `impact`.
