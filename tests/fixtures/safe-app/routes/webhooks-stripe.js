'use strict';

// S1: Stripe webhook with the full control set:
//   - HMAC signature verification against the raw body
//   - timing-safe comparison
//   - timestamp tolerance check (replay protection)
//   - delivery-ID dedup (idempotency)
//   - order re-scoped to the session's tenant before fulfillment

const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { pool } = require('../db');

function verifyStripeSignature(payload, header, secret, toleranceSeconds = 300) {
  if (typeof header !== 'string') return false;
  const parts = Object.fromEntries(
    header.split(',').map((kv) => kv.split('='))
  );
  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) return false;

  // S1a: freshness window
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > toleranceSeconds) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${payload}`)
    .digest('hex');

  // S1b: timing-safe comparison
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const seenDeliveries = new Set(); // S1c: dedup (fixture; use a DB table in real apps)

router.post('/', async (req, res) => {
  const raw = req.body.toString('utf8');

  const ok = verifyStripeSignature(raw, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return res.status(400).json({ error: 'invalid signature' });

  const event = JSON.parse(raw);

  if (seenDeliveries.has(event.id)) {
    return res.json({ received: true, duplicate: true });
  }
  seenDeliveries.add(event.id);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    // S1d: only fulfill orders that belong to the tenant this endpoint serves,
    // and only transition unpaid -> paid
    const result = await pool.query(
      `UPDATE orders SET status = 'paid'
       WHERE id = $1 AND tenant_id = $2 AND status = 'pending'`,
      [session.metadata.order_id, session.metadata.tenant_id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'order not fulfillable' });
    }
  }

  res.json({ received: true });
});

module.exports = router;
