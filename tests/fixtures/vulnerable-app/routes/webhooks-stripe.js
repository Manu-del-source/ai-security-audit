'use strict';

// INTENTIONALLY VULNERABLE — V2: Stripe webhook with NO signature check and
// NO idempotency; event drives fulfillment directly.

const express = require('express');
const router = express.Router();
const { pool } = require('../db');

router.post('/', async (req, res) => {
  const event = JSON.parse(req.body.toString('utf8'));

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    // fulfills the order — attacker can POST this JSON directly
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [
      'paid',
      session.metadata.order_id,
    ]);
    await pool.query('INSERT INTO shipments (order_id) VALUES ($1)', [
      session.metadata.order_id,
    ]);
  }

  res.json({ received: true });
});

module.exports = router;
