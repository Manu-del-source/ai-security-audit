'use strict';

// INTENTIONALLY VULNERABLE — test fixture only. Do not deploy.
// Each flaw is numbered: V1..V12 (vulnerable), referenced in tests.

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const { pool } = require('./db');
const stripeRoutes = require('./routes/webhooks-stripe');
const aiRoutes = require('./routes/ai');

const app = express();
app.use(express.json({ limit: '500mb' })); // V11: oversized payload limit

// V2: missing signature verification on Stripe webhooks
app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }), stripeRoutes);

// --- Auth: login issues JWT with hardcoded secret -----------------------
const JWT_SECRET = 'super-secret-jwt-signing-key-2024'; // V6: hardcoded secret

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // V1 (auth): user enumeration via distinct error messages
  const user = await pool.query('SELECT * FROM users WHERE email = $1', [username]);
  if (user.rows.length === 0) {
    return res.status(404).json({ error: 'user not found' });
  }
  const ok = await bcrypt.compare(password, user.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user.rows[0].id, role: user.rows[0].role }, JWT_SECRET, {
    expiresIn: '30d',
  });
  res.json({ token });
});

// V3: IDOR — invoice fetched by ID without ownership check
app.get('/api/invoices/:id', async (req, res) => {
  const { id } = req.params;
  const inv = await pool.query('SELECT * FROM invoices WHERE id = $1', [id]);
  if (inv.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(inv.rows[0]);
});

// V4: SQL injection via sort parameter interpolation
app.get('/api/orders', async (req, res) => {
  const sort = req.query.sort || 'created_at';
  const dir = req.query.dir || 'DESC';
  const rows = await pool.query(
    `SELECT id, total, status FROM orders ORDER BY ${sort} ${dir} LIMIT 50`
  );
  res.json(rows.rows);
});

// V5: reflected XSS — search term echoed unescaped
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<h1>Results for: ${q}</h1>`);
});

// V7: command injection — ping utility passes user input to shell
app.get('/api/tools/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.json({ output: stdout || String(err) });
  });
});

// V8: path traversal — file download composes path from user input
app.get('/api/files/:name', (req, res) => {
  const name = req.params.name;
  const filePath = path.join(__dirname, 'uploads', name);
  fs.createReadStream(filePath).pipe(res);
});

// V9: SSRF — fetches arbitrary URLs from user input
app.get('/api/fetch-url', async (req, res) => {
  const url = req.query.url;
  try {
    const r = await fetch(url);
    const text = await r.text();
    res.type('text/plain').send(text.slice(0, 5000));
  } catch (e) {
    res.status(502).json({ error: 'fetch failed' });
  }
});

// V10: business logic — negative quantities accepted in order creation
app.post('/api/orders', async (req, res) => {
  const { items, coupon } = req.body;
  let total = 0;
  for (const item of items) {
    // price is recalculated server-side (NOT a flaw); quantity is not validated
    const priceRows = await pool.query('SELECT price FROM products WHERE id = $1', [item.product_id]);
    total += priceRows.rows[0].price * item.quantity; // V10: negative quantity reduces total below zero
  }
  if (coupon === 'SAVE10') total -= 10;
  res.json({ total });
});

// V12: upload — user-controlled filename, no validation
const upload = multer({ dest: 'uploads/' });
app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ saved: req.file.path });
});

// AI routes: prompt injection + cross-user retrieval
app.use('/api/ai', aiRoutes);

app.listen(3000, () => console.log('vulnerable-app on :3000'));
