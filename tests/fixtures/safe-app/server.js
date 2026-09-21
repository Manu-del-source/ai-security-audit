'use strict';

// SAFE FIXTURE — each module here *looks* like the vulnerable-app pattern but
// carries the proper control. A correct audit rejects these as findings.
// S1..S8 mirror V-flaws with mitigations.

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const { pool } = require('./db');
const stripeRoutes = require('./routes/webhooks-stripe');
const auth = require('./middleware/auth');

const app = express();
app.use(express.json({ limit: '1mb' })); // S6: sane body limit

// S1: Stripe webhook WITH signature verification (secret from env) and dedup
app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }), stripeRoutes);

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await pool.query('SELECT * FROM users WHERE email = $1', [username]);
  if (user.rows.length === 0) {
    return res.status(401).json({ error: 'invalid credentials' }); // S2: uniform error, no enumeration
  }
  const ok = await bcrypt.compare(password, user.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ sub: user.rows[0].id, role: user.rows[0].role }, process.env.JWT_SECRET, {
    expiresIn: '1d',
  });
  res.json({ token });
});

// S3: invoice route WITH ownership check in the query
app.get('/api/invoices/:id', auth.required, async (req, res) => {
  const inv = await pool.query(
    'SELECT * FROM invoices WHERE id = $1 AND user_id = $2', // ownership predicate
    [req.params.id, req.user.id]
  );
  if (inv.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(inv.rows[0]);
});

// S4: sort column allowlisted; direction whitelisted — no injection
const SORTABLE = new Map([
  ['created_at', 'created_at'],
  ['total', 'total'],
]);
app.get('/api/orders', auth.required, async (req, res) => {
  const sortKey = SORTABLE.has(req.query.sort) ? req.query.sort : 'created_at';
  const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC';
  const rows = await pool.query(
    `SELECT id, total, status FROM orders ORDER BY ${sortKey} ${dir} LIMIT 50`
  );
  res.json(rows.rows);
});

// S5: search term rendered through HTML escaping
app.get('/search', (req, res) => {
  const q = String(req.query.q || '');
  const safe = q.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  res.send(`<h1>Results for: ${safe}</h1>`);
});

// S7: no shell — spawn with argument array, fixed binary, no user-controlled shell line
app.get('/api/tools/ping', auth.required, (req, res) => {
  const host = String(req.query.host || '');
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).json({ error: 'invalid host' });
  }
  const child = spawn('ping', ['-c', '1', host], { shell: false });
  let out = '';
  child.stdout.on('data', (d) => (out += d));
  child.on('close', () => res.json({ output: out }));
});

// S8: download jailed to uploads dir with basename + canonicalization check
app.get('/api/files/:name', auth.required, (req, res) => {
  const name = path.basename(req.params.name); // strips traversal
  const base = path.resolve(__dirname, 'uploads');
  const filePath = path.resolve(base, name);
  if (!filePath.startsWith(base + path.sep)) {
    return res.status(400).json({ error: 'invalid path' });
  }
  fs.createReadStream(filePath).pipe(res);
});

app.listen(3000, () => console.log('safe-app on :3000'));
