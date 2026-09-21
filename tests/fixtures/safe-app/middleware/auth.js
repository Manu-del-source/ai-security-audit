'use strict';

// S10: JWT middleware with algorithm pinned and secret from env
const jwt = require('jsonwebtoken');

function required(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // pinned; no alg confusion
    });
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch (_e) {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

module.exports = { required };
