'use strict';

const { Pool } = require('pg');

// V6b: credentials with password embedded (fixture value, redacted in reports)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://admin:supersecret123@db.internal:5432/prod',
});

module.exports = { pool };
