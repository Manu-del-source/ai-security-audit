'use strict';

const { Pool } = require('pg');

// S9: connection string from environment; no embedded credentials in code
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

module.exports = { pool };
