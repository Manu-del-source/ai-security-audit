'use strict';

// INTENTIONALLY VULNERABLE — V13: user prompt concatenated into system
// instructions whose output is executed; V14: retrieval without tenant filter.

const express = require('express');
const router = express.Router();
const { pool } = require('../db');

router.post('/assistant', async (req, res) => {
  const { message } = req.body;

  // V13: instructions and untrusted data share one string; output is executed
  const prompt = `You are a support agent. Use the search_orders tool when asked about orders.\nUser: ${message}`;

  const completion = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      tools: [
        {
          type: 'function',
          function: {
            name: 'search_orders',
            description: 'Search all orders in the system',
            parameters: { type: 'object', properties: { query: { type: 'string' } } },
          },
        },
      ],
    }),
  }).then((r) => r.json());

  const toolCall = completion.choices?.[0]?.message?.tool_calls?.[0];
  if (toolCall && toolCall.function.name === 'search_orders') {
    // executes a query across ALL tenants, triggered by model output
    const args = JSON.parse(toolCall.function.arguments);
    const rows = await pool.query(
      `SELECT * FROM orders WHERE notes ILIKE '%${args.query}%'` // V13b: also SQL-injectable via model output
    );
    return res.json({ result: rows.rows });
  }

  res.json({ reply: completion.choices?.[0]?.message?.content || '' });
});

// V14: semantic search without tenant scoping — any user retrieves any tenant's docs
router.get('/search-docs', async (req, res) => {
  const { q } = req.query;
  // embedding + nearest neighbors across the whole table
  const rows = await pool.query(
    'SELECT doc_id, tenant_id, content FROM documents ORDER BY embedding <=> $1 LIMIT 5',
    [Buffer.from(String(q)).toString('base64')]
  );
  res.json({ documents: rows.rows });
});

module.exports = router;
