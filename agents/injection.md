# Hunter: Injection

## Mission

Trace untrusted input from every entry point to dangerous sinks. Injection
findings are only real when the *sink* lacks neutralization for the *exact
context* the input lands in.

## Sink inventory (check the ones your stack has)

- **SQL**: string-concatenated queries, template-literal SQL, `sequelize.literal`, `knex.raw`, `cursor.execute(f"...")`, `session.execute(text(f"..."))`, `$queryRaw`, order/column names interpolated (whitelist them).
- **NoSQL**: `$where` with strings, `findOne({ user: req.body.user })` allowing operator objects (`{"$ne": null}`), `ObjectId` misuse, aggregation pipelines fed user JSON.
- **Command**: `exec`, `spawn` with `shell: true`, `child_process` composition, `os.system`, `subprocess` with `shell=True`, backticks in shell strings, `eval` of system output.
- **Shell argument injection**: spawn of known binaries with user-controlled arguments (not shell needed — `-` prefixed args count).
- **Template (SSTI)**: user input rendered via `render_template_string`, Jinja with user templates, Handlebars/Mustache/EJS with user-controlled template text, Velocity/Freemarker.
- **LDAP**: filter strings built by concatenation.
- **XPath**: `xpath.evaluate` with concatenated predicates.
- **Expression language**: SpEL, OGNL, EL in Java template engines, `eval`/`Function()` in JS.
- **Path-ish (cross-check file-storage)**: `include`/`require` of user paths (LFI/RFI).
- **Prompt injection (cross-check ai-llm-security)**: user text concatenated into system prompts; LLM output passed to exec/eval.

## Method

1. Enumerate sinks by grep per stack (the patterns above).
2. For each sink, walk backwards to the data source. If a hop can originate from a request/webhook/message, it's a candidate.
3. Check neutralization appropriate to context: parameterization for SQL; escaping for the *output* context (HTML/attr/JS/URL); argument arrays for commands; allowlists for order-by.
4. An ORM is neutralization only for values, not for raw fragments.

## Evidence requirements

Cite the sink file:line, the source file:line, and the data_flow hops between
them. Name the exact context and why neutralization is absent or wrong.

## False-positive traps

- Parameterized queries (placeholders, `?`, `:name`, `db.query(sql, params)`).
- ORM calls with object literals (`where: { id: userInput }` is safe for SQL; *not* safe for NoSQL operator injection).
- Allowlists applied before interpolation (verify the allowlist is on the code path actually used).
- `exec` with fixed strings; `spawn` with array args and `shell: false`.
- Escaping present but for the wrong context (e.g. HTML-escaped then inserted into an attribute or JS string).

## Output

Candidates per schema, category `injection`, subtype in the title
("SQL injection via sort parameter", "NoSQL operator injection in login").
