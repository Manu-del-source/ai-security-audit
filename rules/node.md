# Rules: Node.js

Load when `languages` includes javascript/typescript on the server.
Complements all agent playbooks with Node-specific sink/context knowledge.

## Prototype pollution

- `merge`/`deepmerge`/`lodash.merge`/`Object.assign` with user JSON: can
  `__proto__`/`constructor.prototype` keys flow into objects used for authz
  decisions, template rendering, or query building? Verify gadget potential —
  pollution alone without a gadget is informational.
- `req.body` from `qs`-style parsers with `allowPrototypes`/`plainObjects`
  settings; Express default body-parser is safe-ish for `__proto__` but check
  nested frameworks.

## Exec & eval sinks

- `child_process.exec/spawn` (shell:true), `eval`, `new Function`, `vm.runIn*`
  (sandbox escapes are cheap), `require()` of dynamic paths (RCE via cache
  poisoning), `Function` constructor.
- Template engines rendering user strings: EJS (`render` with user template
  = RCE), Handlebars compile, Mustache, Pug.

## Request handling

- Middleware order: `helmet`/security headers, body parser limits
  (`express.json({ limit })` default 100kb — uncapped custom parsers are
  candidates), auth middleware actually mounted *before* routes (mount-order
  bugs are common).
- `req.url` vs `req.path` decoding differences → auth bypass via encoded
  slashes/params on naive regex matchers.
- `res.redirect` with user input; `res.sendFile` path traversal.

## Async & unhandled

- Unhandled rejections crashing the process on attacker-shaped input
  (availability): JSON.parse of user data outside try/catch in handlers.
- Promise.all over user arrays (unbounded concurrency).

## npm specifics

- Lockfile committed? Install scripts? `.npmrc` tokens in repo?
  (cross-check supply-chain).
- `NODE_ENV` gating: dev branches reachable in prod?

## Sinks quick-table

| Pattern | Risk |
|---|---|
| `exec(\`...${req.query.x}\`)` | command injection |
| `res.render(x)` with user-controlled view name | LFI/RCE |
| `jwt.verify(token, secret, { algorithms: undefined })` | alg confusion |
| `Object.assign(target, req.body)` on user object | mass assignment |
| `fs.readFile(\`/data/${req.params.p}\`)` | path traversal |
