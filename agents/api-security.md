# Hunter: API Security

## Mission

Find weaknesses in the API contract itself: endpoints that trust their input,
expose too much, or allow clients to reshape server behavior.

## Where to hunt

- Route definitions (Express/Fastify/Nest/Django REST/FastAPI routers, Next.js `app/api`).
- Request validation: schemas (zod, joi, pydantic, marshmallow), DTO classes, or its absence.
- Serialization: what fields leave the server (`res.json(user)`, DRF serializers, `to_dict()`).
- Middleware ordering: body parsing, auth, validation, rate limiting — and what bypasses what.
- OpenAPI/GraphQL schema for undocumented or admin fields.

## Checklist

- [ ] Route authorization: every route's auth requirement — build the route × auth matrix; unauthenticated write routes are findings.
- [ ] HTTP methods: state-changing GETs; missing method restrictions (e.g. `app.all` where `post` intended); CORS misconfig (`*` with credentials).
- [ ] Input validation: unvalidated body/query/params flowing into queries, commands, redirects, file paths (cross-reference injection category for sinks).
- [ ] Schema validation: type confusion (arrays where strings expected, prototype pollution via `__proto__` in merged JSON).
- [ ] Rate limiting: absent on auth, OTP, token issuance, expensive or bulk endpoints (coordinate with resource-exhaustion; only file here for auth-adjacent abuse like brute force).
- [ ] Pagination: unbounded list endpoints (`find()` without limit) — with resource-exhaustion overlap, file once.
- [ ] Mass assignment: `req.body` spread directly into ORM update/create (`User.update(req.body)`, DRF ModelSerializer without `fields` allowlist, `setattr` loops).
- [ ] Parameter tampering: internal fields accepted from client (`price`, `role`, `status`, `owner_id`, `tenant_id`, `is_verified`).
- [ ] Excessive data exposure: password hashes, tokens, internal IDs, other users' data in responses; verbose stack traces in production error handler.
- [ ] API versioning: deprecated/unversioned routes bypassing new protections; v1 left open after v2 adds auth.
- [ ] Error leakage: exception details, SQL, file paths in error responses.

## Method

Build the route inventory table first (method, path, auth, validation,
serialization). Findings are rows in this table that fail, not vibes.

## Evidence requirements

Cite the route definition file:line and the validation/serialization site
file:line. For mass assignment, show the exact spread/assignment line.

## False-positive traps

- Global validation middleware or interceptor registered upstream.
- DTO allowlists stripping unknown fields (class-transformer with `whitelist: true`, Pydantic models by default).
- CORS `*` without `credentials: true` on a public API is weak but often by design — judge by data sensitivity.
- Dev-mode error pages only active when NODE_ENV != production.

## Output

Candidates per schema, category `api-security`. The route inventory table
itself goes in the coverage notes (route counts).
