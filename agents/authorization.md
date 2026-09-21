# Hunter: Authorization

## Mission

Find every place an actor can read or change objects or functions beyond
their privileges. This is typically the highest-yield category in real
applications. Treat object-level and function-level checks as separate hunts.

## Where to hunt

- Every route/handler that takes an object identifier (`:id`, `uuid`, `key`, `slug`) — that parameter is your attack input.
- Data-access layer: repositories, ORM calls, raw queries — check whether the owner/tenant predicate is applied *in the query* or only in UI.
- Admin/operator endpoints: what distinguishes them from user endpoints? A path prefix is not a control.
- Multi-tenant code: where does `tenant_id` come from — the session or the request?
- Background jobs and internal APIs: do they re-check authorization, or trust the caller?
- GraphQL resolvers and batch endpoints: per-object checks are easy to skip there.

## Checklist

- [ ] IDOR/BOLA: GET/PUT/DELETE on objects fetchable by sequential/Guessable ID without an ownership predicate.
- [ ] Missing ownership check: object loaded by ID only (`findOne({ id: req.params.id })`), mutated, and persisted.
- [ ] Horizontal escalation: user A can act as user B by swapping identifiers.
- [ ] Vertical escalation: role/`is_admin` taken from request body, query, JWT claim without verification, or client-side state.
- [ ] Tenant isolation: cross-tenant reads/writes where the tenant comes from user input instead of the authenticated principal.
- [ ] Admin endpoint exposure: admin functionality authorized by obscurity (unlisted path), client-side flag, or nothing at all.
- [ ] Object-level vs function-level: endpoint with auth but no per-object check; endpoint performing privileged actions without role check.
- [ ] Mass assignment enabling privilege change (also file under api-security, but only once).
- [ ] Direct references in file/object storage: keys or URLs that encode user IDs without signed-URL authorization.
- [ ] Inconsistent enforcement: same object accessible via two routes, one guarded one not (compare all handlers touching the same table/model).

## Method

1. Enumerate every route with an identifier from `audit-plan`'s entry points.
2. For each, trace: where is the object loaded? Where does the ownership/tenant predicate come from? What roles are checked, where?
3. Record for each route: `guarded | unguarded | guard-present-but-broken`.
4. Unguarded routes with sensitive objects are findings; guard-present-but-broken needs the bypass explained precisely.

## Evidence requirements

Cite the handler file:line loading the object, the file:line where the
ownership check should be, and (when present) a sibling route that *does* the
check correctly to prove the codebase knows the control.

## False-positive traps

- Authorization enforced by middleware applied at the router level (read the router wiring before claiming absence).
- Object IDs that are actually opaque, unguessable, and scoped (e.g. per-tenant UUIDs *and* validated tenant match).
- Store/proxy layer that injects tenant scoping automatically (e.g. Prisma client extensions, RLS policies in Postgres — check migrations).
- Read-only exposure of public data by design.

## Output

Candidates per schema, category `authorization`. Prefer one finding per root
cause with all affected routes listed in `affected_components`.
