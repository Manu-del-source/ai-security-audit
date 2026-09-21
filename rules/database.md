# Rules: Databases

Load when a database is detected. Database layers implement or break
authorization as much as API code does.

## Parameterization discipline

- All user input reaches queries only as bound parameters. Hunt the raw
  escapes: string concatenation, f-strings/template literals, ORM `raw`/`literal`
  fragments, `ORDER BY`/`LIMIT` interpolation (parameters don't work there —
  allowlist), dynamic table/column names (allowlist).
- NoSQL: operator injection (`$ne`, `$gt`, `$regex` from user JSON),
  `$where` JS execution, aggregation `$expr` from user objects.

## Tenant scoping

- Where is tenant filtering applied: every query (application-side), a
  repository base class, DB RLS (Postgres `ENABLE ROW LEVEL SECURITY` +
  policies), or nowhere? Check migrations for RLS; check a base
  repository/model manager for a scoping hook.
- Cross-tenant references: object IDs accepted without tenant predicate even
  when IDs are UUIDs (UUIDs are not authorization).

## Constraints as controls

- Unique constraints preventing replay/duplication (idempotency for
  business-logic findings); check constraints preventing negative
  amounts/quantities; foreign keys preventing orphan privilege grants.
- Their absence is evidence *for* business-logic candidates, not a finding
  by itself.

## Migrations review

- `is_staff`/`role`/`tenant_id` columns without NOT NULL/constraints.
- Default rows with privileged flags set (seeded admin with weak password is
  a secrets/auth finding).
- RLS policies present but `FORCE` missing (table owner bypasses policies),
  policies `USING` without `WITH CHECK` (write hole).

## Caches & sessions

- Cache keys including user-controlled segments without user scoping
  (cross-user cache poisoning); session stores without TTL; counters/limits
  stored in cache without atomic ops (race conditions).

## Coverage

Record: raw query sites found, sites with parameterization verdict, RLS
status per sensitive table (if migrations available), base-class scoping
mechanism presence.
