# Rules: API Services

Applied when the target is primarily an API (`summary.hasBackend`, no/limited
frontend). Complements `api-security.md` with service-level concerns.

## Auth matrix (build it)

Every endpoint × (none / api-key / jwt / session / mTLS / internal-only).
Findings shape up as matrix holes: privileged operation reachable with lesser
auth class.

- Token verification: signature checked? audience/issuer checked? algorithm pinned?
- API keys: generation entropy, storage (hashed?), scope binding, revocation.
- Internal endpoints: separated by network? by header? "internal" header
  spoofing via direct route match is a classic.

## Contract discipline

- Validation at the boundary: schema (OpenAPI/zod/pydantic) enforced in code
  or just documented? Documented-but-unenforced is a gap to note.
- Unknown-field policy: reject vs strip vs merge (mass-assignment surface).
- Error contract: does 4xx/5xx leak internals (stack, SQL, vendor SDK errors)?

## Versioning & deprecation

- Old versions without the new controls (auth added in v2, v1 open).
- Version negotiation by header vs path — check both for bypasses.

## Rate limiting & quotas

- Present at edge/app? Keys by IP (spoofable via X-Forwarded-For without proxy
  trust config), by user, by token? Auth-critical routes (login, OTP, token)
  need per-identity limits.

## Gateway/platform assumptions

- If deploy config shows an API gateway: what does it own (auth, rate limits,
  schema validation)? Only code paths *not* covered by the gateway are
  candidates for those checks.

## Coverage

Record: endpoints found, endpoints with validation, endpoints in the auth
matrix, unauthenticated write endpoints count.
