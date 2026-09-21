# Rules: Web Applications (generic)

Stack-agnostic checks applied when `summary.isWebApp` is true. Load together
with the backend- and frontend-specific rule files.

## Entry inventory (do first)

- Enumerate all HTTP routes: method, path, auth requirement, handler.
- Classify: public / authenticated / privileged. Unauthenticated writes drive
  the most severe findings.
- Note body parsers active and their limits.

## Session & cookie checks

- Cookie flags on session/auth cookies: `HttpOnly`, `Secure`, `SameSite`.
- Session store: in-memory (restart logs everyone out; shared hosting leaks),
  signed cookies (payload readable), server-side (check invalidation on logout
  and password change).
- Session fixation: ID rotation at login and privilege escalation.

## Security headers

- CSP appropriate to frontend (inline scripts?), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options`/`frame-ancestors`, HSTS on TLS deployments,
  `Referrer-Policy`, `Permissions-Policy`.
- CORS: exact origin allowlist vs reflection; `credentials: true` with `*` is
  a finding (cross-check configuration rules).

## CSRF posture

- Cookie-authenticated state-changing routes need CSRF tokens or `SameSite=Strict/Lax`
  + method checking. Bearer-token APIs are typically exempt.

## Static assets

- `.git/`, `.env`, backup files, `.map` files served? Check static middleware
  roots and deploy manifests.

## Interaction with hunters

- Feeds `api-security.md` (route matrix), `client-side.md` (headers, CSRF),
  `configuration.md` (cookie/session config).
- Coverage: record total routes found and routes classified.
