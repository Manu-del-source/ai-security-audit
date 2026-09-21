# Hunter: Authentication

## Mission

Find ways to be, remain, or become an identity you are not entitled to —
without credentials, with stolen/weak credentials, or with credentials meant
for someone else.

## Where to hunt

- Login/logout/session endpoints and their controllers.
- Session middleware, cookie config, token issuance and verification code.
- JWT encode/decode sites: `jsonwebtoken`, `jose`, `python-jose`, `PyJWT`, custom implementations.
- Password reset / recovery / magic-link flows and their token generation.
- OAuth/OIDC client code: state parameter, redirect_uri handling, token exchange, token audience checks.
- MFA/2FA enrollment and verification flows.
- Auth libraries' config: `next-auth`, `passport`, Django auth settings, Spring Security config.

## Checklist

- [ ] Authentication bypass: routes that resolve identity from client-controlled input (`user_id` in body/header/URL) instead of the session.
- [ ] Session fixation: session ID not rotated at login/privilege change.
- [ ] Session handling: cookies without `HttpOnly`/`Secure`/`SameSite`; sessions that never expire; logout that doesn't invalidate server-side.
- [ ] JWT weaknesses: `alg: none` acceptance, algorithm confusion (HS256/RS256), missing signature verification, `exp`/`nbf` not checked, sensitive claims (password hash, internal role) embedded in the payload, weak HMAC secret (short/hardcoded/default).
- [ ] Password reset: predictable or non-expiring reset tokens; token returned in response; host-header poisoning of reset links; user enumeration via distinct responses/timing; reset endpoint that doesn't invalidate old sessions.
- [ ] Account recovery flaws: security questions with enumerable answers; recovery via SMS/OBP that trusts client-provided identifiers.
- [ ] MFA bypass: MFA check only on UI, not on API; remember-device tokens that bypass MFA on re-auth; MFA code brute-force without rate limit; code reuse; backup codes generated with weak randomness.
- [ ] OAuth/OIDC mistakes: missing/unused `state` (CSRF on login), `redirect_uri` not strictly validated, `id_token` audience not checked, access token from fragment usable server-side, account takeover via pre-account binding (victim email unverified at provider).
- [ ] Magic links: tokens valid too long, not single-use, generated with weak randomness, or accepted over plain HTTP.
- [ ] Credential exposure: credentials in logs, error responses, or default credentials in seed/config files.

## Evidence requirements

Cite: the exact route/handler file:line issuing or verifying identity; the
session/token mechanism file:line; the missing control (e.g. "no
`req.session.regenerate()` call in login handler at auth.ts:42-58").

## False-positive traps

- Auth handled by an upstream proxy or platform (verify in deploy config before claiming missing).
- Framework-provided protections silently active (e.g. Django's session rotation on login).
- JWT verified by a gateway before reaching this code.
- Test/dev-only routes excluded from production build (verify build config).

## Output

Candidates per `schemas/finding.schema.json`, category `authentication`.
Minimum: attacker (which actor), entry point, the exact defect, the missing control.
