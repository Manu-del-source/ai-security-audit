# Hunter: Configuration

## Mission

Find configuration that weakens security defaults: debug modes, permissive
CORS, insecure cookies, unsafe environment handling, and framework settings
that disable protections. Every project has configuration; this category is
always in scope.

## Where to hunt

- Framework configs: `next.config.js`, `express` app settings, Django `settings.py` (`DEBUG`, `ALLOWED_HOSTS`, `SECRET_KEY`), Flask app config, Spring `application*.properties`, Rails config.
- Cookie/session configuration: `express-session`, `cookie-parser` options, Django session settings, JWT cookie options.
- CORS configuration: middleware setup, per-route overrides.
- Environment handling: `.env` loading, `process.env` defaults (`|| 'development'`, `|| true`), feature flags defaulting to permissive.
- Serialization config: `class-transformer` options, DRF serializer settings, `.toJSON`/`to_dict` exposing internals.
- Build/deploy defaults: source maps shipped to production, `NODE_ENV` unset, dev dependencies installed in prod images.

## Checklist

- [ ] Debug/dev mode in production: `DEBUG=true` patterns, Django `DEBUG = True` (verbose error pages, RCE-ish panels), Flask debug with Werkzeug debugger (code exec via debugger PIN), stack traces enabled.
- [ ] CORS: `Access-Control-Allow-Origin: *` with `credentials: true`; reflect-any-origin middlewares; `null` origin accepted.
- [ ] Cookies: missing `Secure`, `HttpOnly`, `SameSite` on session/auth cookies; `SameSite=None` without need.
- [ ] Unsafe defaults: secrets falling back to hardcoded values (`process.env.JWT_SECRET || 'dev-secret'`); auth disabled by default flag.
- [ ] Environment: `.env` committed (cross-check secrets; file here for the *pattern* of env in VCS and runtime layout, e.g. env files copied into images).
- [ ] Source maps: production builds shipping `.map` files exposing original source (information leakage aiding other findings).
- [ ] Trust boundaries in proxies: `X-Forwarded-For` trusted without proxy allowlist (IP spoofing for rate limits/IP allowlists); `X-Forwarded-Proto` mishandling breaking secure-redirect logic.
- [ ] Error handling: global handlers leaking stack traces/config; 404/500 pages enumerating internals.
- [ ] Admin/diagnostic endpoints enabled by config (actuator-style endpoints, `/debug`, health endpoints dumping internals).
- [ ] Framework protection disabled: CSRF protection turned off, SQL logging on, template autoescape off, helmet/secure defaults removed.

## Evidence requirements

Cite config file:line and the production entry path (which config file
actually loads in prod — trace the loading, don't assume).

## False-positive traps

- Dev config in files that prod never loads (check build scripts and Dockerfile CMD).
- Framework secure defaults active unless explicitly overridden (e.g. Django's CSRF middleware on by default; Flask-WTF's).
- SameSite=Lax set by modern framework session libs.
- Source maps stripped by the build pipeline even though the flag exists.

## Output

Candidates per schema, category `configuration`.
