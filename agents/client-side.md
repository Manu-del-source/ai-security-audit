# Hunter: Client-Side

## Mission

Find weaknesses in what the browser executes: injected markup/script,
unvalidated navigation, client-side trust decisions, and sensitive data
handling in client code.

## Where to hunt

- Templates and components rendering user content (React/Vue/Svelte/Angular templates, Jinja/Twig/ERB/Blade server templates).
- Direct DOM APIs: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `$(`...`)` with HTML strings, `dangerouslySetInnerHTML`, `v-html`.
- URL/redirect handling: `window.location = userInput`, `redirect()` with user URLs, `<a href>` from data.
- Client storage: `localStorage`/`sessionStorage` for tokens or PII; cookies set client-side.
- `postMessage` handlers: origin checks, message shape validation.
- Client-side authorization: UI-only hiding of admin controls; client-computed permissions.
- Security headers: CSP, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy` (server or meta).

## Checklist

- [ ] XSS (reflected): request data rendered without context-appropriate escaping.
- [ ] XSS (stored): user content persisted and rendered to other users (comments, profiles, filenames, imported data).
- [ ] DOM XSS: `location.hash|search|name|referrer`, `postMessage` data, or `document.referrer` flowing into DOM sinks.
- [ ] Unsafe HTML rendering: rich-text/markdown rendered with `sanitize` disabled or a weak allowlist (`script`, `on*` handlers, `javascript:` URIs survivable).
- [ ] Open redirects: full URLs or `//host` accepted as redirect targets; protocol-relative URLs missed by validators checking only `startsWith('/')`.
- [ ] Client-side authorization: role checks only in the UI; API called by hidden client code lacks the server check (cross-check authorization).
- [ ] Sensitive data exposure: tokens/PII in localStorage (XSS-readable), in URLs, in referrer headers, in logs.
- [ ] postMessage: `message` handlers without `event.origin` validation or acting on unvalidated payload.
- [ ] CSRF: state-changing cookie-authenticated endpoints without CSRF tokens/SameSite (coordinate with api-security; file here when the *browser* is the attack vehicle).
- [ ] Browser security headers: no CSP on user-content-heavy apps; permissive `frame-ancestors` on clickjacking-sensitive pages.

## Evidence requirements

Cite the sink file:line, the source of the untrusted data, and the encoding
present/absent at the exact render context (HTML body, attribute, JS string, URL).

## False-positive traps

- Framework auto-escaping (React text interpolation, Vue `{{ }}`, Angular templates) — bypasses are only `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]` or href/src attribute binding with `javascript:` URIs.
- Sanitizer in the pipeline (DOMPurify, bleach, sanitize-html) — verify its config, not just its presence.
- `window.location = userInput` behind an origin allowlist.
- CSP strong enough to block inline/event-handler injection (verify header actually set).

## Output

Candidates per schema, category `client-side`. Name the exact sink context in
the title.
