# Rules: React (SPA)

Load when `react`/`react-dom` detected without SSR framework.

## XSS surface

- `dangerouslySetInnerHTML` sites: where does the HTML come from (user
  content, rich-text editors, markdown renderers, LLM output)? Sanitizer
  present AND configured (DOMPurify defaults ok; custom allowlists often leak
  `onerror`/`javascript:`).
- `href`/`src` from user data: `javascript:` URIs (React does not block these
  as of 16/17/18; modern React warns but renders).
- `window.location` assignments from URL params (open redirect, DOM XSS via
  hash-based routing).
- `useEffect` fetching from user-controllable URL.

## Client-side auth is not auth

- Role checks in components (`user.role === 'admin'`) hide UI but prove
  nothing server-side. Find the *server* checks; if absent, the SPA is the
  finding's evidence of client-only authorization.
- JWTs in localStorage: readable by any XSS; document as part of XSS impact.
- Auth state from `localStorage`/global without server revalidation on
  sensitive actions.

## State & data exposure

- Redux/Zustand/Context holding PII/tokens — XSS reads all of it.
- Error boundaries swallowing errors that leak state to logs.
- Props drilling secrets from server-rendered globals (`window.__INITIAL_STATE__`
  with user data/CSRF tokens readable by scripts?).

## Build & bundle

- Source maps deployed to prod (exposes original code incl. comments with
  secrets); bundle scanning for accidentally included `.env` values via
  `import.meta.env`/`process.env` leakage.
- `VITE_*`/`REACT_APP_*`/`NEXT_PUBLIC_*` naming holding secret-shaped values.

## Coverage

Record: components with `dangerouslySetInnerHTML` count, client-side-only
auth checks count, localStorage token usage sites.
