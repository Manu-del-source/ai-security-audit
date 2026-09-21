# Rules: Next.js

Load when `next` detected. Next collapses server/client boundaries; the
audit must be explicit about which code runs where.

## Server/Client boundary discipline

- `"use client"` components holding logic assumed server-only; secrets
  imported into client modules (anything imported by a client component
  ships to the browser unless it's server-only — check `import` graphs of
  files using `NEXT_PUBLIC_*` vs plain secrets).
- `process.env.X` read in client components → undefined (or shipped, for
  NEXT_PUBLIC) — finding only if it indicates intent (secret in client bundle).

## App Router specifics

- Route handlers (`app/api/*/route.ts`): auth per handler — there is no
  global guard unless middleware exists; check `middleware.ts` matcher
  coverage (path-based matchers miss nested/unlisted paths; casing tricks).
- Server Actions (`"use server"`): reachable by POST from the client bundle;
  validate authorization *inside* the action (client can invoke directly).
  Argument tampering: actions receive client-shaped args.
- Parallel/intercepting routes: layout-level auth (checking in `layout.tsx`)
  does not protect `page.tsx` accessed directly in all cases — verify where
  the auth check actually executes.
- `cookies()`/`headers()` mutation rules; dynamic APIs used at request time.

## Data fetching

- Server Components fetching user data: per-request auth context propagated?
  Cached fetches (`force-cache`) of per-user data → cross-user leakage.
- `generateStaticParams`/ISR serving per-user pages statically.

## Pages Router (if present)

- `getServerSideProps` auth checks per page; API routes (`pages/api/*`)
  without middleware.
- `_document`/`_app` injections.

## Config

- `next.config.js`: `images.domains` (SSRF via optimizer), `rewrites`/`redirects`
  with user input, security headers config, `output: standalone` copying env.
- Middleware bypass: matcher regex pitfalls (unicode, trailing slash,
  `.*` greediness); auth in middleware but secrets in server actions it
  can't see.

## Typical Next.js findings

| Pattern | Risk |
|---|---|
| Route handler reading `session.user.id` from client-supplied header | auth bypass |
| Server Action doing `prisma.user.update({ where: { id: args.id }, data: args.data })` | IDOR + mass assignment |
| `NEXT_PUBLIC_SERVICE_ROLE_KEY`-style naming | secret exposure |
| middleware matcher `['/admin/:path*']` only | admin routes outside `/admin/*` unguarded |
| `fetch(userUrl, { next: { revalidate } })` cached cross-user | data leak |
