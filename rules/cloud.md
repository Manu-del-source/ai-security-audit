# Rules: Cloud

Load when cloud SDKs, IaC, or deployment configs are detected. Complements
`cloud-security.md` and `infrastructure.md` playbooks.

## IAM discipline

- Least privilege per role/function: wildcard `Action`/`Resource` on
  roles attached to user-facing code is a finding; on internal/build roles it
  is usually informational unless the role is reachable from untrusted input.
- Trust policies: who can assume roles; external IDs for cross-account;
  confused-deputy surfaces (public endpoints holding roles that act on
  user-supplied resource ARNs).
- IaC drift: policy files vs inline policies in code; duplicated definitions.

## Storage

- Bucket policies: public-read on user data, `Principal: "*"` with conditions
  that don't bind (missing `aws:SourceVpce`/referer checks that can't be met).
- Presigned URL issuance: TTL, method scoping, key derivation from identity,
  content-length/type constraints in POST policies.
- Bucket CORS: `*` origin with credentials on data buckets.
- Public buckets used for user uploads: enumeration via predictable keys,
  listing allowed.

## Serverless

- Env vars in function config with secrets (plaintext at rest in many
  default configs, visible in deploy pipelines/logs).
- Public invocability: API Gateway without authorizer; function URL auth
  `NONE` on privileged functions.
- Long-running privileged functions doing string→query/command composition
  (RCE with cloud role = amplification; check `rules/cloud.md` metadata note).

## Edge/platform

- Platform-managed auth (Vercel/Cloudflare Access) covering the app?
  If claimed, code-level auth checks may be absent by design — document the
  boundary in coverage instead of filing "missing auth" for routes behind it.
- Platform feature flags: preview deployments public with real data bindings.

## Secrets distribution

- Where secrets land: env at build time (bundled into artifacts?), runtime
  injection from a manager (good), committed config (finding, cross-check
  secrets hunter).
- Service-account JSON/keys committed or baked into images.

## Coverage

Record: roles found and their wildcard use, buckets and public status,
functions and invocability, secrets manager usage vs plaintext env.
