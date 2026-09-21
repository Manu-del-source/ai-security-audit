# Hunter: Cloud Security

## Mission

Find weaknesses in cloud-provider usage: IAM, managed storage exposure,
serverless misconfiguration, and trust relationships between cloud services
and application code.

## Where to hunt

- IAM policies: inline and managed, in IaC (`*.tf`, CloudFormation), serverless config (`serverless.yml` iamRoleStatements, SAM policies).
- Object storage: S3/GCS/Azure configs, bucket policies, CORS on buckets, presigning code.
- Serverless functions: handlers, event sources, environment config.
- Managed auth services: Cognito, Firebase Auth, Supabase RLS — client-side config and policy files.
- KMS/secrets manager usage patterns.

## Checklist

- [ ] IAM: wildcard actions/resources; roles combining mutually exclusive duties; identity-based policies allowing `*` on critical services; missing permission boundaries for app roles.
- [ ] Storage exposure: bucket policies with public-read on private data; ACL grants to `AllUsers`/`AuthenticatedUsers`; bucket CORS allowing `*` with credentials.
- [ ] Serverless: function env vars holding plaintext secrets; invocation of privileged functions from public event sources (API Gateway without authorizer); long-lived cloud credentials in function env instead of roles.
- [ ] Serverless IAM: role allowing the function to read *all* of a bucket when it needs one prefix; `s3:*` on `*` in a handler that lists objects.
- [ ] Presigning logic: signing arbitrary keys requested by the client (key not derived from server-side identity/ownership), long TTLs, signing `*` methods.
- [ ] Supabase/Postgres RLS: tables without RLS enabled while accessed with anon key; policies missing `USING`/`WITH CHECK`; service-role key shipped to the client.
- [ ] Firebase: database rules in test mode (`allow read, write: if true`), storage rules public, service-account JSON committed.
- [ ] Cognito: identity pools with unauthenticated roles too privileged; misconfigured trust chains between user pools and IAM.
- [ ] Metadata/SSRF convergence: app with cloud role fetches user-supplied URLs (cross-check injection; file here when the *role* is the amplification — SSRF to metadata is cloud-impact).
- [ ] Cross-service trust: webhook signers' public keys fetched over plain HTTP; OIDC issuers accepted over `http://`.

## Evidence requirements

Cite the policy/config file:line and the principal/role affected. State the
blast radius in cloud terms (which resources, which operations).

## False-positive traps

- Wildcards in policies scoped to app-specific, low-privilege resources.
- RLS enforced via a centralized database wrapper even when policies are absent per-table (verify the wrapper).
- Public buckets that are static-asset CDNs by design.
- Local dev stacks (`localstack`, emulators) in test configs.

## Output

Candidates per schema, category `cloud-security`.
