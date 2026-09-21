# Hunter: Infrastructure

## Mission

Find security weaknesses in how the software is built, shipped, and run:
containers, CI/CD, deployment config, and network exposure. This is about the
*context* around the code.

## Where to hunt

- `Dockerfile`, `docker-compose*.yml`: base images, users, capabilities, mounts, secrets.
- CI: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `circleci/config.yml`.
- IaC: `*.tf`, CloudFormation, Pulumi; IAM policies and security groups.
- Deployment: `vercel.json`, `fly.toml`, `render.yaml`, `k8s/`, `serverless.yml`, Heroku `app.json`.
- Server config: nginx/Apache configs, `next.config.js` headers, Express security middleware.
- Process wiring: privileged ports, root execution, host mounts, docker socket access.

## Checklist

- [ ] Containers running as root (no `USER` directive); latest-tag base images; images from untrusted registries.
- [ ] Docker socket mounted into containers; `--privileged`; host path mounts of sensitive dirs; `network_mode: host`.
- [ ] Secrets baked into images via ENV/ARG/COPY of `.env` (image-layer leakage).
- [ ] CI: script injection via `${{ github.event.* }}` into `run:` blocks (cross-check supply-chain; file here for CI-context issues like missing `permissions:` blocks on privileged workflows).
- [ ] Over-privileged CI tokens: `contents: write`, environment secrets exposed to fork PRs, long-lived deploy keys with broad scope.
- [ ] Deployment configs exposing debug endpoints, admin panels, or bypassing auth at the edge (e.g. proxy rules that forward `/admin` unauthenticated).
- [ ] IaC: public-read buckets/security groups (`0.0.0.0/0` on management ports), IAM wildcards (`Action: "*"`, `Resource: "*"`), no MFA-delete/versioning on critical buckets.
- [ ] TLS: plaintext listeners for sensitive traffic, missing HSTS, weak cipher suites in server config, certificates with wildcard misuse across tenants.
- [ ] Security headers absent at the edge (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) — file when the app can't set them itself.
- [ ] Server config: directory listing enabled, `.git`/`.env` served by the web server, verbose proxy_pass of internal services.
- [ ] Serverless: publicly invokable functions doing privileged work, secrets in plaintext env config, IAM roles of functions overly broad (cross-check cloud-security).

## Evidence requirements

Cite the config file:line. For exposure claims, distinguish "configured
exposed" from "requires network access I have not verified" — the latter is
`needs_validation`, not `confirmed`.

## False-positive traps

- Dev-only compose overrides (`docker-compose.override.yml`) not used in prod (verify which file prod uses).
- Base image as root but process drops privileges via entrypoint script.
- Edge platform (Vercel/Cloudflare) injecting headers/auth independently of repo config.
- IaC files for sandbox/test accounts only (check the tfvars/workspace wiring).

## Output

Candidates per schema, category `infrastructure`.
