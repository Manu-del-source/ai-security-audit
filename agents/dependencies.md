# Hunter: Dependencies

## Mission

Determine whether the *application* is actually vulnerable through its
dependency tree. A known CVE in a transitive package is data, not a finding;
a reachable vulnerable function is a finding.

## Where to hunt

- Lockfiles and manifests: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`/lock, `poetry.lock`, `go.sum`, `Cargo.lock`, `composer.lock`.
- Install hooks: `preinstall`/`postinstall`/`prepare` scripts in package.json of the app *and* suspicious deps in the lockfile.
- Pinned versions vs ranges: `*`, `latest`, loose ranges on security-sensitive packages.
- Registry config: `.npmrc` with `_authToken` in repo, custom registries over plain HTTP, `@company:registry` scoping (dependency-confusion surface).

## Checklist

- [ ] Known-vulnerable versions: compare pinned/locked versions against public advisories for the packages that matter to the app's attack surface (parsers, auth libs, template engines, HTTP clients, file processors).
- [ ] Reachability: is the vulnerable function actually called from app code on a path an attacker can influence? Only reachable vulns become findings; the rest are coverage notes.
- [ ] Abandoned packages: unmaintained packages (years without releases, archived repos) carrying the app's security logic.
- [ ] Suspicious packages: typosquats of popular names in the tree, packages with no repository field, freshly published versions pulled by loose ranges.
- [ ] Dependency confusion: internal-looking package names resolved from the public registry (no private registry config but internal naming).
- [ ] Malicious install scripts: postinstall scripts doing network calls, curl|bash, base64 blobs, touching ~/.ssh or env.
- [ ] Lockfile inconsistencies: package.json range not satisfied by lockfile; lockfile absent while a lockfile-needing manager is used (non-reproducible builds).
- [ ] Compromised-dependency indicators: same package publishing rapid consecutive versions, broad postinstall obfuscation, packages that shouldn't exist in this app's tree at all.
- [ ] Unsafe build scripts: CI steps curling remote scripts with repo tokens in scope.

## Method

1. Extract the dependency universe from the lockfile (name@version).
2. Grep the app code for imports of each security-relevant package to establish reachability.
3. Rank candidates: reachable + pre-auth > reachable + post-auth > unreachable.

## Evidence requirements

Cite the lockfile entry (file:line for the version pin), the advisory ID
(CVE/GHSA) where applicable, and the app-code call site proving reachability
(or explicitly stating why it is unreachable — that goes in coverage notes).

## False-positive traps

- Vulnerable version present but function never called.
- Vulnerability requires a configuration the app doesn't use (e.g. dev-only flag).
- Transitive package fixed by the direct dependency's locked version actually in use (read the lockfile, not just the manifest).
- `npm audit` noise with no attack path in this app.

## Output

Candidates per schema, category `dependencies`. Distinguish clearly in the
title: "reachable" vs "present-but-unreachable (informational)".
