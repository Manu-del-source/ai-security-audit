# Hunter: Supply Chain

## Mission

Assess integrity of the pipeline that turns source into running software:
who can push code, what runs on install/build/publish, and whether artifacts
can be tampered with. Distinct from Dependencies (which is about known
vulnerabilities in pinned code).

## Where to hunt

- Package manager configs: `.npmrc`, `.yarnrc.yml`, `pip.ini`, `cargo/config.toml`, `composer.json` repositories section.
- Publish scripts and `files` allowlists in package.json; setup.py/package-level hooks.
- Build pipelines: `.github/workflows/*`, Dockerfiles with remote fetches, Makefile targets.
- Git hooks: `.husky/*`, `lefthook.yml`.
- Vendored or committed binaries/bin-scripts whose source isn't in the repo.

## Checklist

- [ ] Install scripts in app dependencies with network/exec behavior (cross-check dependencies; file here when the *pattern* is systemic).
- [ ] Dependency confusion surface: internal package names without registry scoping; `postinstall` fetching from untrusted hosts.
- [ ] Lockfile manipulation: manual edits, versions not matching any registry checksum (verify when suspicious), mixed lockfiles.
- [ ] CI permissions: workflows with `pull_request_target` checking out PR head and running it with secrets; `contents: write` on untrusted input; script injection from `${{ github.event.* }}` into `run:`.
- [ ] Third-party Actions pinned by tag/mutable ref instead of SHA (supply-chain pivot risk), especially privileged ones.
- [ ] Publish workflow abuses: workflows that publish packages triggered by untrusted events; NPM_TOKEN/PyPI tokens in workflow scope without environment protection.
- [ ] Build over plain HTTP: Dockerfile `curl http://`, pip without `--require-hashes`, apt from unsigned repos.
- [ ] Vendored blobs: checked-in binaries, minified files without source, "util" scripts with obfuscation.
- [ ] Release integrity: no lockfile in published artifact, no provenance/attestation where ecosystem supports it (informational).

## Evidence requirements

Cite the config file:line and describe the exploit primitive concretely
("workflow runs PR-head code with `secrets.NPM_TOKEN` in scope because of
`pull_request_target` + explicit checkout of `refs/pull/*/head`").

## False-positive traps

- `dependabot.yml`/Renovate keeping deps pinned and reviewed.
- Workflows with `pull_request` (not `pull_request_target`) — they run without secrets.
- Actions pinned to full commit SHAs.
- Internal packages genuinely published to the same public registry under a scoped name (`@company/...`) — scoping prevents confusion for npm; not for pip.

## Output

Candidates per schema, category `supply-chain`.
