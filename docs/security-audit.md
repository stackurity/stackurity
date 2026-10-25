# Security review of Stackurity itself

This page covers PRD FR-18: a repeatable, evidence-led way to review Stackurity's own code, plugins, build pipeline, deployment and releases. AI-assisted review is optional. Nothing here is needed to run Stackurity.

## 1. Map the system first (coverage before findings)

### Trust boundaries

| Boundary | Inbound data | Trust | Main controls |
|---|---|---|---|
| Browser → API | User actions | Authenticated users, by role | Session cookie (HttpOnly, SameSite=Strict, Secure), CSRF header, RBAC, rate-limited login and setup, audit log |
| Agent, CI or plugin → `/ingest`, `/sbom/import` | Observation batches, SBOMs | **Untrusted content** from authenticated collectors | Size limits (64 MiB wire, 256 MiB decompressed, 200k observations), schema and purl validation, host-bound tokens can only report their own asset (and applications whose `runs_on` host is that asset, as app-path identities are scoped to the host server-side); a collector token reads back findings only through `/collections/{id}/result` for collections it submitted |
| New host → `/enroll`, `/install/agent.sh`, `/download/agent/*` | Enrollment code; installer and agent binary | **Unauthenticated** endpoints | Codes are 32-byte random, stored hashed, single or limited use, expiring (default 24 h), revocable and audited; `/enroll` is rate limited per IP and gives one refusal for every failure; the installer verifies the binary's SHA-256 from the same HTTPS origin (TLS is the root of trust) and refuses plain HTTP except to local ports; settings written to the systemd EnvironmentFile are restricted server-side and re-checked by the agent |
| Agent → application directories | Installed package metadata and lockfiles | **Untrusted content** on the host | Read as data with size caps (1 MiB manifests, 64 MiB installed.json) and a 100,000-package limit per application; symlinks not followed except a release layout's `current` link, which must stay inside the application; credentials stripped from Git remote URLs |
| Agent → local binaries (runtime detection) | Version output | Host binaries, run with the agent's privileges | Only binaries owned by root or the agent's uid with no group- or world-writable path component, fixed `--version` argument, empty environment, 5-second timeout, 64 KiB output cap, never under `--root`; disabled with `--no-runtimes` |
| Server → Git hosts | Repository contents | **Untrusted** | HTTPS only, `protocol.allow=never` except https, no hooks, submodules, LFS or symlinks, files parsed as data, clone deleted afterwards |
| Server → registries (Syft) | Image layers | **Untrusted** | Strict image-reference pattern, `registry:` scheme forced, clean environment, output capped |
| Server → feeds (OSV, KEV, endoflife.date, npm, Packagist) | Advisory and release data | Semi-trusted public data | Size caps, schema decoding, never executed, mirrorable; stale or failed feeds are shown, not trusted silently |
| Server → plugins | Plugin output | **Untrusted executables**, installed by an admin | Admin-only directory, permission checks, clean environment, scratch directory, deadline, output caps, batches validated, no remediation path |
| Server → agents (`/agent/actions`) | Approved changes | Agents trust the server, within their local allowlist | Host-bound tokens, policy and approval re-checked at dispatch, local allowlist, strict name/version patterns, no shell, dry run first |
| Server → notification channels | Outbound messages | Admin-configured endpoints | Secrets referenced not stored, redirects never followed, HTTPS required by default, signed webhooks |
| Operator → secrets | Credentials | Trusted | Only `env:STACKURITY_SECRET_*` or `file:` under the secrets directory; tokens and sessions stored as SHA-256 hashes; passwords hashed with argon2id |

### Privileged operations

- Creating users, tokens, policies and channels, and deleting assets (admin).
- Approving remediation plans (security; admin for major upgrades).
- Agents running with `--remediate` (root on the host).
- Running plugin executables.
- The agent running installed binaries' version flags for runtime detection.

### Input surfaces to review

- HTTP handlers in `internal/api`.
- Every parser in `internal/collect`, `internal/sbom`, `internal/intel` and `internal/osv`.
- Plugin I/O in `internal/plugins`.
- Agent actions in `internal/agentfix`.

## 2. Automated checks (every change)

`.github/workflows/security.yml` runs these. All of them are static or dependency checks:

- `govulncheck`: Go vulnerabilities that are actually reachable.
- OSV-Scanner on `go.mod` and `web/package-lock.json`, plus `npm audit` for runtime dependencies.
- CodeQL for Go and TypeScript.
- Dogfooding: Stackurity inventories its own lockfiles, and the batch is kept as a release artifact.

The release pipeline (`release.yml`) publishes SHA256 checksums signed with Sigstore (keyless), build provenance attestations, a CycloneDX source SBOM, and a signed multi-arch image with an SBOM and provenance.

To verify a download:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/stackurity/stackurity/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

## 3. Manual or AI-assisted review (optional)

Work through the boundaries above one at a time. For each candidate issue, record it in this format so it can be validated independently and reported from verified records:

```json
{"id": "SR-2026-001", "component": "internal/plugins", "boundary": "Server → plugins",
 "title": "…", "verdict": "candidate|confirmed|rejected",
 "evidence": ["file:line", "request/response", "test name"],
 "impact": "what an attacker gains, concretely", "confidence": "low|medium|high",
 "validation": {"method": "unit test|reproduction|second reviewer", "by": "…", "status": "needs_validation|validated"}}
```

Rules:

- **Validate high-impact candidates independently**, with a second reviewer or a failing test, before calling them confirmed. Missing validation is recorded as `needs_validation`, never silently dropped.
- **A deviation from a checklist is not a vulnerability** unless there is evidence of a concrete impact.
- **Never execute untrusted repository code, build scripts, tests or plugins on your workstation or CI host** as part of review. If dynamic validation is needed, use an OS-enforced sandbox with:
  - no network by default
  - read-only target and toolchain mounts
  - a sanitised environment
  - scratch-only writes
  - CPU, memory, process, disk and time limits

  If those controls are not available, don't execute anything. Record the candidate as `needs_validation` and note what remains unverified.
- **Don't probe production or shared infrastructure.** Live testing needs separate authorisation and an agreed scope.

Security-relevant fixes ship with a test that shows the protection holds. The existing suites follow this rule: CSRF, RBAC, bound tokens, setup token, clone hardening, plugin isolation, agent input validation, header injection and redirect handling.

## 4. Reporting

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
