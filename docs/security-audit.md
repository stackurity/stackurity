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
| Server → registries (Syft) | Image layers | **Untrusted** | Strict image-reference pattern, `registry:` scheme forced, clean environment, output capped, every connection through a guarded proxy for workspaces without private network access |
| Server → feeds (OSV, KEV, endoflife.date, package registries) | Advisory and release data | Semi-trusted public data | Size caps, schema decoding, never executed, mirrorable; links inside registry documents are followed only on the same host; stale or failed feeds are shown, not trusted silently |
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
- The tests in section 4, including the workspace isolation sweep, run in `ci.yml` on every change; `fuzz.yml` fuzzes the parsers of untrusted input for longer when started by hand.

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

## 4. Verification: every stated control and the test that proves it

The documentation is the test specification. Each control stated on this page, in [SECURITY.md](../SECURITY.md), [design/workspaces.md](design/workspaces.md) and [network.md](network.md) has at least one test that fails if the control is removed. Tests that need PostgreSQL run when `STACKURITY_TEST_DATABASE_URL` is set; `make test-ee` runs the same suites, the isolation sweep included, in the licensed build. Fuzz targets run their seed corpus with `go test`; the `fuzz` workflow fuzzes each for a chosen time when started by hand.

### Workspace isolation

| Control | Tests |
|---|---|
| Every route is checked for cross-workspace access; a new route cannot skip it | `TestEveryRouteIsClassified` walks the chi router and fails for any route without an isolation rule (and for rules naming routes the edition no longer serves) |
| Workspace B never reads, counts, changes or deletes A's objects, by listing, guessed id, search, export (CycloneDX, reports, evidence), audit log, job status, notification routes, deliveries, integrations or secrets | `TestIsolationSweep`: every route, as every B credential (each role's session, an admin token, a collector token, a host-bound agent token), with A's ids; B's listings are identical with and without A's data; A's data, secret and credentials are unchanged afterwards. Also `TestWorkspaceIsolation`, `TestSearchWorkspaceIsolation`, `TestJiraWorkspaceBoundaries` |
| References stay inside the workspace (foreign keys ignore row-level security) | `TestCrossWorkspaceReferences` (API), `TestReferencesStayInTheirWorkspace` (database triggers, store and raw SQL from system scope) |
| Code without a scope sees no tenant rows | `TestNoScopeSeesNothing` |
| Every workspace table enforces row-level security; the application role cannot bypass it | `TestEveryTenantTableHasRowLevelSecurity` (fails for any new table without forced RLS and policies, unless listed as global with a reason); `testdb.New` refuses to run tests when the role bypasses RLS (`db.CheckIsolation`); `TestMigrateRestoresAppRoleGrants` |
| Periodic work runs once per active workspace, in its scope | `TestEveryWorkspaceScopes` |
| Secrets are never returned; another workspace can neither read nor decrypt them | `TestWorkspaceSecrets`, `TestIsolationSweep` (A's secret value never appears; B writing the same name creates its own) |
| `env:` and `file:` secret references only for instance admins | `TestWorkspaceSecrets` |
| Plugins outside the operator's workspace need explicit credentials | `TestPluginsNeedCredentialsOutsideDefault` |
| Instance administration only for instance admins | `TestIsolationSweep` (every instance route answers 403 to every workspace principal), `TestWorkspaceMembership` |
| Shared data (feeds) changed only by instance admins | `TestIntelEndpoints`, `TestIsolationSweep` |
| Switching workspace needs membership; the last admin stays | `TestWorkspaceMembership` |
| Shared accounts (and instance admins) cannot be taken over by a workspace admin | `TestWorkspaceMembership`, `TestWorkspaceAdminCannotTakeOverInstanceAdmin` |
| Revoked and expired tokens, tokens and sessions of removed or disabled users and of disabled workspaces are refused on the next request; a role downgrade applies on the next request | `TestCredentialChangesTakeEffectImmediately`, `TestChangeOwnPassword` |
| A collector reads back only collections it submitted; host-bound tokens report only their host | `TestCollectionResult`, `TestBoundTokenLimits`, `TestApplicationBatches` |

### Browser and API

| Control | Tests |
|---|---|
| CSRF header on cookie requests that change state; no anonymous access | `TestCSRFAndAuth` |
| Session cookie is HttpOnly, SameSite=Strict, Secure when configured | `TestSessionCookieAttributes` |
| Role-based access | `TestRoles`, `TestWorkflowRoles`, `TestIsolationSweep` |
| Sign-in, setup and password change are rate limited across replicas and fail closed | `TestSignInLimitPerAddressAcrossReplicas`, `TestSignInLimitPerAccount`, `TestSetupLimitAcrossReplicas`, `TestSignInLimitFailsClosed` |
| First-admin setup needs the setup token | `TestSetup` |
| Tokens, sessions and enrollment codes are stored only as hashes; passwords with argon2id | `TestSecretsAtRest` |
| No credential in logs, API answers (other than the one that hands it out) or audit entries | `TestSecretsNeverLogged`, `TestWebhookURLsNeverInErrors`, `TestCloneHardening`, `TestImageScanUsesGuardedProxy`, `TestHostilePluginOutput` |
| Enrollment codes: single or limited use, expiring, revocable, one refusal for every failure | `TestEnrollmentAndInstaller` |

### Outbound connections (SSRF)

| Control | Tests |
|---|---|
| Loopback, private, link-local (with or without a zone), CGNAT, unique local, IPv4-mapped and IPv4-compatible IPv6, NAT64, multicast and metadata addresses (169.254.169.254, fd00:ec2::254) are refused for workspaces without private access | `TestPolicy`, `TestEveryInternalCategoryIsRefused`, `TestZonedLinkLocalDial` |
| Decimal, octal, hexadecimal and short IPv4 notations are refused | `TestNonStandardIPv4Notation` |
| The address actually dialled is checked (DNS rebinding) | `TestDialChecksTheAddressActuallyUsed`, `TestDNSRebinding` (a resolver that answers public, then private) |
| Webhook, Slack, Teams, Jira and SMTP relay destinations | `TestChannelsRefuseInternalDestinations`, `TestJiraWorkspaceBoundaries` |
| Redirects are never followed | `TestRedirectsAreNeverFollowed` (301 to 308, to an internal address) |
| HTTPS required for webhooks unless allowed | `TestPayloads`, `TestWorkflowRoles` |
| Git: HTTPS only, no `ext::`, `file`, `ssh` or `git` transports, no credentials or query in the URL, pinned to the checked address, no hooks, submodules, LFS or symlinks, credential only in the environment and never in errors | `TestValidate`, `TestValidateRefusesNonHTTPSAndHiddenCredentials`, `TestCloneRefusesInternalDestinations`, `TestCloneHardening`, `TestCloneRejectsFileTransport` |
| Image scans: strict references, internal registries refused, every Syft connection checked through the guarded proxy | `TestValidate` (image), `TestImageScanRefusesInternalRegistries`, `TestImageScanUsesGuardedProxy`, `TestProxyChecksEveryTunnel` |
| Kubernetes API server and plugin targets follow the workspace's policy | `TestCollectSendsNetworkPolicy`, `TestNetworkPolicyIsEnforced`, `TestInternalAPIServersRefused` |
| Registry and repository documents: links followed only on the same scheme and host | `TestLinksStayOnTheRegistryHost` |

### Untrusted content

| Control | Tests |
|---|---|
| Batches: size, schema, purl and field limits | `FuzzBatch`, `TestMisbehavingPlugins` |
| SBOM import: size, depth and count limits; cycles harmless | `FuzzImport`, `TestHostileSBOMs` |
| Lockfiles: data only, bounded; one hostile entry cannot void a scan | `FuzzLockfiles`, `TestHostileLockfiles` |
| Advisory records and version comparison: bounded time, no panics | `FuzzRecord`, `FuzzComparators`, `TestHostileRecords` |
| updateinfo XML: no entity expansion or external entities, bounded | `FuzzParseUpdateInfo`, `TestHostileUpdateInfo` |
| Plugins: clean environment, deadline, output caps, validated batches, no app-path identities, own identity stamped, credentials redacted | `TestMisbehavingPlugins`, `TestHostilePluginOutput`, `FuzzPluginBatches`, `TestCappedHoldsUnderIOCopy` |
| Output caps of subprocesses (git, plugins, packs, runtime detection) hold | `TestCapBufferHoldsUnderIOCopy`, `TestCappedHoldsUnderIOCopy`, `TestLimitedBufferHoldsUnderIOCopy` |
| Stack packs run sandboxed and signed | `TestSandboxContainsHostilePacks`, `TestSignatures`, `TestManifestValidation` |
| Application directories: symlinks not followed except a release `current` link that resolves inside the application, credentials stripped from Git remotes, hostile package metadata skipped | `TestScanNodeApp`, `TestDiscoverAndReleases`, `TestReleaseLinkStaysInsideApp`, `TestHostilePackageMetadata` |
| Runtime detection: only safely owned binaries, fixed argument, empty environment, capped output, off with `--no-runtimes` | `TestUnmanagedRuntimes`, `TestRuntimesDisabled`, `TestLimitedBufferHoldsUnderIOCopy` |
| Agent actions: allowlist, strict names, no shell, dry run first, removals refused | `TestRefusals`, `TestAllowlistFile`, `TestDryRunRemovalsAreRefused`, `TestDryRunFailureStops`, `TestRollbackRefusesRemovals` |

### Not provable by a test

Some commitments are design properties checked by review rather than tests: no telemetry or update checks (every outbound client is listed in [network.md](network.md)), and Stackurity never executing code from what it inspects (the clone and parser tests above show the hardening, not the absence of every other path).

### Findings of the October 2026 verification

Writing these tests found and fixed the following; each fix is its own commit with the impact described.

| Severity | Issue | Fix |
|---|---|---|
| High | Any workspace admin could disable shared intelligence feeds for every workspace | Feed changes need an instance admin |
| Medium | A workspace admin could set the password of an instance admin whose only workspace was theirs | Account changes to instance admins need an instance admin |
| Medium | Zoned IPv6 link-local addresses (`fe80::1%eth0`) passed the private-network check everywhere | The zone is dropped before checking; more IPv6 ranges blocked |
| Medium | A workspace could point its routes, assets, findings and teams at another workspace's channels, teams and users (foreign keys ignore RLS), and probe their ids | Migration 0025 triggers |
| Medium | Output caps on plugin, git, pack and runtime output were never applied (embedded `bytes.Buffer` brings `ReadFrom`) | Buffers are named fields |
| Low | Syft made its own connections after a single DNS check (rebinding, redirects) | Syft runs through a guarded CONNECT proxy |
| Medium | Very long versions made each comparison slow enough for one batch to occupy the shared evaluator for hours | Versions over 256 characters are not compared |
| Low | Git clone pinning could be bypassed with IPv4 in decimal or hex notation; tokens in repository URL queries reached errors and asset attributes | Non-standard notations and URL queries refused |
| Low | One hostile lockfile or package entry made the whole batch invalid, hiding every other package | Unusable entries are skipped and reported as partial coverage |
| Low | A release `current` link could reach outside the application through a release that is itself a link | The release must resolve inside the application |
| Low | Webhook URLs in percent-encoded form leaked into stored delivery errors | Every form of the URL is redacted |
| Low | Passwords typed into the email field were stored in the audit log; malformed Git and Kubernetes URLs were echoed with credentials | Only existing accounts are recorded; URLs are not echoed |

## 5. Reporting

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
