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
| Slack → `/integrations/slack/actions` | Button clicks (Slack's payload) | **Unauthenticated** endpoint; trusted only once Slack's signature verifies | The channel named in the button's value must be an enabled Slack channel with a signing secret, in an enabled workspace; that channel's secret must verify the `v0` HMAC-SHA256 signature over the exact body (constant-time compare); timestamp within 5 minutes; each signature accepted once; the Slack workspace must match the channel's webhook; answers only to `hooks.slack.com` response URLs; the clicker acts only through a linked account (see [Acting from Slack](#acting-from-slack)) |
| Operator → secrets | Credentials | Trusted | Only `env:STACKURITY_SECRET_*` or `file:` under the secrets directory; tokens and sessions stored as SHA-256 hashes; passwords hashed with argon2id |

### Privileged operations

- Creating users, tokens, policies and channels, and deleting assets (admin).
- Approving remediation plans (security; admin for major upgrades).
- Agents running with `--remediate` (root on the host).
- Running plugin executables.
- The agent running installed binaries' version flags for runtime detection.

### Input surfaces to review

- HTTP handlers in `internal/api`, including the public Slack interactivity endpoint (`internal/api/slack.go`).
- Every parser in `internal/collect`, `internal/sbom`, `internal/intel` and `internal/osv`.
- Plugin I/O in `internal/plugins`.
- Agent actions in `internal/agentfix`.

## 2. Automated checks (every change)

`.github/workflows/security.yml` runs these. All of them are static or dependency checks:

- `govulncheck`: Go vulnerabilities that are actually reachable.
- OSV-Scanner on `go.mod` and `web/package-lock.json`, plus `npm audit` for runtime dependencies.
- CodeQL for Go and TypeScript.
- Dogfooding: Stackurity inventories its own lockfiles, and the batch is kept as a release artifact.
- The tests in section 4, including the workspace isolation sweep, run in `ci.yml` on every change; the isolation suite also runs as its own **Workspace isolation** check, which blocks a release when it fails (section 6). `fuzz.yml` fuzzes the parsers of untrusted input for longer when started by hand.

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
| Content-Security-Policy allows no inline styles or scripts (`style-src 'self'`; every dashboard page was checked in a browser for violations), and no `Server` or `X-Powered-By` header names the software | `TestCSPHasNoUnsafeInline` |
| Role-based access | `TestRoles`, `TestWorkflowRoles`, `TestIsolationSweep` |
| Sign-in, setup and password change are rate limited across replicas and fail closed | `TestSignInLimitPerAddressAcrossReplicas`, `TestSignInLimitPerAccount`, `TestSetupLimitAcrossReplicas`, `TestSignInLimitFailsClosed` |
| First-admin setup needs the setup token | `TestSetup` |
| Tokens, sessions and enrollment codes are stored only as hashes; passwords with argon2id | `TestSecretsAtRest` |
| No credential in logs, API answers (other than the one that hands it out) or audit entries | `TestSecretsNeverLogged`, `TestWebhookURLsNeverInErrors`, `TestCloneHardening`, `TestImageScanUsesGuardedProxy`, `TestHostilePluginOutput` |
| Enrollment codes: single or limited use, expiring, revocable, one refusal for every failure | `TestEnrollmentAndInstaller` |
| Slack clicks: only a request signed with the signing secret of the channel its button names is acted on; bad signature, another channel's or workspace's secret, a channel without a secret or disabled, a timestamp over 5 minutes old or ahead, a replay, another Slack workspace and a foreign `response_url` are refused | `TestSlackSignatureVerification` |
| Linking a Slack account: single use, 15 minutes, in the channel's workspace only, a browser session only, never taking over an account linked to someone else; each person lists and removes only their own links | `TestSlackAccountLinking`, `TestIsolationSweep`, `TestProjectIsolationSweep` |
| A linked Slack click has the person's dashboard permissions (role, project access, removed members refused) and is audited like the dashboard with source `slack` | `TestSlackActionPermissions` |
| Channels without a signing secret send exactly the earlier link buttons; interactive buttons only when the secret resolves; the secret never appears in messages | `TestSlackInteractiveButtons`, `TestDispatcherInteractiveOnlyWithSigningSecret`, `TestSlackChannelSigningSecretRef` |
| Two-factor sign-in: the password alone does not sign in; TOTP per RFC 6238 within one step either side; a code (including the one that confirmed enrolment) is never accepted twice; recovery codes work once and are stored hashed; five wrong codes end the sign-in, ten per account per 15 minutes; API tokens unaffected | `TestTOTPVectors`, `TestCheckTOTPWindow`, `TestRecoveryCodes`, `TestMFASignIn`, `TestMFAChallengeEndsAfterFailures` |
| Password reset: the same answer whether or not the account exists, and nothing emailed for an unknown address; the link is built from `STACKURITY_BASE_URL`, works once and for 15 minutes; a reset ends every session, revokes tokens when asked, and keeps two-factor sign-in; requests are limited per address and per email | `TestPasswordReset`, `TestPasswordResetLimitedPerEmail`, `TestPasswordResetKeepsMFA` |
| New passwords found in known breaches are refused at setup, change, reset, invitation and by admins; only a 5-character SHA-1 prefix is sent; an unreachable check accepts the password | `TestBreachCheckSendsOnlyThePrefix`, `TestBreachCheckFailsOpen`, `TestBreachedPasswordsRefused` |
| Failing on purpose from many addresses does not lock out the owner's recent addresses; other addresses still stop at the account cap | `TestSignInAccountCapSparesKnownAddress` |
| Sessions end after the idle timeout and 12 hours; expiry and sign-out are audited; a sign-in ends the browser's previous session; a password change ends other sessions, rotates the current one, disconnects assistants by default and revokes tokens when asked | `TestSessionIdleAndAbsoluteExpiry`, `TestSessionRotation`, `TestPasswordChangeRevocation` |
| A password an admin sets for someone else is temporary: until it is changed the session can do nothing else | `TestTemporaryPassword` |
| "Require two-factor sign-in": a password session without a second factor can only enrol (no data, no tokens) and cannot turn it off; single sign-on sessions are not affected; an admin reset ends the member's sessions and is audited; a workspace admin cannot reset an instance admin's | `TestRequireMFAForMembers`, `TestResetMFAOfInstanceAdmin` |

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
| Scan jobs: disk, walk, depth and coverage limits; NUL and control characters cleaned; unsafe links dropped; plugin metadata bounded (1.0, see the next section) | `TestCloneSizeLimit`, `TestImageScanSizeLimit`, `TestWalkLimits`, `TestWalkStopsWithItsContext`, `TestOversizedLockfile`, `TestCoverageIsCapped`, `TestIngestLimits`, `TestUntrustedOutputIsCleaned`, `TestUntrustedIdentityIsRefused`, `TestUnsafeLink`, `TestKeepUsable`, `TestLongEvidenceIsClipped`, `TestHostilePluginMetadata` |
| Output caps of subprocesses (git, plugins, packs, runtime detection) hold | `TestCapBufferHoldsUnderIOCopy`, `TestCappedHoldsUnderIOCopy`, `TestLimitedBufferHoldsUnderIOCopy` |
| Stack packs run sandboxed and signed | `TestSandboxContainsHostilePacks`, `TestSignatures`, `TestManifestValidation` |
| Application directories: symlinks not followed except a release `current` link that resolves inside the application, credentials stripped from Git remotes, hostile package metadata skipped | `TestScanNodeApp`, `TestDiscoverAndReleases`, `TestReleaseLinkStaysInsideApp`, `TestHostilePackageMetadata` |
| Runtime detection: only safely owned binaries, fixed argument, empty environment, capped output, off with `--no-runtimes` | `TestUnmanagedRuntimes`, `TestRuntimesDisabled`, `TestLimitedBufferHoldsUnderIOCopy` |
| Agent actions: allowlist, strict names, no shell, dry run first, removals refused | `TestRefusals`, `TestAllowlistFile`, `TestDryRunRemovalsAreRefused`, `TestDryRunFailureStops`, `TestRollbackRefusesRemovals` |

### Scan jobs outside the packs sandbox

Stack packs run in their own sandbox ([packs.md](packs.md)). Everything else that runs a scanner or parses scan output is listed here with its time, size and count limits and how its output is treated before it is stored, shown or acted on. "1.0" marks what the Proof release added after reviewing each path; the rest was already there.

| Path | Time | Memory, output and disk | Files and entries | Output treated as untrusted |
|---|---|---|---|---|
| Git repository scan (server, `internal/collect/gitrepo`) | 10 minutes per scan (the worker's 20-minute job limit behind it); 1.0: the deadline kills git's whole process group, helpers included | git stderr 64 KiB; 1.0: the clone may use at most 1 GiB on disk, measured while git runs, then git is stopped | 1.0: as lockfiles below | https only, no credentials in the URL, host checked and pinned, no hooks, symlinks, LFS or submodules; the batch is validated |
| Lockfiles (repositories, CI, application directories; `internal/collect/lockfile`) | 1.0: the walk stops with the scan's deadline (it ignored it); `git ls-files` 30 seconds | 64 MiB per lockfile, read with a limit; 1.0: files held for stack packs at most 512 MiB in total, `git ls-files` output at most 16 MiB | 1.0: at most 500,000 files and directories and 64 levels, each shown as partial coverage; coverage capped at 1,000 items so the batch is not refused | Data only; one hostile entry is dropped, not the scan (`model.Usable`); coverage text clipped |
| Container image scan (server, `internal/collect/image`) | 15 minutes; 1.0: the deadline kills Syft's whole process group | Syft's SBOM at most 64 MiB, stderr 64 KiB; 1.0: at most 4 GiB of layers on disk, measured while Syft runs | As SBOM import | Reference and platform checked by strict patterns, registry reached through the guarded proxy; the SBOM is imported as below |
| SBOM import (`internal/sbom`, `POST /sbom/import`) | The HTTP server's 5-minute read limit | 64 MiB on the wire, 256 MiB after gzip (1.0: tested), document 64 MiB | 200,000 components, nesting 32 | Validated as a batch; 1.0: an over-long supplier or reference is clipped instead of refusing the whole document |
| Inventory upload (`POST /ingest`) and every batch above (`model.Validate`) | As SBOM import | As SBOM import (1.0: tested) | 200,000 observations, 1,000 coverage items, 32 identifiers, 16 relations, 32 evidence fields | Unknown fields refused, purls parsed, field lengths bounded. 1.0: NUL and control characters removed from text (one NUL used to fail the whole ingest), refused in purls and versions, environment, provider and region at most 256 bytes, and a link value (`*url*`, `link`, `homepage`) with a `javascript:`, `data:`, `vbscript:` or `file:` scheme dropped before it is stored. The dashboard also renders only http and https links (`safeHttpUrl`) |
| Plugins (`internal/plugins`) | 15 minutes on the server (metadata and validation 30 seconds, health 1 minute); the process group is killed | stdout 128 MiB, stderr 256 KiB | 1,000 batches per run | Each batch validated; identity stamped, app-path identities refused, credentials redacted. 1.0: metadata bounded (names 256 bytes, description 4 KiB, lists 100 entries of 512 bytes) and its homepage must be an http or https address |
| Host agent: OS packages, runtimes, applications (`internal/collect/linux`, `windows`, `apps`) | rpm 2 minutes, runtime probes 5 seconds and 1 minute; 1.0: each collection at most 30 minutes, and the application walk stops with it | Scanner lines 16 MiB, runtime output capped, manifests 1 MiB, `.git/config` 256 KiB | 100,000 packages per application, 200 runtime candidates, node_modules depth 32 | Applications drop bad entries; 1.0: OS package and Windows batches drop entries the server would refuse instead of failing the batch, and say so |

What scan output can trigger: findings, notifications (text, never commands) and the completion of a **Check again**. Remediation commands come from the stored advisory data and an allowlist, never from scanner text ([remediation.md](remediation.md)). A scanner's output is never executed and never followed as a URL by the server.

Not added, on purpose: a per-package-count limit in the Linux and Windows collectors (the server's 200,000 observations per batch applies), and a size limit on the agent's own reads of the package database (it is the host's own data, read by its owner).

### Acting from Slack

Slack channels set up with a Slack app's signing secret carry interactive **Assign to me** and **Snooze 1 week** buttons, and Slack sends each click to the public `POST /api/v1/integrations/slack/actions` (`internal/api/slack.go`).

**Signature verification.** The endpoint reads at most 64 KiB, then the button's value (`stk1|<channel>|<action>|<fix>`). It looks the channel up across workspaces (it must be an enabled `slack` channel of an enabled workspace with `signing_secret_ref`), resolves that channel's signing secret in the channel's workspace, and compares `v0=` HMAC-SHA256 of `v0:<X-Slack-Request-Timestamp>:<body>` with `X-Slack-Signature` in constant time. The workspace therefore comes from the channel whose secret verified the exact bytes, never from the payload alone: a payload naming another channel fails unless signed with that channel's secret. Every failure before verification gets the same 401, so channel ids and their configuration cannot be probed. The timestamp must be within 5 minutes either way, and the SHA-256 of the signature is stored per workspace (`slack_seen_requests`, kept 10 minutes): a replay is refused. After verification, the team and user ids must look like Slack ids, the click must come from the Slack workspace of the channel's webhook URL (when it can be told), and `response_url` must be `https://hooks.slack.com/...` (or `hooks.slack-gov.com`), so a signed payload can never make the server post elsewhere. Answers go out without redirects, through the same address checks as other outbound requests, and the response URL is never logged. The signing secret is a secret reference like every other (env: and file: references for instance administrators only) and is never returned, logged or put in a message; if it cannot be read, messages fall back to link buttons and clicks are refused.

**Account linking.** Without a bot token Stackurity cannot read a Slack user's email, so a Slack user is never matched to an account by name or email. The first click of a Slack user gets an ephemeral reply (visible to them only) with `/slack/link#<token>`: 32 random bytes, stored as SHA-256 in the channel's workspace (`slack_link_requests`), single use, 15 minutes; a new click replaces an unused one. The token travels in the URL fragment and request bodies only. Confirming needs a signed-in browser session (API tokens are refused) in the same workspace (row-level security makes another workspace's token unknown), shows the Slack user and workspace being linked, and refuses a Slack account already linked to someone else (409; they must unlink first), so a forwarded link cannot take over a linked account. Links (`slack_links`) are per workspace with row-level security; a member with project access only sees only their own, and the API lists and deletes only the caller's. The linked user must be a member (database trigger). Linking and unlinking are audited (`slack_link.create`, `slack_link.delete`).

**Acting.** A linked click runs as the linked person: their current membership (removed or disabled accounts are refused), organisation role and project roles are read at click time, the request is scoped like theirs (workspace, and member narrowing for project-only members), and the dashboard's own handler (`POST /findings/actions`, with `requireRole(engineer)`, `checkAction` and the per-asset role check) does the change in batches of 500 over the fix's open issues as that person sees them (at most 2,000). Audit entries and finding history are the dashboard's, with `source: slack` and the Slack ids. The risk of the design: anyone who controls a linked Slack account acts as its Stackurity user, as with any single sign-on; people should only link their own Slack account (the confirmation page says so) and can unlink at any time.

### AI assistants (remote MCP and OAuth)

Assistants reach `/mcp` and sign in through the OAuth endpoints (`internal/api/assistants.go`, `internal/store/assistants.go`, `internal/mcp`). See [ai-assistants.md](ai-assistants.md#how-sign-in-works).

**Tokens and codes.** Authorization codes (`stkx_`), access tokens (`stka_`) and refresh tokens (`stkr_`) are 32 random bytes, stored as SHA-256 only, looked up in system scope and then scoped to the connection's workspace like API tokens. Codes are single use, 2 minutes, bound to client, redirect URI and an S256 PKCE challenge; a reused code revokes the connection made with it, and a replayed refresh token revokes its connection (`TestAssistantOAuth`). Confidential clients' secrets are compared as hashes in constant time.

**Audience.** An access token is accepted only on requests the `/mcp` tools make in process (a context value nothing outside the server can set); the API answers 401 to it directly. `/mcp` reads no cookies, so CORS (allowed for any origin on the discovery, OAuth and MCP paths) lends a page nothing, and `Origin: null` is refused.

**Consent and scope.** Only a signed-in browser session may allow a connection (API tokens and assistants are refused), in its active workspace (the decision names the workspace the page showed, and is refused if the session switched), on a project it can see, with a role no higher than its own. "Allow changes" is separate and off by default; a connection without it is refused every request but GET by `projectGate`. Every request then acts with the lower of the connection's role and the person's current role, narrowed to their projects and to the connection's project (`projectGate`): a connection limited to a project is refused organisation routes and any other project, and sees no other project's names, people or teams. Its context is bound to the project (`tenant.WithBoundProject`): `tenant.WithoutProject`, which handlers use to widen to the workspace, keeps the narrowing, and ignoring on every asset (`Server.everywhere`) refuses it (`TestBoundProjectStays`, `TestAssistantProjectIsolation`). Assistants are refused account routes other than `GET /auth/me` and instance administration. Isolation is tested per tool across workspaces (`TestAssistantWorkspaceIsolation`) and projects (`TestAssistantProjectIsolation`), and `/mcp` is part of the route sweeps.

**Redirects and clients.** Redirect URIs are HTTPS, loopback HTTP or an app scheme in reverse-DNS form (never `intent:`, `ms-*`, `javascript:`, `data:`, `file:` and similar), compared exactly (only a loopback port may differ), and the token request must repeat the code's. The issuer and resource come only from `STACKURITY_BASE_URL`; without it the endpoints are off. Registration is limited per address (IPv6 per /64) and capped while unused registrations wait; wrong tokens at `/mcp` are limited per address. An invalid client or redirect URI is shown on the consent page and never redirected to. Client ID metadata documents are fetched through the outbound address guard, without redirects, at most 64 KiB in 5 seconds, and must name their own URL as `client_id` (`TestAssistantClientKinds`).

**Changes.** Tools that change something are offered only with "Allow changes" (or `--allow-writes` for stdio), and make a change only when called with the confirm code of a preview of that exact change. The code is a digest, not a secret or a consent: it guards against model mistakes, while the person's choice and role decide, and the API's role checks and audit apply to every change (`TestWriteToolsNeedConfirmation`, `TestReadOnlyByDefault`, `TestAssistantRoles`). No secret goes to the model but the install command it was asked for (an install code for at most 50 servers and 24 hours): invitation links are never returned.

### Not provable by a test

Some commitments are design properties checked by review rather than tests: no telemetry, and no request to the project beyond the update check and feedback a user sends on purpose (every outbound client is listed in [network.md](network.md)), and Stackurity never executing code from what it inspects (the clone and parser tests above show the hardening, not the absence of every other path).

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

## 6. Tenant-isolation incidents

A tenant-isolation failure is any way a principal of one workspace (a session, an API token, a collector or agent token) can read, count, change, delete or learn the existence of another workspace's data, or any way background work (an evaluation, a notification, an export, a Jira issue) carries one workspace's data into another. On an installation that hosts several organisations this is the most serious class of bug Stackurity can have. This section is the process for one, whether it is reported from outside, found in review, or shown by a failing test.

### Report

- **From outside, or as an operator:** report privately as described in [SECURITY.md](../SECURITY.md), marked "tenant isolation". Include the version, the edition, the workspaces and principals involved (ids, not data), the request or steps, and the time window. Do not test further against workspaces you do not own.
- **Found by a maintainer or a test:** open a private security advisory on the repository at once, not a public issue or pull request.

Isolation reports are triaged as critical until shown otherwise and handled before anything else.

### Triage

Work from a copy where you can: take a `pg_dump` of the database and keep the server and reverse-proxy logs for the window before changing anything.

1. **Establish the window and the principals.** From the report: the workspaces (ids), users, tokens (`api_tokens.id`, `last_used_at`, updated at most once a minute) and the times.
2. **Pull the request logs.** The server logs every request as an `http` line with method, path, status, duration and `request_id` (query strings are never logged). Match them to the reverse proxy's logs for client addresses. Look for requests from the suspected principal to ids that belong to another workspace, and for unusual 200s on routes that should have answered 404.
3. **Pull the audit events.** Changes are audited per workspace, including sign-ins, token and user changes, workspace changes and switching workspace (`auth.login`, `auth.login_failed`, `token.create`, `token.revoke`, `user.update`, `workspace.update`, `workspace.enter`). Reads are not audited; the request logs cover them.

   ```sql
   -- psql as the database login role. If it is not a superuser, first let the
   -- policies show every workspace for this session:
   SELECT set_config('stackurity.scope', 'system', false);

   SELECT at, workspace_id, actor_type, actor_id, actor_name, action, object_type, object_id, remote_addr, detail
   FROM audit_events
   WHERE at BETWEEN '2026-10-01 00:00Z' AND '2026-10-02 00:00Z'
     AND (actor_id = 42 OR workspace_id IN (1, 2))
   ORDER BY at;
   ```

4. **Run the isolation suite against the affected version.** `STACKURITY_TEST_DATABASE_URL=... tools/release-checks/isolation.sh` (add `-tags ee -overlay ee-overlay.json` after `make ee-overlay` for the licensed build). Then reproduce the report as a test, normally a new rule or case in `TestIsolationSweep` (`internal/api/sweep_test.go`): that test is the proof of the bug and, once fixed, of the fix.
5. **Check the database's own enforcement** on the affected installation:

   ```sql
   -- Tables without forced row-level security or without policies. Only the
   -- global tables listed in internal/db/rls_test.go may appear.
   SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, count(p.polname) AS policies
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   LEFT JOIN pg_policy p ON p.polrelid = c.oid
   WHERE n.nspname = current_schema() AND c.relkind = 'r'
   GROUP BY 1, 2, 3
   HAVING NOT (c.relrowsecurity AND c.relforcerowsecurity) OR count(p.polname) = 0
   ORDER BY 1;

   -- The application role must not bypass row-level security.
   SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'stackurity_app';

   -- As the application role (the login role is a member when the migration
   -- created it), a workspace scope sees only its own rows, and no scope
   -- sees none.
   BEGIN;
   SET LOCAL ROLE stackurity_app;
   SELECT set_config('stackurity.scope', '', true), set_config('stackurity.workspace_id', '', true);
   SELECT count(*) FROM assets;                                     -- 0: no scope
   SELECT set_config('stackurity.workspace_id', '2', true);
   SELECT DISTINCT workspace_id FROM assets;                        -- only 2
   SELECT DISTINCT workspace_id FROM findings;                      -- only 2
   SELECT DISTINCT workspace_id FROM audit_events;                  -- only 2
   ROLLBACK;

   -- Rows pointing at another workspace's rows (foreign keys ignore
   -- row-level security; migration 0025's triggers refuse new ones). Each
   -- query must return nothing. Run with the system scope set as above.
   SELECT r.id FROM routes r JOIN channels c ON c.id = r.channel_id WHERE r.workspace_id <> c.workspace_id;
   SELECT d.id FROM deliveries d JOIN channels c ON c.id = d.channel_id WHERE d.workspace_id <> c.workspace_id;
   SELECT f.id FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.workspace_id <> a.workspace_id;
   SELECT i.id FROM incidents i JOIN teams t ON t.id = i.owner_team_id WHERE i.workspace_id <> t.workspace_id;
   ```

   The server also refuses to start if its role bypasses row-level security (`db.CheckIsolation`).
6. **Decide the scope:** which workspaces' data, which kinds (inventory, findings, user names and emails, integration and channel settings; stored secrets are encrypted and never returned by the API), since which version, and whether it was actually exploited (step 2 and 3) or only possible.

### Contain

- **Disable the affected workspace** (or the one the access came from): **Settings → Workspaces**, or `PATCH /api/v1/admin/workspaces/{id}` with `{"disabled": true}` as an instance admin. Its tokens and sessions are refused on their next request and its periodic work (alerts, integrations, evaluations) stops; its data stays for the investigation.
- **Revoke credentials:** the tokens involved (`DELETE /api/v1/tokens/{id}`, audited as `token.revoke`), and the sessions of the users involved (disable the user, or `DELETE FROM sessions WHERE user_id = ...;`). In an emergency, `UPDATE api_tokens SET revoked_at = now() WHERE workspace_id = ... AND revoked_at IS NULL;`.
- **Block the route** at the reverse proxy if the leak is through one endpoint and a fix is not yet available.
- **Rotate what may have leaked:** if integration or channel settings were exposed, rotate the underlying credentials (Git tokens, webhook URLs, bot tokens, Jira tokens) at their providers, then update the secrets in Stackurity.
- **Upgrade** to the fixed release as soon as it is published, then run the checks in step 5 again.

### Notify and disclose

- **Operators** tell the organisations whose data was exposed, through their workspace admins, with what was exposed, to whom, when, and what was done; and meet their own legal obligations (for example, personal data breach notification deadlines). Stackurity holds people's names and email addresses, so assume personal data is involved until shown otherwise.
- **The project** fixes the bug in private (advisory fork), adds the reproducing test, releases a patch version with a GitHub security advisory and a CVE, and credits the reporter if they agree. The advisory states the affected versions and editions, whether exploitation leaves traces in the request logs or audit events, and how to check an installation (the queries above).

### Any isolation-test failure blocks a release

The isolation suite is `tools/release-checks/isolation.sh`: every test in section 4's workspace-isolation table, run by name, failing if any of them fails, is skipped or no longer exists. It runs as the **Workspace isolation** job of `.github/workflows/release-checks.yml` on every pull request (keep it a required status check for `main` in the repository's branch protection), and the release workflow runs the same checks and publishes nothing unless they pass. The tests also run in `ci.yml` and, for the licensed build, in `make test-ee`.

- A failure blocks merging and releasing. It is not retried until it passes, skipped or marked flaky: an isolation test that fails intermittently is treated as a failing one until the cause is understood.
- A failure on `main` or on a release branch is handled as a suspected incident under this section, starting with triage, until shown to be a defect of the test alone.
- A fix lands with a test that fails without it, and a new table, route or background job that holds workspace data lands with its row-level security, its sweep rule and its scope (the tests above fail otherwise).

## 7. Security-sensitive areas

There is no CODEOWNERS file. Instead, a change touching one of these areas needs a reviewer who has read this section, and the review checks the points listed.

| Area | Why | What review checks |
|---|---|---|
| `internal/tenant` | The scope every database connection carries | A context without a scope still sees nothing; `tenant.System` is not reachable from request handling except where an instance admin is checked |
| `internal/db` (`db.go`) and `internal/db/migrations` | Row-level security, the application role, grants, same-workspace triggers | Every new table has `workspace_id`, `FORCE ROW LEVEL SECURITY` and policies, or is listed as global in `rls_test.go` with a reason; new references between workspace tables get a 0025-style trigger; nothing grants `BYPASSRLS` or ownership to `stackurity_app` |
| `internal/api` authentication and authorisation (`middleware.go`, `handlers_auth.go`, `handlers_workspaces.go`, the single sign-on handlers of the licensed build) | Who a request is, its workspace and role | Credentials are looked up only by hash; a lookup failure is never treated as anonymous or as another principal; role and instance-admin checks sit on the route; every new route has a rule in `sweep_test.go` |
| `internal/store` code that uses `tenant.System` | System scope reads every workspace | It is needed (platform work, instance admin views) and its results never reach a workspace principal |
| `internal/netguard` | Server-side request forgery from workspace-supplied URLs | Every outbound connection a workspace can point somewhere goes through it; the checked address is the one dialled; redirects are not followed |
| `internal/secrets`, `internal/auth` | Stored secrets, password and token hashing | Secrets stay encrypted per workspace and are never returned or logged; no weaker hashing |
| `internal/agentfix`, `internal/plugins`, `internal/packs` | Code that changes hosts or runs third-party code | Allowlists, sandboxing and output caps stay in place ([remediation.md](remediation.md), [plugins.md](plugins.md), [packs.md](packs.md)) |
