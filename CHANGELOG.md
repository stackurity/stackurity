# Changelog

All notable changes to Stackurity. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version can change behaviour, and the notes say when it does.

Each release's section is published as its GitHub release notes, and a tag without a section here cannot be released (`go run ./tools/changelog -version vX.Y.Z` prints it). New changes go under **Unreleased**, which is renamed to the version when it is tagged. Subsections are **Security**, **Added**, **Changed**, **Fixed** and **Upgrading**. Put fixes for vulnerabilities under `### Security`, first: installations treat a release with that heading as a security release and show administrators a banner they can only snooze.

## Unreleased

### Added

- **Risk policy preview.** `POST /api/v1/risk-policy/preview` (admins) validates a proposed policy like a save and scores the workspace's open findings under the current and the proposed policy in memory, inside a read-only transaction: counts per priority and SOS before and after, how many findings are raised or lowered, and up to 50 changed findings with their asset and the factors whose points differ. **Settings > Risk policy** requires a preview of the exact changes before saving, and shows who last changed the policy and when (`last_change` in `GET /risk-policy`, from the audit log). The preview and prioritisation share one query, so the preview is what a save produces.
- **Remediation policy preview (Pro).** `POST /api/v1/remediation/policies/preview` shows which fixable packages and assets a new or edited policy would authorise or stop authorising, using the planner's candidates and first-matching-policy rule, without saving. The policy editor requires it before saving and shows who last changed the policy.
- **Health centre.** Every platform health problem now has when it last worked, the latest error, what it affects (a summary, counts across workspaces, up to ten named objects with links) and a suggested next step with a documentation link. New problems: integrations whose latest run failed (and those failing for two scheduled runs or more), notification channels with failed or retrying deliveries, assets whose collector stopped reporting (with the production count), production assets with failed or partial collection, production assets running components no source could evaluate, and job kinds retried three or more times. Objects are named, and their errors shown, only for the instance administrator's active workspace; these problems never become platform incidents.
- **Finding provenance.** The finding page shows how each verdict was reached: every matched advisory (linked) with its feed, ecosystem and the affected range that matched, the installed version, the version rules used (Debian version rules, RPM epoch:version-release, SemVer, ...) and the evidence state (confirmed, needs validation, stale, confirmed with stale advisory data, unknown) with a one-line reason. The findings list shows the same state.
- Reports count open findings by evidence state: `open.by_evidence` in the outcomes report and in the evidence report (Pro), whose exceptions also carry their `verification`.
- The audit log page can be opened filtered by object type (`/audit?object_type=settings`).

## 0.4.0

### Security

Found by turning the security documentation into tests (see "Verification" in `docs/security-audit.md`); each fix has its own commit.

- Workspace admins could disable shared intelligence feeds for every workspace. Enabling or disabling a feed now needs an instance administrator.
- A workspace admin could set the password, name or status of an instance administrator whose only workspace was theirs. That now needs an instance administrator.
- Zoned IPv6 link-local addresses (`fe80::1%eth0`) passed the private-network check for webhooks, Jira, SMTP, Git and Kubernetes destinations. IPv4-compatible IPv6, local-use NAT64 and site-local ranges are now blocked too.
- A workspace could point its routes, assets, findings and teams at another workspace's channels, teams and users by id, and probe which ids exist. Migration 0025 adds database triggers that keep references inside the workspace; team members must be members of the workspace.
- The output caps on plugins, git, stack packs and runtime detection were never applied. They now are.
- Image scans for workspaces without private network access run Syft through a guarded proxy, so DNS rebinding and redirects to internal addresses are refused.
- Versions longer than 256 characters are no longer compared (they could keep the shared evaluator busy for hours); such components are reported as not evaluated.
- Git repository URLs with IPv4 in decimal, octal or hexadecimal notation, or with a query or fragment, are refused; clone errors redact the Basic credential.
- One malformed or over-long entry in a lockfile or an installed package no longer makes the whole scan invalid; it is skipped and reported as partial coverage.
- A release `current` link must resolve inside the application, through every link.
- Delivery errors redact Slack and Teams URLs in every form; plugin logs and errors redact the plugin's credentials; failed sign-ins no longer record what was typed as the email unless it is an existing account; malformed Git and Kubernetes URLs are not echoed in errors.

### Added

- **Update notices for administrators.** Every 12 hours one server replica reads the public list of Stackurity releases from GitHub (an anonymous request with a generic `User-Agent`; no version, id or other data about the installation is sent) and compares it with the running version locally. Instance administrators see a banner when a newer release exists (dismissable per version) or a stronger one when a newer release has a **Security** section (it can only be snoozed for 24 hours), and **Settings → What's new** (`/updates`, also linked from the version in the sidebar) shows the notes of every newer release with upgrade steps. `GET /api/v1/updates` returns the same for instance administrators. `STACKURITY_UPDATE_CHECK=off` turns the check off entirely, and `STACKURITY_UPDATE_URL` points it at a mirror; see [docs/network.md](docs/network.md#update-check).
- **Coverage states.** Every asset says how far its findings can be trusted: Healthy and recently evaluated, Stale intelligence, Failed collection, Partially evaluated, Unsupported or Awaiting verification, each with its reason (`GET /api/v1/assets/{id}/coverage-summary`, the asset page, the Coverage page and the overview). Inventory rows say whether they were checked, and the Inventory and component pages mark each component that was not ("not checked: <reason>"). See `docs/compatibility.md`.
- A matching corpus of real advisories for every supported ecosystem (`internal/intel/testdata/corpus`), run through the whole pipeline in the tests.
- **How priorities are decided** (`docs/risk.md`): every input and factor, how missing evidence is scored and why, a table of 36 validated scenarios and the invariants the scoring keeps. A scenario suite and property tests in `internal/risk` check them on every build.
- Each finding records the risk policy version that produced its priority (`priority_policy_version`; `policy_version` in the explanation is now that version, with `current_policy_version` next to it).
- Risk policy changes are audited in the same transaction, with the full policy before and after, both versions and the changed fields. `PUT /risk-policy` returns `version`, `previous_version` and `changed`.
- Explanations name the evidence behind exposure (set on the asset, reported by the collector, or a workload running the image) and say when a severity is missing.
- **Release checks in CI** (`.github/workflows/release-checks.yml`, on pull requests to main and before every release). For each earlier release still in use (0.2.0 and 0.3.0), a job installs it from GHCR with demo data, a second workspace and findings, starts the current build on the same database and checks that migrations apply, `/readyz` is 200, the API answers and nothing was lost; restores a `pg_dump` of the result into a new PostgreSQL server (which has no `stackurity_app` role) and checks again; and runs the documented rollback. A tag publishes nothing unless these pass. Run them locally with `tools/release-checks/upgrade.sh`.
- `docs/install.md` describes how to roll back an upgrade (recreate the database, restore the pre-upgrade backup, start the previous image), and `docs/remediation.md` has a "Failure handling" section on what automatic fixing does when a change, an agent or the network fails.
- **Crash recovery tests** (`internal/crashtest`, run in CI): the real server is killed during a feed refresh, an inventory upload, a notification delivery, a periodic task and a job, and restarted. `docs/reliability.md` lists what is guaranteed (previous data kept, work resumed or failed visibly, findings never duplicated, notifications at least once with a delivery id to deduplicate) and how each is tested.
- The Helm chart is published and signed with each release: `helm install stackurity oci://ghcr.io/stackurity/charts/stackurity --version 0.4.0`. Also new outside this repository: the GitHub Action `stackurity/scan-action@v1` and the Homebrew formula `brew install stackurity/tap/stackurity`.

### Changed

- An asset with no environment adds `environment_unknown` (default +0.5) instead of scoring like a known non-production asset, and SOS rules that require production match it, as unknown exposure already matches rules that require exposure. **A confirmed known-exploited finding on an asset with no environment is now SOS**; set environments to avoid it.
- The risk policy editor rejects weights that point the wrong way (for example negative points for known exploitation, or unknown exposure weighted above exposed). Stored policies keep working until next saved.
- `PUT /risk-policy` fills fields it leaves out with their defaults instead of 0, as reading a stored policy already did.
- Automatic fixing (Pro): an approval by a person lapses if the rollout has not started within 14 days; the plan is cancelled and proposed again for a fresh decision. A host whose package changed since the plan was made is dropped from the plan before release, instead of failing the rollout when its agent refuses the stale change.
- The agent retries a remediation result report through brief network or server outages (four attempts). The server accepts a repeated report without recording it twice, and answers 409, not 404, to a report that contradicts what is recorded.
- GitHub release notes are now this changelog's section for the version, instead of a generated list of pull requests, and the release workflow fails when the section is missing. Tags with a prerelease suffix (`v0.4.0-rc.1`) are published as prereleases.

### Fixed

These change findings after upgrading: expect new findings on Rocky Linux and RHEL 10 hosts and for Drupal modules, and fewer on Ubuntu ESM and FIPS hosts.

- Rocky Linux binary packages such as `openssl-libs` were never matched: Rocky's advisories name source packages.
- RHEL 10 hosts matched no advisory: Red Hat publishes RHEL 10 per minor release.
- Ubuntu Pro FIPS channels were applied to regular builds (patched ESM hosts were reported affected, with a FIPS build as the fix) and regular fixes to FIPS builds. For FIPS builds, FIPS-updates is preferred over the frozen certified channel.
- Composer advisories published for another repository (Drupal contrib modules) were never matched.
- Fixes published only for SLES for SAP or HPC are labelled as needing a subscription on plain SLES.
- A release the feed has no advisories for (too new, or no longer covered) is reported as not evaluated instead of clean; so are unreadable RubyGems versions, unresolved Maven properties and, when a record matched without a comparison, any unparseable version.
- The Go standard library reported as `go1.22.1` and PyPI names with dots are matched.
- Evaluation gaps are recorded per inventory row: evaluating another asset or workspace no longer clears a gap. Reasons say exactly why a component could not be checked.
- A saved SOS rule picked up the conditions of the default rule at the same position that it did not set itself (for example `production: true`), so the rule applied was narrower than the one shown.
- An image run by one internal workload and one whose exposure could not be decided scored as internal; it is now unknown.
- Lower confidence (`needs_validation`, `stale`) no longer raises a score that is already below zero.
- Automatic fixing (Pro): a change already on a host when its plan was revoked, its policy disabled or its rollout halted was never verified or timed out. It stayed in flight for ever and blocked every later plan for that package on that host.
- Automatic fixing (Pro): when an agent applied a change but its report was lost, the change timed out after two hours and, with `auto_rollback`, was rolled back although it had worked. Fresh inventory now settles such changes, and timeouts never queue a rollback, since nothing is known to have changed.
- Automatic fixing (Pro): a change released shortly before the maintenance window closed, and not fetched in time, failed the whole plan at its dispatch deadline. It now waits for the next window.
- Automatic fixing (Pro): two rollout loops running at once (replicas whose worker leases overlapped) could each release up to `max_concurrent` changes.
- Automatic fixing (Pro): a plan whose changes were all cancelled was marked `succeeded`. A halted plan now says which host failed and why.
- A background job whose server was killed on every attempt (for example a feed sync that runs the server out of memory) was retried for ever: interrupted attempts did not count towards `max_attempts`. It now fails after the limit, with the interruption as its error, and shows on Platform health and in metrics.
- An interrupted feed sync showed no error until its retry finished; it now shows as failing ("the sync started ... was interrupted") as soon as the next attempt starts.
- A crash between storing new advisories and queueing their evaluation could delay new findings until the daily evaluation; evaluation is now queued before the feed's cursor moves.

### Upgrading

- Update agents along with the server: they retry remediation reports, which the server now expects.
- Migrations 0023 to 0025 run at startup. 0023 rewrites every inventory row once and replaces `evaluation_gaps` with a view; 0025 adds triggers that refuse references to another workspace's channels, teams and users (existing rows are kept). Each feed's first sync after the upgrade scans its stored advisories once to learn which releases it covers; for Ubuntu this sync is slow.
- Expect findings to change: new ones on Rocky Linux and RHEL 10 hosts and for Drupal modules, fewer on Ubuntu ESM and FIPS hosts. A confirmed known-exploited finding on an asset with no environment is now SOS.
- Approvals by a person now lapse after 14 days if the rollout has not started.
- The update check contacts `api.github.com` every 12 hours; add it to an egress allowlist or set `STACKURITY_UPDATE_CHECK=off`.

## 0.3.1

### Fixed

- Full vulnerability feed downloads (for example the Ubuntu archive, about 750 MB) were cancelled after the 20-minute job timeout on small servers and retried from the start, so the one-off re-sync after upgrading to 0.3.0 could never finish. Feed syncs may now run for 3 hours, and long jobs renew their lock so a second worker does not start the same job.
- The sidebar showed the version as "vv0.3.0".
- A finding's own fix is labelled "Fixes this issue", so it no longer reads as contradicting the package's upgrade recommendation.

## 0.3.0

### Added

- **Kubernetes.** A read-only `kubernetes` plugin, shipped in the image like `aws-managed`, reports each cluster (control plane, kubelet, container runtime and node OS versions, for lifecycle), its workloads, the images they run (by digest) and whether each workload is reachable from outside the cluster (LoadBalancer or NodePort Services, Ingresses, host networking). Running images are queued for scanning, most exposed first. Namespaces it cannot read and images it cannot pull are reported as coverage gaps. Least-privilege RBAC: `deploy/kubernetes/stackurity-reader.yaml`; see `docs/kubernetes.md`.
- **Jira.** A `jira` notification channel (Jira Cloud and Data Center) opens one issue per incident, comments when findings join or leave or the priority changes, and comments and transitions it when the incident resolves. Issues are never duplicated, across retries and replicas. Issue links show on incidents.
- **Upgrade recommendations** for every finding and installed component: minimum fixed version, recommended target (newest stable release in the installed major line that fixes every open finding), change type, withdrawn and end-of-life flags, and a rationale built only from stored data.
- **Remediation outcomes** report (**Issues → Remediation outcomes**, `GET /api/v1/reports/outcomes`): time to remedy by priority, how findings were resolved, SLA compliance, reopened findings, and remediation success, failures and rollbacks.
- **AI assistant tools** (MCP, read-only): `explain_finding`, `upgrade_recommendation`, `remediation_plan` and `verify_since`.
- **CVSS v4.0 scoring**, ported from the FIRST reference calculator, including threat and environmental metrics. The higher of the v3 and v4 ratings is used.
- **Automatic fixing (Pro) with zypper and yum**: SUSE (SLES, SLED, openSUSE Leap) and Amazon Linux 2 hosts, plus RHEL, CentOS and Oracle Linux 7 through yum. Like the other managers, a change runs only when its dry run shows exactly the planned change; removals, obsoletes, vendor or architecture changes and changes in the wrong direction are refused.
- Search finds workspace members (for engineers and above) and open findings by title.
- `STACKURITY_PLATFORM_WORKSPACE` chooses the workspace that receives platform-health incidents.
- Helm: optional `metrics.serviceMonitor` for the Prometheus Operator.

### Changed

- Sign-in, setup, password change, enrollment and single sign-on rate limits are shared across replicas (stored in the database) and fail closed.
- Hosts whose OS has no supported package manager (for example Amazon Linux 1, Tumbleweed, or an unknown OS) no longer get automatic-fix plans.
- Image scan failures keep Syft's error (for example `DENIED` from a registry) as the coverage reason.
- Plugin requests carry the workspace's network policy, and `pkg/plugin` has a `Dialer` that enforces it.

### Fixed

- Automatic fixing (Pro) on dnf hosts (RHEL, Rocky, AlmaLinux, Fedora, Amazon Linux 2023) did not check what the dry run would do: it ran with `-q`, which hides the transaction, so a change was approved on dnf's exit status alone. The dry run is now read, and the change is refused if it would remove or obsolete a package, change a package's vendor or architecture, pull in weak dependencies, or move anything in the wrong direction.
- Outbound webhook, Slack and Teams calls shared one connection pool across workspaces, so a workspace not allowed to reach private addresses could reuse a connection another workspace had opened to an internal host. Workspaces with different network policies now use separate pools.

### Upgrading

- Update agents before enabling automatic fixing on SUSE, Amazon Linux 2 or EL7 hosts: older agents refuse yum and zypper actions (safely).
- Migrations 0017 to 0021 run automatically at startup. Migration 0021 makes each OSV feed download its full archive once on its next sync, so stored advisories are rated with their CVSS v4 vectors; expect one sync as heavy as a fresh install.
- Reopened findings are counted from this upgrade on.

## 0.2.0

### Added

- **Vulnerability matching for RHEL, SUSE, openSUSE Leap and Amazon Linux.** Red Hat, SUSE and openSUSE advisories come from OSV; Amazon Linux 2 and 2023 advisories (ALAS) are read from Amazon's own repositories. Packages on these systems were inventoried before but listed as evaluation gaps. SUSE LTSS fixes are labelled as needing a subscription, like Ubuntu Pro. Container images scanned with Syft (for example Red Hat UBI and Amazon Linux base images) match as well as agent inventory.
- **Latest-release data for PyPI, Go modules, crates.io, RubyGems, NuGet, Maven Central and pub.dev**, alongside npm and Packagist, including deprecated packages and yanked, retracted or unlisted versions.
- **Global search** (`GET /api/v1/search`, the search box in the top bar, and an MCP `search` tool): CVE and advisory ids, packages with or without a version, hosts and any asset identifier, image digests, repositories and teams.
- **Several server replicas.** Periodic tasks are claimed in the database with a lease, so each runs once per interval across replicas; notification deliveries are claimed before sending; the setup token, licence and stack packs are shared.
- **Prometheus metrics** on an optional separate listener (`STACKURITY_METRICS_ADDR`).
- **Platform health** for instance administrators (`GET /api/v1/admin/health`, **Settings → Platform health**, and a banner): failing or stale feeds, background tasks that stopped succeeding, failed jobs and a job backlog.

### Changed

- NuGet versions are compared with NuGet's own rules (four numeric parts, case-insensitive prerelease labels). A NuGet version that cannot be parsed is now an evaluation gap instead of a loose comparison.
- Fix plans use `yum` on Amazon Linux 2 and `zypper` on SUSE.
- Automatic fixing (Pro) skips SUSE and Amazon Linux 2 hosts, which have no `dnf`.
- Release images are cross-compiled; building the arm64 image no longer needs emulation.

### Fixed

- After a backup was restored into a new PostgreSQL server, the database role used for workspace isolation was missing: a server with several workspaces refused to start, and one with a single workspace ran without row-level security. The role and its grants are now created on every start.

### Upgrading

Migrations 0014 to 0016 run automatically at startup. Keep the Helm update strategy at `Recreate` (the default) for this upgrade: a rolling upgrade would briefly run the old in-memory scheduler next to the new one.

## 0.1.0

First public release. The `v0.1.0` tag exists, but no release artifacts or images were published for it; 0.2.0 is the first published release.
