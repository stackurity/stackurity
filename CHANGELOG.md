# Changelog

All notable changes to Stackurity. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version can change behaviour, and the notes say when it does.

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
