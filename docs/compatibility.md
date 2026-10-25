# Compatibility

What each release runs on and what it can assess. "Assessed" means installed packages are matched against vulnerability advisories; everything else listed under hosts is inventoried and shown as an evaluation gap, never as clean.

## Server

| | Supported |
|---|---|
| Install | Docker Engine 24+ with the Compose plugin, or Kubernetes with the Helm chart in `deploy/helm` |
| Images | `ghcr.io/stackurity/stackurity` for linux/amd64 and linux/arm64 |
| Database | PostgreSQL 16 or later (Compose ships 17). Row-level security is used for workspace isolation; on managed databases where the login role cannot create roles, the table owner's FORCE ROW LEVEL SECURITY applies instead |
| Replicas | One or more against one database (0.2+). Upgrade by stopping every replica first; the Helm chart's default `Recreate` strategy does this |
| Minimum size | 2 CPU, 2 GB memory, 10 GB disk for a few hundred assets |

## Agent

Release binaries: linux/amd64, linux/arm64, windows/amd64, darwin/amd64 and darwin/arm64 (darwin for `stackurity scan` in CI and on laptops; the host collector reads Linux and Windows).

| Host | Inventory | Vulnerabilities assessed | Source |
|---|---|---|---|
| Debian | dpkg | Yes | OSV (Debian) |
| Ubuntu | dpkg | Yes, Ubuntu Pro fixes labelled | OSV (Ubuntu) |
| Alpine | apk | Yes | OSV (Alpine) |
| Rocky Linux, AlmaLinux | rpm | Yes | OSV |
| Red Hat Enterprise Linux | rpm | Yes, main stream of each major release (0.2+) | OSV (Red Hat) |
| SUSE Linux Enterprise | rpm | Yes, LTSS fixes labelled (0.2+) | OSV (SUSE) |
| openSUSE Leap | rpm | Yes (0.2+) | OSV (openSUSE) |
| Amazon Linux 2023 and 2 | rpm | Yes (0.2+); Amazon Linux 2 extras topics with a version line | ALAS from Amazon's repositories |
| CentOS, Oracle Linux, Fedora, Amazon Linux 1 | rpm | No: evaluation gap | |
| Windows | Registry (installed programs, OS build) | No: lifecycle only; hotfixes and Store apps are unsupported coverage | |
| Runtimes outside a package manager | Detected | No: lifecycle only | endoflife.date |

The same rules apply to container images scanned through the bundled Syft and to imported SBOMs: the purl's `distro` qualifier selects the source.

## Application dependencies

| Ecosystem | Lockfiles read | Vulnerabilities | Latest releases |
|---|---|---|---|
| npm, yarn, pnpm | Yes | OSV | npm (0.1+) |
| Composer | Yes | OSV | Packagist (0.1+) |
| PyPI (Poetry, Pipenv, pinned requirements) | Yes | OSV | PyPI (0.2+) |
| Go modules | Yes | OSV | proxy.golang.org (0.2+) |
| RubyGems (Bundler) | Yes | OSV | rubygems.org (0.2+) |
| NuGet | Yes | OSV | nuget.org (0.2+) |
| Dart and Flutter (pub) | Yes | OSV | pub.dev (0.2+) |
| Maven, Gradle | Java stack pack | OSV | Maven Central (0.2+) |
| Cargo | Rust stack pack | OSV | crates.io (0.2+) |

## Remediation (Pro)

| Target | Manager | Rollback |
|---|---|---|
| Debian, Ubuntu | apt | Best effort |
| RHEL, Rocky, AlmaLinux, Amazon Linux 2023 | dnf | Best effort |
| Alpine | apk | Manual |
| SUSE, openSUSE, Amazon Linux 2 | Not supported: findings and fix plans only | |
| npm, Composer repositories | Renovate pull requests | Revert the pull request |
