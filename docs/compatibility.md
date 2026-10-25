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
| Ubuntu | dpkg | Yes, Ubuntu Pro fixes labelled; FIPS builds matched against the FIPS channels | OSV (Ubuntu) |
| Alpine | apk | Yes | OSV (Alpine) |
| Rocky Linux, AlmaLinux | rpm | Yes (Rocky by source package) | OSV |
| Red Hat Enterprise Linux | rpm | Yes, main stream of each major release (0.2+), each minor release from RHEL 10 | OSV (Red Hat) |
| SUSE Linux Enterprise | rpm | Yes, LTSS fixes labelled (0.2+), and fixes only published for SAP or HPC products | OSV (SUSE) |
| openSUSE Leap | rpm | Yes (0.2+) | OSV (openSUSE) |
| Amazon Linux 2023 and 2 | rpm | Yes (0.2+); Amazon Linux 2 extras topics with a version line | ALAS from Amazon's repositories |
| CentOS, Oracle Linux, Fedora, Amazon Linux 1 | rpm | No: evaluation gap | |
| Windows | Registry (installed programs, OS build) | No: lifecycle only; hotfixes and Store apps are unsupported coverage | |
| Runtimes outside a package manager | Detected | No: lifecycle only | endoflife.date |

The same rules apply to container images scanned through the bundled Syft and to imported SBOMs: the purl's `distro` qualifier selects the source.

## Clusters and cloud

| Source | Inventory | Assessed | Notes |
|---|---|---|---|
| Kubernetes 1.25+ (kind, kubeadm, k3s, RKE2, EKS, GKE, AKS) through the `kubernetes` plugin | Workloads, the images they run (by digest), exposure, control plane, kubelet, container runtime and node OS versions | Images: as container images above. Versions: lifecycle only (endoflife.date `kubernetes`, `amazon-eks`, `google-kubernetes-engine`, `azure-kubernetes-service`, `containerd`, node OS) | Read-only RBAC in `deploy/kubernetes`. Kubeconfig with an embedded token or client certificate, a token, or the in-cluster service account; exec credential plugins are not supported. See [kubernetes.md](kubernetes.md) |
| AWS managed services through the `aws-managed` plugin | RDS, Aurora, ElastiCache, EKS, Lambda, OpenSearch engine and runtime versions | Lifecycle only | |

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
| RHEL, CentOS and Oracle Linux 8 or later, Rocky, AlmaLinux, Fedora, Amazon Linux 2023 | dnf | Best effort |
| Amazon Linux 2, RHEL, CentOS and Oracle Linux 7 | yum | Best effort |
| SLES, SLES for SAP, SLED, openSUSE Leap | zypper | Best effort |
| Alpine | apk | Manual |
| openSUSE Tumbleweed, Amazon Linux 1, other rpm systems | Not supported: findings and fix plans only | |
| npm, Composer repositories | Renovate pull requests | Revert the pull request |

## Coverage states

Having no findings only means something if the components were checked. The
dashboard, the API and these docs use one vocabulary for that.

Each inventoried component (each row on an asset) is:

| Row coverage | Meaning |
|---|---|
| Checked (`evaluated`) | Matched against the vulnerability feed for its ecosystem and release |
| Stale intelligence (`stale_intelligence`) | Matched, but the feed is past its staleness window, disabled or its last sync failed: newer advisories are missing |
| Not checked (`not_evaluated`) | A source exists but could not be used: the feed has not synced, the release has no advisories in it, the version could not be read, or the distro release is unknown. The reason is shown |
| Unsupported (`unsupported`) | No vulnerability source exists for it: an unsupported ecosystem or distribution, a runtime installed outside a package manager, a Kubernetes or managed-service version (lifecycle only) |
| Awaiting verification (`awaiting`) | Inventoried, not evaluated yet |

Each asset is in one or more states; the most severe, in this order, is its
headline:

| Asset state | When |
|---|---|
| Failed collection (`failed_collection`) | A collector reported a failed scope, or the asset stopped reporting (stale), so the inventory may be incomplete or out of date |
| Stale intelligence (`stale_intelligence`) | Components were checked against stale or failing intelligence |
| Partially evaluated (`partially_evaluated`) | Components could not be checked, the last collection was incomplete, or a scope was only partly read |
| Unsupported (`unsupported`) | Components or collector scopes have no vulnerability source |
| Awaiting verification (`awaiting_verification`) | Inventory has not been evaluated yet, or not within the last 48 hours |
| Healthy and recently evaluated (`healthy`) | None of the above: every scope was collected and every component checked against current intelligence within 48 hours |

The asset page shows the states with their reasons above the tabs, the
Findings tab says how many components the findings do not cover, and the
Inventory tab marks each component that was not checked ("not checked:
<reason>") and can be filtered by coverage. The Coverage page counts assets
by state; the Intelligence page lists every component not checked. The API
returns the same values (`GET /assets/{id}/coverage-summary`, `coverage` on
inventory rows).

## How matching is tested

Each supported ecosystem has a corpus of real advisory records, frozen and
trimmed, with installed versions and the verdict each must get, in
[`internal/intel/testdata/corpus`](../internal/intel/testdata/corpus/README.md).
The test runs them through the whole pipeline (download, storage, release
selection, comparison, fixed version, subscription labels, coverage), not
only the version comparators. Every corpus also has cases the system cannot
evaluate, with the explicit response expected.

| Ecosystem | Corpus | What it covers | Cannot evaluate |
|---|---|---|---|
| npm | `npm/` | Pre-release ranges (canary, beta), `last_affected`, several ranges, listed versions, a withdrawn record, a record spanning several ecosystems | A dist-tag (`latest`) instead of a version: not checked |
| Packagist | `packagist/` | Two advisories for one CVE, `v` prefixes, short bounds ("6"), RC versions, withdrawn records, Drupal's own repository | A branch (`dev-master`): not checked |
| PyPI | `pypi/` | Branch ranges, pre-releases (`1.8b1`), `last_affected`, GHSA and PYSEC duplicates, PEP 503 names, withdrawn records | A non-PEP 440 version: not checked |
| Go | `go/` | `v` prefixes, pseudo-versions, the standard library and its `go1.x` spelling, withdrawn records | `(devel)`: not checked |
| Maven | `maven/` | Qualifiers (`2.0-beta9`), three ranges per advisory, listed versions only, withdrawn records | An unresolved `${property}`: not checked |
| RubyGems | `rubygems/` | Pre-releases (`3.0.0.beta1`), several ranges, withdrawn "all versions" records | A string Gem::Version rejects: not checked |
| crates.io | `crates/` | Several introduced/fixed pairs in one range, pre-releases, advisories without a CVE, withdrawn records | A requirement (`1.x`): not checked |
| NuGet | `nuget/` | Per-major ranges, `last_affected` without a fix, pre-releases, withdrawn records | More than four version parts: not checked |
| Pub | `pub/` | `+build` versions, pre-release fixes, single-version advisories, withdrawn records | A constraint (`any`): not checked |
| Debian | `debian/` | `+debNuM` backports, epochs (and a version reported without one), per-release fixes, binary to source mapping, withdrawn records | A release without advisories, no distro qualifier, a malformed epoch: not checked; derivatives: unsupported |
| Ubuntu, including Pro | `ubuntu/` | `ubuntu0.22.04.N` updates, Pro-only (ESM) fixes and universe packages, FIPS builds and the FIPS-updates channel | A release without advisories: not checked |
| Alpine | `alpine/` | `-rN` revisions, per-release fixes, `_alpha` pre-releases | A release without advisories, no distro qualifier: not checked; other apk distributions: unsupported |
| Rocky Linux | `rocky/` | Source-package matching, `el9_4` z-stream fixes, epochs (agent and Syft forms, and a missing epoch), Rocky 8 and 9 | A release without advisories: not checked |
| AlmaLinux | `alma/` | Binary-package records without CVE ids, minor releases on the major stream | A release without advisories: not checked |
| Red Hat | `redhat/` | `el9_4` fixes, EUS records kept out of the main stream, RHEL 10 minor-release streams, Syft's namespace and epoch | A RHEL 10 stream without advisories: not checked; CentOS: unsupported |
| SUSE, including LTSS | `suse/` | Source-package matching, Basesystem fixes, LTSS-only fixes, SLES for SAP | A service pack without advisories, an unreadable VERSION_ID: not checked |
| openSUSE Leap | `opensuse/` | Leap entries of SUSE records, per-release fixes | A Leap release without advisories: not checked; Tumbleweed: unsupported |
| Amazon Linux 2 and 2023 | `amazon/` | Real `updateinfo` read through the repository mirrors, epochs, AL2 extras (kernel-5.10) limited to their version line | Amazon Linux 1: unsupported |

Known limits the corpus documents: RHEL hosts on an EUS minor release are
matched against the main stream; from a FIPS build's version alone the
matcher cannot tell the certified FIPS channel from FIPS-updates and follows
FIPS-updates; a Debian or rpm version reported without its epoch sorts below
every fix with one.

