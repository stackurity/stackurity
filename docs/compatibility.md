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
| Windows | Registry (installed programs, OS build) | No: lifecycle only for the operating system (see [Windows end of life](#windows-end-of-life)); installed programs are not matched; hotfixes and Store apps are unsupported coverage | endoflife.date `windows-server`, `windows` |
| Runtimes outside a package manager | Detected | No: lifecycle only | endoflife.date |
| Packages from a vendor's own repository (MongoDB, Docker, Elastic, Grafana, PGDG, NodeSource, Redis, nginx.org, MariaDB, MySQL, HashiCorp, Kubernetes and others, see [below](#packages-from-vendor-repositories)) | dpkg, rpm | No: evaluation gap; lifecycle with upstream dates | endoflife.date |

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

## Kernels

A host keeps several kernels installed, and each kernel version is several
packages built from one source package (on Ubuntu: `linux-image-<v>`,
`linux-modules-<v>`, `linux-modules-extra-<v>`, `linux-headers-<v>`,
`linux-headers-<v>-generic`, `linux-tools-<v>`). Every kernel advisory
applies to all of them alike, so they are reported per kernel version:

| Package | Findings |
|---|---|
| Kernel code of one version: Debian and Ubuntu `linux-image-*`, `linux-modules-*`, `linux-tools-<version>` and other packages named with the kernel ABI; RPM `kernel`, `kernel-core`, `kernel-modules*` and flavours (`kernel-rt-*`, `kernel-debug-*`, `kernel-64k-*`, `kernel-uek*`, SUSE `kernel-default*`) | One finding per CVE per installed kernel version, on the package that boots (`linux-image-*`, `kernel-core`, `kernel`, `kernel-default`). The other packages of that version are listed in the finding's evidence (`kernel_packages`) and their inventory rows say "its findings are reported once, on ...". Matching is unchanged: findings from every package are merged, a free fix wins over a paid-channel one and the highest fixed version is kept |
| No running code: `linux-headers-*` (and `linux-<flavour>-headers-*`), `linux-libc-dev`, `linux-tools-common`, `linux-source*`, `linux-doc`; RPM `kernel-headers`, `kernel-devel`, `kernel-*-devel`, `kernel-macros`, `kernel-source`, `kernel-doc`, `kernel-syms` | None. They are checked (coverage `evaluated`) with the reason "kernel headers or build files, not running code" |
| `kernel-tools`, `kernel-tools-libs`, `kernel-firmware`, `linux-firmware`, metapackages (`linux-image-generic`) | Matched like any package: userspace code, firmware or a different source |

A kernel version that is installed but not the one running (from the agent's
`kernel_running`) keeps its single finding per CVE, marked
`not_running_kernel`: the risk engine scores it down to P4, it is never SOS,
and the action plan puts it under **Remove old kernels**
(`sudo apt autoremove --purge`, `dnf remove --oldinstallonly`, `zypper
purge-kernels`). When the running kernel is unknown, every kernel version is
treated as running. On the first pilot's Ubuntu 20.04 host this turned the
same CVE from five findings per kernel version (headers, flavour headers,
modules, plus `linux-libc-dev` and `linux-tools-common` for the newest) into
one; the fixture in `internal/intel/pilot_test.go` goes from 510 findings and
100 P1 to 150 and 20. Alpine installs one kernel package at a time and is
matched as before.

## Lifecycle of distribution packages

End-of-life dates from endoflife.date are the upstream project's: nginx 1.18
ended in 2021, PHP 8.1 on 2025-12-31, MySQL 8.0 on 2026-04-30. A
distribution that ships one of those versions keeps patching its own package
for as long as the distribution release is supported (Ubuntu 22.04 to
2027, RHEL 9 to 2032), so an upstream end-of-life finding on it would be a
false positive. For a runtime or server matched to an endoflife.date
product:

| Installed as | End-of-life finding |
|---|---|
| Outside the package manager (nvm's Node.js, a downloaded binary, a language package) | Upstream dates, as before |
| A distribution package (deb, rpm or apk with a `distro` qualifier) on a supported distribution release | None. The inventory row records "nginx 1.18 is end of life upstream since 2021-04-20; this is Ubuntu 22.04's own package, and Ubuntu 22.04 provides security updates until 2027-06-30", shown on the component and asset pages (`lifecycle_note`) |
| A distribution package on a release that is itself end of life (Ubuntu 20.04 after 2025-05-31) | None of its own: the operating system's end-of-life finding says its packages no longer get free fixes, and the action plan's release upgrade lists them. If the asset has no operating system row (some SBOMs), the package finding stays |
| A distribution package whose release is not in the lifecycle data, or without a `distro` qualifier | Upstream dates: the distribution's support cannot be confirmed |
| A build from another repository: a package name only a vendor ships (`mongodb-org-server`, `docker-ce`, `elasticsearch`, `grafana`, ...) or a version that shows the repository: Ondřej Surý's PHP (`deb.sury.org`), nginx.org (`1.24.0-1~jammy`), Docker (`~ubuntu.24.04~noble`), Redis (`-1rl1~noble1`), MariaDB (`+maria~`), NodeSource, PGDG, Remi (`.remi`), nginx.org rpm (`.ngx`), MySQL's APT repository (`-1ubuntu22.04`) | Upstream dates: the distribution does not maintain it. The inventory row's note names the repository |
| .NET (`dotnet-runtime-X.Y`) from Red Hat, from Microsoft's repository (packages.microsoft.com, the only source on Debian) or from Ubuntu's .NET backports PPA (`~ppa`) | Upstream dates: Red Hat's .NET life cycle is Microsoft's, and Microsoft's and the PPA's packages end with the release. Ubuntu's own archive packages (`-0ubuntu1~22.04.1`) follow the Ubuntu row above, since Canonical supports them for the Ubuntu release's lifetime |

The distribution's date is the endoflife.date end of its standard security
support (`eol`), the same date the operating system's own finding uses; paid
extensions (Ubuntu Pro, SUSE LTSS, RHEL ELS) do not count. Limits: the agent
does not record which repository a package came from, so a third-party build
whose name and version look like the distribution's own is treated as the
distribution's (Team RabbitMQ's `rabbitmq-server` `4.0.2-1`, Microsoft's
`dotnet-runtime-8.0` `8.0.3-1`, InfluxDB 1.x, Redis's rpm); Ubuntu's security support covers the `main` repository, and
`universe` packages get security fixes only through Ubuntu Pro, which the
package data does not distinguish; RHEL Application Streams modules can
retire before the release does. Vulnerability matching is unaffected:
fixes that only a paid channel publishes are still reported.

## What Stackurity cannot check

### Lifecycle mappings

End-of-life dates come from endoflife.date. A component gets them when its
package URL maps to an endoflife.date product, in this order:

1. An entry of Stackurity's lifecycle overlay marked `override` (none today).
2. endoflife.date's own package identifiers.
3. The same package name in another namespace of a family: `pkg:rpm/` RHEL,
   its rebuilds and Syft's name for it (`redhat`, `rhel`, `centos`, `rocky`,
   `almalinux`, `ol`), and `pkg:deb/` `debian` and `ubuntu`. endoflife.date
   lists `pkg:rpm/redhat/nginx`, so `pkg:rpm/rocky/nginx` and agent-reported
   RHEL packages (`pkg:rpm/rhel/...`) matched nothing before. Amazon Linux and
   Fedora are not in a family: their package names differ. `dotnet-sdk-*` is
   left out, so .NET keeps one finding per release from `dotnet-runtime-X.Y`.
4. The rest of the overlay
   ([`internal/intel/eoloverlay/lifecycle_overlay.json`](../internal/intel/eoloverlay/lifecycle_overlay.json)),
   a versioned data file embedded in the binary. Each entry names the index
   it was checked against. It adds:

| Product | Package URLs |
|---|---|
| Electron | `pkg:npm/electron` (endoflife.date tracks it with no identifier) |
| MongoDB | `mongodb-org-server` deb and rpm (MongoDB's repository; endoflife.date lists `pkg:deb/*/mongodb`) |
| Redis | `redis-server` deb (endoflife.date lists only the `redis` metapackage) |
| Docker Engine, containerd | `docker-ce` deb and rpm, `docker.io`, `containerd.io`, `containerd` |
| PostgreSQL | `postgresql-<major>` deb, PGDG's `postgresql<major>-server` rpm (the release line is read from the name) |
| Node.js | `nodejs` deb (NodeSource and the distributions) |
| Elasticsearch, Kibana, Logstash, OpenSearch, Grafana | Their own repositories' deb and rpm packages |
| InfluxDB, Telegraf | `influxdb`, `influxdb2`, `influxdb3-core`, `influxdb3-enterprise`, `telegraf` deb |
| MySQL, MariaDB | `mysql-community-server` deb and rpm, `mariadb-server` deb |
| Apache HTTP Server, Tomcat | `apache2` deb; `tomcat9`, `tomcat10`, `tomcat11` deb and `org.apache.tomcat.embed:tomcat-embed-core` (Spring Boot) |
| RabbitMQ, Kubernetes, GitLab, Jenkins, SQL Server | `rabbitmq-server` deb; `kubelet` deb and rpm; `gitlab-ce` and `jenkins` deb and rpm; `mssql-server` deb |
| Eclipse Temurin, Amazon Corretto, Go | `temurin-<v>-jdk`/`-jre`; `java-<v>-amazon-corretto-jdk`; `golang-<v>-go` (release line from the name) |
| HashiCorp Vault, Consul, Terraform, Nomad | Their deb packages from HashiCorp's repository; the distributions' own `consul` (Debian 10-11, Ubuntu 18.04-23.10) and `nomad` (Ubuntu 18.04-21.04), versioned `+dfsg`, stay distribution packages |
| OpenSSL, Exim, Postfix, Dovecot, Prometheus, Erlang, Podman | Distribution packages (`openssl`, `exim4-base`, `postfix`, `dovecot-core`, `prometheus`, `erlang-base`, `podman`); on a supported release they get the upstream note, not a finding |
| Symfony, CakePHP, Twig, Craft CMS, Shopware | `symfony/http-kernel`, `cakephp/cakephp`, `twig/twig`, `craftcms/cms`, `shopware/core` (Composer) |
| Kotlin, Quarkus, Apache Kafka, Apache Lucene, Liquibase | `kotlin-stdlib`, `quarkus-core`, `kafka_2.13`/`kafka_2.12` (the broker), `lucene-core`, `liquibase-core` (Maven) |

A Debian or RPM epoch is ignored when the release line is read
(`5:27.3.1-1~ubuntu.24.04~noble` is Docker 27). An end-of-life finding mapped
by the overlay says so in its evidence (`mapping`: `overlay` or
`namespace_family`, with `overlay_version`).

Not covered: products endoflife.date does not track (NestJS, Flask, FastAPI,
CodeIgniter, Varnish; the overlay lists them so the coverage-gap report counts
them, and no dates are invented for them), release lines endoflife.date does
not list (Elasticsearch 8.15, for example), packages whose names were not
checked against a vendor's index (MongoDB Enterprise, `gitlab-ee`, PGDG and
RHEL `postgresql-server`, HashiCorp rpm packages), and Amazon Corretto 8
installed as `java-1.8.0-amazon-corretto-jdk` is read as line 8.

### Packages from vendor repositories

Debian, Ubuntu and RHEL-family advisories describe the distribution's own
builds. A package from a vendor's repository either has no record there
(`mongodb-org-server`, `docker-ce`) or carries a different version from the
distribution's build, so matching it against them showed it as clean. Such a
package (recognised as in the lifecycle table above: a vendor-only name or a
version that shows the repository) is now coverage `unsupported`, with the
reason "built by <repository>, not by the distribution", and its end of life
uses upstream dates. This includes builds from Ondřej Surý's PHP, nginx.org,
NodeSource, PGDG, Remi and MySQL's repository, which were matched against the
distribution's advisories before.

Vulnerabilities of these packages are not matched: none of these servers has
an upstream ecosystem in OSV that their versions can be compared in without
guesswork (MongoDB, Redis, nginx, PostgreSQL and Node.js are not packages of
an OSV ecosystem; Docker and Grafana are Go modules whose module versions do
not follow the release numbers). Use the vendor's security advisories for
them.

### Coverage-gap report

Instance administrators see what Stackurity cannot check across every
workspace under **Settings → Coverage gaps** (`GET /api/v1/admin/coverage-gaps`):
files a scan found that no built-in reader or installed stack pack reads, by
kind (`mix.lock`, `rebar.lock`, `Package.swift`, `Package.resolved`,
`Podfile.lock`, `conanfile.txt`, `conanfile.py`, `conan.lock`, `vcpkg.json`,
`uv.lock`, `pdm.lock`, `packages.config`, `deno.lock`, `bun.lock`,
`bun.lockb`, `build.sbt`, and Maven, Gradle and Cargo files without their
stack pack); components with no vulnerability source, by package type and
reason (vendor builds per repository); and products with no lifecycle match.
Each is counted by assets and workspaces. The report names no workspace,
asset, path or package. The new file kinds are reported by agents and scans
from this release on; older agents report only the kinds they knew.

## Windows end of life

The Windows agent reports the operating system as `pkg:generic/windows@10.0.<CurrentBuild>.<UBR>` with the registry's `ProductName`, `EditionID` and `DisplayVersion`. The build number decides the endoflife.date release; the product name and edition tell Server from client and pick between releases that share a build. Server Core, Datacenter, Standard, Essentials, Evaluation and Azure Edition installs of a release share its dates.

| Build | Windows Server release (endoflife.date `windows-server`) |
|---|---|
| 6002, 6003 | 2008 SP2 (`2008-sp2`) |
| 7601 | 2008 R2 SP1 (`2008-r2-sp1`) |
| 9200 | 2012 |
| 9600 | 2012 R2 (`2012-r2`) |
| 14393 | 2016 |
| 16299, 17134 | 1709, 1803 (semi-annual channel) |
| 17763 | 2019 when the product name says 2019; 1809 (semi-annual channel, `1809-sac`) when it has no year ("Windows Server Datacenter") |
| 18362, 18363, 19041, 19042 | 1903, 1909, 2004, 20H2 (semi-annual channel) |
| 20348 | 2022 |
| 25398 | 23H2 (annual channel, `23h2-ac`) |
| 26100 | 2025 |

Windows client (endoflife.date `windows`) is mapped too: the build gives the version (19045 is Windows 10 22H2, 22631 Windows 11 23H2, 26100 Windows 11 24H2; Windows 7 SP1, 8 and 8.1 by build), and the edition the support policy: Home and Pro (including Pro Education and Pro for Workstations) take the `-w` release, Enterprise, Education and Enterprise multi-session the `-e` release, Enterprise LTSC/LTSB `-e-lts` and IoT Enterprise LTSC `-iot-lts`. Windows 11 reports "Windows 10" in its product name; the build decides. Agents older than this change do not send the edition; the product name is used instead.

A finding is raised when the release's endoflife.date `eol` date (end of Microsoft's extended support; for Windows Server 2016, 2027-01-12) has passed, titled "Windows Server 2016 is end-of-life since 2027-01-12", like Linux releases: there is no finding ahead of the date. Paid Extended Security Updates (endoflife.date `eoes`, Windows Server 2012 R2 to 2026-10-13) do not count, as Ubuntu Pro and RHEL ELS do not. The action plan's release upgrade for Windows Server names the newest supported LTSC release.

When the release cannot be told, the operating system row is a coverage gap (`not_evaluated`) with the reason, never supported: a build not in the tables (Insider and newer builds until Stackurity adds them), Windows Server 2003 (one build for RTM, SP1 and SP2) and 2008 R2 without SP1, build 17763 without a product name, a product name whose year disagrees with the build, a client `DisplayVersion` that disagrees with the build, an edition the tables do not know, and products endoflife.date does not track as Windows (Azure Stack HCI, Hyper-V Server). A release missing from the endoflife.date data is a gap too.

## .NET end of life

endoflife.date `dotnet` releases are "8", "6", "3.1". Flagged when the release has ended:

- **Linux distribution packages**: `dotnet-runtime-X.Y` (deb or rpm, any distribution) is .NET X.Y; one finding per installed release, since the SDK and ASP.NET Core runtime pull it in. Red Hat's packages, Microsoft's (packages.microsoft.com) and Ubuntu's .NET backports PPA get the upstream date; Ubuntu's own archive packages are maintained by Canonical while the Ubuntu release is supported (see [Lifecycle of distribution packages](#lifecycle-of-distribution-packages)).
- **NuGet**: `pkg:nuget/Microsoft.NETCore.App` and the runtime packs (`Microsoft.NETCore.App.Runtime.linux-x64` and the like), in a `packages.lock.json` (self-contained apps list the runtime pack), an image scan or an imported SBOM.

Not flagged:

- .NET installed outside a package manager on Linux (the `dotnet-install` script, a tarball under `/usr/share/dotnet`, `/opt/dotnet` or `~/.dotnet`): the agent does not look for it.
- .NET on Windows: the installed programs ("Microsoft .NET Runtime - 8.0.10 (x64)", "Microsoft ASP.NET Core 8.0.10 - Shared Framework") are inventoried by name and not matched to endoflife.date, nor is .NET Framework.
- An application's target framework (`<TargetFramework>net6.0</TargetFramework>` in a project file): project files are not read, and a framework-dependent app's `packages.lock.json` does not list the runtime.

## Paid support channels

Ubuntu Pro (Canonical) and SUSE LTSS are paid subscriptions for commercial
use. Their advisories are matched, and a finding whose only fixed build is in
one of them is labelled "no free fix" (`requires_subscription`). They are
never the recommended action: the action plan says "Fixed in Ubuntu Pro (paid
subscription); without it, upgrade to a supported release" on an end-of-life
release, and on a supported one, to install the update when the distribution
publishes a free fix. Groups carry `needs` so a team with a subscription can
use it, and findings that need one get no "fix available" bonus in the risk
score.

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
| Ubuntu, including Pro | `ubuntu/` | `ubuntu0.22.04.N` updates, Pro-only (ESM) fixes and universe packages, FIPS builds and the FIPS-updates channel, kernel modules against the `linux` source while headers, `linux-libc-dev` and `linux-tools-common` get no findings | A release without advisories: not checked |
| Alpine | `alpine/` | `-rN` revisions, per-release fixes, `_alpha` pre-releases | A release without advisories, no distro qualifier: not checked; other apk distributions: unsupported |
| Rocky Linux | `rocky/` | Source-package matching, `el9_4` z-stream fixes, epochs (agent and Syft forms, and a missing epoch), Rocky 8 and 9 | A release without advisories: not checked |
| AlmaLinux | `alma/` | Binary-package records without CVE ids, minor releases on the major stream | A release without advisories: not checked |
| Red Hat | `redhat/` | `el9_4` fixes, EUS records kept out of the main stream, RHEL 10 minor-release streams, Syft's namespace and epoch, `kernel-core` matched while `kernel-devel` (listed in the advisory) gets no findings | A RHEL 10 stream without advisories: not checked; CentOS: unsupported |
| SUSE, including LTSS | `suse/` | Source-package matching, Basesystem fixes, LTSS-only fixes, SLES for SAP | A service pack without advisories, an unreadable VERSION_ID: not checked |
| openSUSE Leap | `opensuse/` | Leap entries of SUSE records, per-release fixes | A Leap release without advisories: not checked; Tumbleweed: unsupported |
| Amazon Linux 2 and 2023 | `amazon/` | Real `updateinfo` read through the repository mirrors, epochs, AL2 extras (kernel-5.10) limited to their version line | Amazon Linux 1: unsupported |

Known limits the corpus documents: RHEL hosts on an EUS minor release are
matched against the main stream; from a FIPS build's version alone the
matcher cannot tell the certified FIPS channel from FIPS-updates and follows
FIPS-updates; a Debian or rpm version reported without its epoch sorts below
every fix with one.

