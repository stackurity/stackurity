# Stackurity

Open-source, self-hosted software inventory and upgrade intelligence. Stackurity discovers software across hosts, repositories, containers and SBOMs, keeps one inventory with evidence for every component, and shows clearly what was **not** checked.

> **Status:** first public release (v0.1). Inventory, intelligence, alerts and team workflow, stack packs and workspaces are in Community; see the [known limitations](#known-limitations) below and [editions](#editions) for what Pro and Enterprise add.

## What it does today

- **Hosts:** a read-only, unprivileged agent for Linux (dpkg, rpm and apk) and Windows (registry). On Linux it also finds runtimes and servers installed outside the package manager (Node.js from nvm, downloaded database binaries) and flags hosts that need a reboot to run patched code. It can also read the libraries deployed applications actually have installed (node_modules, Python virtualenvs, Composer vendor), so each application appears with its host, web server, runtime and repository in one stack view.
- **Repositories:** npm, yarn, pnpm, Composer, Poetry, Pipenv, pip (pinned), Go modules, Bundler, NuGet and Dart/Flutter pub, including direct and transitive dependencies. More technologies come as [stack packs](docs/packs.md): signed, sandboxed WebAssembly readers an administrator installs when their estate needs them, such as Java (Maven and Gradle) and Rust (Cargo). Scans run server-side from Git or in CI, where they can fail the pipeline on a severity, priority or known exploitation threshold. Lockfiles are parsed as data and nothing is executed.
- **Managed cloud services:** AWS RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch versions through a read-only plugin, with lifecycle tracking.
- **Plugins:** a public, language-agnostic plugin contract with a conformance checker. See [docs/plugins.md](docs/plugins.md).
- **Container images:** inventory from a registry reference through the bundled Syft. No Docker daemon is needed.
- **SBOMs:** CycloneDX and SPDX JSON import, CycloneDX 1.6 export.
- **Vulnerability intelligence:** OSV data for npm, Packagist, PyPI, Go, Maven, RubyGems, crates.io, NuGet, Pub, Debian, Ubuntu, Alpine, Rocky, Alma, Red Hat Enterprise Linux, SUSE Linux Enterprise and openSUSE Leap, and Amazon's own advisories (ALAS) for Amazon Linux 2 and 2023. Versions are compared by each ecosystem's own rules, so distro backports are handled. Advisories are deduplicated across sources, CISA KEV flags known exploitation, and refresh is hourly and incremental.
- **Versions and lifecycle:** latest stable releases from npm, Packagist, PyPI, Go modules, crates.io, RubyGems, NuGet, Maven Central and pub.dev (patch, minor or major, plus deprecated packages and yanked, retracted or unlisted versions), and end-of-life data from endoflife.date for operating systems, runtimes and frameworks.
- **One inventory:** stable asset identities, conflict detection and merging, and relations between assets. Every component carries its source, timestamp, confidence and evidence.
- **Coverage ledger:** unsupported, skipped, failed, partial and stale areas are shown separately from healthy coverage. They are never treated as healthy.
- **Risk-based alerting:** configurable P1–P4 priority with explained factors (KEV, exposure, production, criticality, fix availability, confidence), SOS rules that never rely on severity alone, and incidents that group findings so one CVE on fifty servers is one alert.
- **Team workflow:** acknowledge, assign, risk acceptance (security role, with a reason, an expiry capped by policy, and the mitigation in place) and deadlines, with full history. Several teams with routing by team and escalation of overdue issues are part of Pro.
- **Evidence (Pro):** a periodic patch-management report for audits and security questionnaires: coverage, open and overdue findings, time to resolve, active exceptions and replica drift.
- **AI assistants:** `stackurity mcp` is a read-only Model Context Protocol server, so coding agents can ask what is vulnerable and what to upgrade ([docs/ai-assistants.md](docs/ai-assistants.md)).
- **Notifications:** email, Slack, Microsoft Teams and signed webhooks, with routing by priority, team and environment, quiet hours, rate limits with digests, retries and a delivery log. Feed, collector and coverage failures alert too.
- **Controlled remediation (Pro):** opt-in, policy-scoped upgrades with approval gates, maintenance windows, canary then staged rollout, verification against freshly collected inventory and health checks, and halt-on-failure with best-effort rollback where the package manager supports it. Hosts are enrolled one at a time with a bound token and a local allowlist. Repositories get Renovate pull requests, so code review stays in place. See [docs/remediation.md](docs/remediation.md).
- **Workspaces:** one installation can serve several organisations, kept apart by PostgreSQL row-level security as well as by the application.
- **Dashboard, API and CLI:** role-based access (viewer, engineer, security, admin, collector), API tokens, a full audit log and single sign-on (Pro).

## Quick start

Stackurity is self-hosted: your inventory and findings stay on your own server, and your hosts and pipelines send data to it. Nothing needs inbound access to your machines.

**1. Run the server** (Docker Compose; plain HTTP is for evaluation only):

```sh
git clone https://github.com/stackurity/stackurity.git
cd stackurity/deploy
./init-secrets.sh
STACKURITY_COOKIE_SECURE=false docker compose up -d --build
docker compose logs stackurity | grep -A2 "one-time token"
```

Open http://localhost:8080 and create the first administrator with the token from the log.

**2. See it working in five minutes** with a labelled demo estate: a server with outdated packages and an end-of-life runtime, an application deployed on it, and two repositories. Findings appear once the vulnerability feeds have synced:

```sh
docker compose exec stackurity stackurity admin load-demo        # --remove deletes it again
```

**3. Connect your own estate:**

- **Servers:** under **Assets → Add server**, create an install command and run it on each Linux host. The agent is read-only and unprivileged, and it reports OS packages, runtimes and the libraries your deployed applications have installed.
- **Code:** add repositories under **Integrations**, or run `stackurity scan . --fail-on critical` in CI to block vulnerable changes.
- **Cloud:** the AWS plugin reads managed service versions with a read-only role.
- **People and tools:** invite your team (or turn on single sign-on with Pro), route alerts to Slack, Teams or email, and give AI assistants read-only access with `stackurity mcp`.

**4. Act on it:** each asset's **Action plan** groups findings into concrete upgrades. With Pro, opt-in remediation applies approved upgrades on enrolled hosts and opens Renovate pull requests for repositories.

For TLS, backups, upgrades, Kubernetes (Helm), the agents and plugins, see [docs/install.md](docs/install.md). [docs/security-audit.md](docs/security-audit.md) covers the threat model and how releases are signed. The API is described in [docs/api.md](docs/api.md), and every outbound connection is listed in [docs/network.md](docs/network.md).

## Known limitations

- Run a single server replica. Background work runs in-process, and notification delivery isn't yet coordinated across replicas.
- Vulnerability matching covers language packages, Debian, Ubuntu (not Pro), Alpine, Rocky, Alma, RHEL, SUSE, openSUSE Leap and Amazon Linux 2 and 2023. CentOS, Oracle Linux, Fedora and Amazon Linux 1 packages are inventoried but listed as evaluation gaps.
- Red Hat advisories are matched against the main stream of each major release; Extended Update Support (EUS, AUS) streams are not modelled, so a host held on an EUS minor release can show fixes it already has through EUS. SUSE publishes no severity in its advisory data, so SUSE findings show severity "unknown" and are prioritised on the other risk factors.
- Amazon Linux 2 extras topics are read when the topic name carries its version line (kernel-5.10, php8.2, postgresql14); packages from other topics (docker, epel and similar) are matched against core advisories only.
- Release (latest-version) data covers the language registries above, not OS packages. Maven Central publishes no release dates, and RubyGems hides yanked versions, so neither is shown for those. Lifecycle data covers everything endoflife.date tracks.
- CVSS v4 vectors are kept but not scored locally; the vendor's label is used instead.
- Runtimes found outside the package manager get lifecycle (end-of-life) tracking only; vulnerabilities are not matched for them.
- Java needs the Java stack pack; from a `pom.xml` alone it sees direct dependencies only. Windows hotfixes and Microsoft Store apps are reported as unsupported coverage.
- Single sign-on supports OpenID Connect; SAML is not implemented.
- Remediation applies to Linux packages (apt, dnf, apk) and to repositories through Renovate. SUSE (zypper) and Amazon Linux 2 (yum) hosts get findings and fix plans but no automatic fixing.

## Editions

Community is free and complete for finding and prioritising what to fix. Pro adds automatic fixing, multi-team workflow, the evidence report and single sign-on; Enterprise adds packs for enterprise technologies. See [Editions and licences](docs/install.md#editions-and-licences).

## Principles

- Self-hosted, with no vendor account and no telemetry.
- Every finding carries its source, timestamp and confidence.
- Missing or stale data is shown as missing or stale. It is never treated as healthy.
- Refreshing intelligence never changes your software. Changes need explicit policy.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Commmerce Revolution and Future Technologies Private Limited.
