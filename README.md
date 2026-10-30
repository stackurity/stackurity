# Stackurity

Open-source, self-hosted software inventory and upgrade intelligence. Stackurity discovers software across hosts, repositories, containers and SBOMs, keeps one inventory with evidence for every component, and shows clearly what was **not** checked.

> **Status:** an early release under active development; see the [latest release](https://github.com/stackurity/stackurity/releases/latest) and the [changelog](CHANGELOG.md). Inventory, intelligence, alerts and team workflow, stack packs, Kubernetes, Jira and workspaces are in Community; see the [known limitations](#known-limitations) below and [editions](#editions) for what Pro and Enterprise add.

## What it does today

- **Hosts:** a read-only, unprivileged agent for Linux (dpkg, rpm and apk) and Windows (registry). On Linux it also finds runtimes and servers installed outside the package manager (Node.js from nvm, downloaded database binaries) and flags hosts that need a reboot to run patched code. It can also read the libraries deployed applications actually have installed (node_modules, Python virtualenvs, Composer vendor, and front-end libraries loaded from a CDN or copied into a site), so each application appears with its host, web server, runtime and repository in one stack view.
- **Repositories:** npm, yarn, pnpm, Composer, Poetry, Pipenv, pip (pinned), Go modules, Bundler, NuGet and Dart/Flutter pub, including direct and transitive dependencies. More technologies come as [stack packs](docs/packs.md): signed, sandboxed WebAssembly readers an administrator installs when their estate needs them, such as Java (Maven and Gradle) and Rust (Cargo). Scans run server-side from Git or in CI, where they can fail the pipeline on a severity, priority or known exploitation threshold. Lockfiles are parsed as data and nothing is executed.
- **Managed cloud services:** AWS RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch versions through a read-only plugin, with lifecycle tracking.
- **Kubernetes:** a read-only plugin maps which workloads run which images (by the digest the node pulled), which workloads are exposed outside the cluster (LoadBalancer, NodePort, Ingress, host networking), and the control plane, kubelet, runtime and node OS versions for lifecycle. Running images are scanned with the bundled Syft, and exposure feeds risk scoring. Namespaces it cannot read and images it cannot pull show as not assessed. See [docs/kubernetes.md](docs/kubernetes.md).
- **Plugins:** a public, language-agnostic plugin contract with a conformance checker. See [docs/plugins.md](docs/plugins.md).
- **Container images:** inventory from a registry reference through the bundled Syft. No Docker daemon is needed.
- **SBOMs:** CycloneDX and SPDX JSON import, CycloneDX 1.6 export.
- **VEX:** OpenVEX and CycloneDX VEX import (standalone, embedded in an SBOM, or as a signed attestation), matched to components by package URL, image digest or CPE; a `not_affected` statement hides a finding only after a security user approves it or a source pinned to a key or token applies it, and stops applying when the version or image changes. Decisions (false positives, mitigations, imported statements) export as OpenVEX or CycloneDX VEX. See [docs/vex.md](docs/vex.md).
- **Vulnerability intelligence:** OSV data for npm, Packagist, PyPI, Go, Maven, RubyGems, crates.io, NuGet, Pub, Debian, Ubuntu, Alpine, Rocky, Alma, Red Hat Enterprise Linux, SUSE Linux Enterprise and openSUSE Leap, and Amazon's own advisories (ALAS) for Amazon Linux 2 and 2023. Versions are compared by each ecosystem's own rules, so distro backports are handled. CVSS v3 and v4 vectors are scored locally (v4 as the FIRST reference calculator does). Advisories are deduplicated across sources, CISA KEV flags known exploitation, FIRST EPSS predicts it, and refresh is hourly and incremental.
- **Versions and lifecycle:** latest stable releases from npm, Packagist, PyPI, Go modules, crates.io, RubyGems, NuGet, Maven Central and pub.dev (patch, minor or major, plus deprecated packages and yanked, retracted or unlisted versions), and end-of-life data from endoflife.date for operating systems, runtimes and frameworks.
- **Upgrade recommendations:** for each installed component with open findings, the minimum fixed version, the version to move to (the newest stable release in the same major line that fixes every open finding, or the distribution's fixed build for OS packages), whether it is a major upgrade, withdrawn versions and release-line support, with the reasons. Built only from stored data; missing data is reported as missing.
- **One inventory:** stable asset identities, conflict detection and merging, and relations between assets. Every component carries its source, timestamp, confidence and evidence.
- **Global search:** type a CVE or advisory id, a package with or without a version, a hostname, image digest or repository URL, a team, words from a finding's title or a workspace member, and land on the affected assets, components and findings.
- **Coverage ledger:** unsupported, skipped, failed, partial and stale areas are shown separately from healthy coverage. They are never treated as healthy.
- **Risk-based alerting:** configurable P1–P4 priority with explained factors (KEV, EPSS, exposure, production, criticality, fix availability, confidence), SOS rules that never rely on severity alone, and incidents that group findings so one CVE on fifty servers is one alert. [docs/risk.md](docs/risk.md) explains how priorities are decided, what happens when evidence is missing, and the scenarios and invariants the scoring is tested against.
- **Team workflow:** acknowledge, assign, risk acceptance (security role, with a reason, an expiry capped by policy, and the mitigation in place) and deadlines, with full history. Several teams with routing by team and escalation of overdue issues are part of Pro.
- **Remediation outcomes:** time to remedy by priority, SLA compliance against the risk policy, findings resolved by a fresh inventory versus by changed advisory data, findings that came back after being resolved, and remediation success, failures and rollbacks, always with the counts behind each rate.
- **Evidence (Pro):** a periodic patch-management report for audits and security questionnaires: coverage, open and overdue findings, time to resolve, active exceptions and replica drift.
- **AI assistants:** with `STACKURITY_BASE_URL` set to the server's public `https://` address, paste `https://<your server>/mcp` into Claude, ChatGPT or any assistant that supports remote MCP servers and sign in, nothing to install. Assistants can ask what is vulnerable, why it has its priority, which version to upgrade to, and whether a change fixed it, with cited ids and sources, and, if you allow changes, create projects, add servers, assign, snooze or ignore issues and check fixes again ([docs/ai-assistants.md](docs/ai-assistants.md)).
- **Notifications:** email, Slack, Microsoft Teams and signed webhooks: a few messages that bring people to the dashboard (urgent issues right away, grouped per asset and fix; a daily or weekly summary; a quiet "connected" message for a new server's first scan), with routing by priority, team and environment, quiet hours, hourly limits, retries and a delivery log. Feed, collector and coverage failures alert too.
- **Jira:** one issue per incident in Jira Cloud or Data Center, kept up to date as findings join and priority changes, commented on and optionally transitioned when the incident resolves, and linked from the dashboard.
- **Controlled remediation (Pro):** opt-in, policy-scoped upgrades with approval gates, maintenance windows, canary then staged rollout, verification against freshly collected inventory and health checks, and halt-on-failure with best-effort rollback where the package manager supports it. Hosts are enrolled one at a time with a bound token and a local allowlist. Repositories get Renovate pull requests, so code review stays in place. See [docs/remediation.md](docs/remediation.md).
- **Workspaces:** one installation can serve several organisations, kept apart by PostgreSQL row-level security as well as by the application.
- **Dashboard, API and CLI:** role-based access (viewer, engineer, security, admin, collector), API tokens, a full audit log and single sign-on (Pro).

## Quick start

Stackurity is self-hosted: your inventory and findings stay on your own server, and your hosts and pipelines send data to it. Nothing needs inbound access to your machines.

If you would rather not run a server, **Stackurity Cloud** runs the same release for you at [app.stackurity.ai](https://app.stackurity.ai): sign up for a 14-day free trial, no card needed, then choose a [plan](https://stackurity.ai/pricing.html). Self-hosting the Community edition stays free, with no account and no asset limit; nothing below needs Stackurity Cloud.

There are two ways to run it. Both keep the session cookie `Secure`, as production does: Chrome, Edge and Firefox treat `http://localhost` as a secure origin, so a trial on your own machine needs no security setting changed.

### Try it on your own machine

**1. Run the server** (Docker Compose):

```sh
git clone https://github.com/stackurity/stackurity.git
cd stackurity/deploy
./init-secrets.sh
docker compose up -d   # pulls the signed ghcr.io/stackurity/stackurity image; add --build to build from source
docker compose logs stackurity | grep -A2 "one-time token"
```

Open http://localhost:8080 in Chrome, Edge or Firefox on the same machine and create the first administrator with the token from the log. Safari does not send `Secure` cookies to `http://localhost`, so sign-in does not stick there: use another browser, or, for local evaluation only and never in production, start with `STACKURITY_PORT=127.0.0.1:8080 STACKURITY_COOKIE_SECURE=false STACKURITY_BASE_URL=http://localhost:8080 docker compose up -d`, which also keeps the port off your network ([why](docs/install.md#tls)).

**2. See it working in five minutes** with a labelled demo estate: a server with outdated packages and an end-of-life runtime, an application deployed on it, and two repositories. Findings appear once the vulnerability feeds have synced:

```sh
docker compose exec stackurity stackurity admin load-demo        # --remove deletes it again
```

**3. Connect your own estate:**

- **Servers:** under **Assets → Add server**, create an install command and run it on each Linux host. The agent is read-only and unprivileged, and it reports OS packages, runtimes and the libraries your deployed applications have installed.
- **Code:** add repositories under **Settings → Integrations**, or run `stackurity scan . --fail-on critical` in CI to block vulnerable changes.
- **Cloud:** the AWS plugin reads managed service versions with a read-only role, and the Kubernetes plugin reads a cluster's workloads, images and exposure with a read-only service account.
- **People and tools:** invite your team (or turn on single sign-on with Pro), route alerts to Slack, Teams or email, and connect AI assistants to `/mcp` with the organisation, project and role you choose.

**4. Act on it:** **Fixes** groups findings into concrete upgrades, and **Home** shows the few that need you now. With Pro, opt-in remediation applies approved upgrades on enrolled hosts and opens Renovate pull requests for repositories.

### Production install

Put Stackurity behind a reverse proxy that serves HTTPS (Caddy, nginx, Traefik), set `STACKURITY_BASE_URL=https://stackurity.example.com` and leave `STACKURITY_COOKIE_SECURE` at its default. The steps, Kubernetes (Helm), backups and the upgrade checklist are in [docs/install.md](docs/install.md). Never set `STACKURITY_COOKIE_SECURE=false` on a server other people reach: the server logs a warning and Platform health shows one if you do.

For TLS, backups, upgrades, Kubernetes (Helm), the agents and plugins, see [docs/install.md](docs/install.md). [docs/compatibility.md](docs/compatibility.md) lists supported platforms and what each can assess, [docs/verification.md](docs/verification.md) how each claim is tested, and [CHANGELOG.md](CHANGELOG.md) what changed in each release. [docs/security-audit.md](docs/security-audit.md) covers the threat model and how releases are signed, and [docs/operations.md](docs/operations.md) the recommended alerts, their runbooks and operational drills. The API is described in [docs/api.md](docs/api.md), and every outbound connection is listed in [docs/network.md](docs/network.md).

## Known limitations

- Several server replicas can share one database, but versions cannot be mixed: an upgrade stops every replica before the new version starts ([upgrade checklist](docs/install.md#upgrading)). A server whose database a newer version has migrated refuses to start, and one already running fails `/readyz`.
- Vulnerability matching covers language packages, Debian, Ubuntu (not Pro), Alpine, Rocky, Alma, RHEL, Oracle Linux, SUSE, openSUSE Leap and Amazon Linux 2 and 2023. CentOS, Fedora and Amazon Linux 1 packages are inventoried but listed as evaluation gaps.
- Red Hat advisories are matched against the main stream of each major release; Extended Update Support (EUS, AUS) streams are not modelled, so a host held on an EUS minor release can show fixes it already has through EUS. SUSE publishes no severity in its advisory data, so SUSE findings show severity "unknown" and are prioritised on the other risk factors.
- Amazon Linux 2 extras topics are read when the topic name carries its version line (kernel-5.10, php8.2, postgresql14); packages from other topics (docker, epel and similar) are matched against core advisories only.
- Release (latest-version) data covers the language registries above, not OS packages. Maven Central publishes no release dates, and RubyGems hides yanked versions, so neither is shown for those. Lifecycle data covers everything endoflife.date tracks.
- Upgrade recommendations pick the newest release in a major line from the full list of stable releases, which release sync records from this release on; until a component's release data is next refreshed (daily) only versions the registry dates are known. Major lines are the leading version number, also for 0.x packages.
- Reopened findings are counted from the upgrade that started recording them; earlier reopenings are not known.
- Runtimes found outside the package manager get lifecycle (end-of-life) tracking only; vulnerabilities are not matched for them.
- A distribution package past its upstream end of life (nginx 1.18 on Ubuntu 22.04) raises no end-of-life finding while the distribution release is supported. The agent does not record which repository a package came from: builds from Ondřej Surý's PHP repository, nginx.org, NodeSource, PGDG, Remi and MySQL's APT repository are recognised by their version and keep the upstream date, other third-party builds are taken as the distribution's own. Ubuntu `universe` packages, which get security fixes only through Ubuntu Pro, are not told apart from `main` ([details](docs/compatibility.md#lifecycle-of-distribution-packages)).
- Java needs the Java stack pack; from a `pom.xml` alone it sees direct dependencies only. Windows hotfixes and Microsoft Store apps are reported as unsupported coverage.
- Single sign-on (OpenID Connect or SAML) admits people into one workspace per installation; SAML single logout is not supported.
- Kubernetes exposure covers Services, Ingresses and host networking, not Gateway API routes or service meshes. Running images are scanned without registry credentials, so images behind pull secrets show as failed coverage unless added as container image integrations. Kubernetes CVEs are not matched (lifecycle only).
- Remediation applies to Linux packages (apt, dnf, yum, zypper, apk) and to repositories through Renovate. Kernels and other packages installed side by side in several versions are not upgraded automatically on rpm systems.

## Editions

Community is free and complete for finding and prioritising what to fix. Pro adds automatic fixing, multi-team workflow, the evidence report and single sign-on; Enterprise adds packs for enterprise technologies. [docs/editions.md](docs/editions.md) has the full matrix with limits and prerequisites; licences are covered in [Editions and licences](docs/install.md#editions-and-licences).

## Principles

- Self-hosted, with no vendor account and no telemetry. The only automatic request to the project is a check for new releases: an anonymous read of the public release list that sends nothing about you, compared locally, and turned off with `STACKURITY_UPDATE_CHECK=off`. **Send feedback** in the dashboard sends only what a user writes there, when they press Send; `STACKURITY_FEEDBACK_URL=` turns it off.
- Every finding carries its source, timestamp and confidence.
- Missing or stale data is shown as missing or stale. It is never treated as healthy.
- Refreshing intelligence never changes your software. Changes need explicit policy.

## Pilots and reporting wrong results

[docs/pilot.md](docs/pilot.md) describes a two-to-four-week pilot, hosted or on your own server. If Stackurity reports something that does not apply, misses a known vulnerability, or cannot check something you need, use the [issue forms](https://github.com/stackurity/stackurity/issues/new/choose); confirmed wrong and missed findings become permanent test cases.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 OUTDO INC.
