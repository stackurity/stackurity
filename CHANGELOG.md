# Changelog

All notable changes to Stackurity. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version can change behaviour, and the notes say when it does.

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
