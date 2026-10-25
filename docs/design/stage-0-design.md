# Stackurity — Stage 0 design

**Status:** Accepted, and implemented through Stage 5 · 2026-10-23. "Implementation notes" at the end lists where the build departed from this plan.
**Scope:** Decisions needed before Stage 1 code. Requirements live in the PRD (v1.1); this document records *how* we will meet them and what we deliberately reuse.

## 1. Decisions

| # | Decision | Choice |
|---|---|---|
| D1 | Name | Stackurity (working name; trademark/domain screen before public launch) |
| D2 | License | Apache-2.0 for all Stackurity code |
| D3 | Languages | Go for server, agent and CLI; TypeScript + React (Vite) for the dashboard |
| D4 | Packaging | One Go binary `stackurity` with subcommands (`server`, `agent`, `scan`, `sbom`, `admin`). Dashboard is embedded into the binary. |
| D5 | Database | PostgreSQL 16+. No SQLite mode in MVP. |
| D6 | Job queue | PostgreSQL table with `FOR UPDATE SKIP LOCKED`. No Redis or broker in the MVP, so it's one fewer service to run and back up. |
| D7 | Install | Docker Compose: `stackurity` and `postgres`. Scanner binaries (Trivy, Syft) are pinned inside the server image. |
| D8 | Vulnerability data | OSV is the primary feed, downloaded in bulk per ecosystem and matched by our own matcher (see §4). Trivy/Grype results are imported as a second verifier, not as the source of truth. |
| D9 | Version intelligence | Registry APIs (npm, Packagist; more via adapters) for releases; endoflife.date for lifecycle |
| D10 | Component identity | Package URL (purl) without version is the component key; version is stored separately |
| D11 | SBOM | CycloneDX 1.6 JSON import/export via `cyclonedx-go`; SPDX 2.3 JSON import with our own parser |
| D12 | Auth | Local users (argon2id) + session cookie for UI, hashed API tokens for API/agents. OIDC is post-MVP. |
| D13 | Remediation | Not in MVP. The policy engine, audit log and asset model are designed so Stage 4 adds remediation without schema rewrites. |
| D14 | Plugins | Built-in adapters implement a Go interface now. External plugins (Stage 5) run as separate processes that speak versioned JSON over stdio, using the same contract. |
| D15 | Telemetry | None. All outbound calls are listed in `docs/network.md`. |

## 2. Reuse review (verified 2026-10-23)

| Project | License | How we use it | Notes |
|---|---|---|---|
| Trivy | Apache-2.0 | Pinned binary for container image / filesystem scans (Stage 2) | Run as a subprocess with a timeout; output parsed and validated as untrusted |
| Syft | Apache-2.0 | Pinned binary for SBOM generation from images | Optional alternative to Trivy for inventory |
| Grype | Apache-2.0 | Optional second verifier | Not bundled in MVP |
| OSV-Scanner | Apache-2.0 | Not embedded; OSV **data** is used directly | Our matcher needs to re-evaluate stored inventory without rescanning |
| OSV data | Per source (GHSA CC-BY-4.0, Ubuntu CC-BY-SA-4.0, Chainguard CC-BY-NC-ND-4.0, …) | Each install downloads it directly from `storage.googleapis.com/osv-vulnerabilities` | We do not redistribute feed data. Attribution is shown in the UI. Ecosystems are configurable so operators can exclude sources whose terms they cannot accept. |
| endoflife.date | MIT (code/data) | Lifecycle API `endoflife.date/api/v1` | Products carry purl identifiers we can map to components |
| Dependency-Track | Apache-2.0 | Not embedded. Optional export target via CycloneDX. | Overlaps with our SBOM portfolio features but has no host/cloud inventory, coverage ledger or remediation |
| Renovate | **AGPL-3.0** | Stage 4: invoked as a separate, user-run tool/container; Stackurity generates config and reads results | Never vendored or linked into Stackurity |
| cyclonedx-go | Apache-2.0 | Go library | |
| spdx/tools-golang | license metadata unclear on GitHub | Not used. We parse SPDX JSON ourselves. | Revisit if needed |
| bum.pt | Source-available, proprietary (no hosting or competing products without a commercial agreement) | Product reference only. **No code reuse.** | Feature overlap: version tracking, release metadata, EOL, CVE lookup |

**Where Stackurity adds value over these tools:** one inventory that spans hosts, repos, images, SBOMs and cloud services; evidence and provenance on every observation; a coverage ledger; risk-based SOS with ownership and escalation; and, later, policy-gated remediation.

## 3. Architecture

```
            ┌──────────── stackurity server ─────────────────────────────┐
 Browser ──►│ HTTP: /api/v1 (JSON, OpenAPI)  ·  embedded React dashboard │
 CLI ──────►│ auth (session / API token) · RBAC                          │
 Agent ────►│ ingest: observation batches → validation → inventory       │
            │ workers (Postgres queue):                                  │
            │   feed refresh (OSV, registries, endoflife.date)           │
            │   matcher / re-evaluation · risk scoring                   │
            │   repo + image scans · notifications · coverage checks     │
            └────────────────────────────┬───────────────────────────────┘
                                         │
                                    PostgreSQL
```

- **Ingest is the single entry point.** Agents, CLI scans, SBOM imports, scanner adapters and (later) plugins all produce an `ObservationBatch`. Batches are validated (size limits, purl syntax, schema version) and written as observations, then folded into current inventory.
- **Evaluation is separate from collection.** When a feed changes, only the components affected by the changed advisories are re-evaluated (FR-05/FR-06). Rescanning isn't needed.
- **Never execute target code.** Lockfiles and manifests are parsed as data. Repos are shallow-cloned, read, then deleted. No install scripts or builds run.

## 4. Vulnerability matching

- The OSV per-ecosystem `all.zip` is fetched on first run. After that, `modified_id.csv` drives incremental hourly refresh (FR-06). We record attempt and success times per feed.
- Advisories are stored with their aliases (CVE, GHSA, …). Findings are deduplicated by alias group but keep every source (FR-05).
- Version comparison is per ecosystem: npm (semver), Packagist (Composer normalisation), Debian (dpkg epoch/upstream/revision), RPM (rpmvercmp), Alpine (apk). Distro packages are matched against the distro's own OSV ecosystem (e.g. `Debian:12`, `Ubuntu:24.04:LTS`), so backported fixes are respected.
- Findings get a verification state (FR-15): `confirmed` (exact purl + version within an affected range from an authoritative source), `needs_validation` (fuzzy name match, missing version, or inferred ecosystem), `rejected`, `unknown`, `stale` (feed past its freshness threshold).

## 5. Data model (Stage 1–2)

| Table | Purpose |
|---|---|
| `assets` | id, kind (host, repository, image, application, managed_service, sbom), name, environment, owner_team_id, provider, region, criticality, tags, first_seen, last_seen, collection_status |
| `asset_identifiers` | (scheme, value) → asset, e.g. `machine-id`, `git-url`, `image-digest`. Unique per scheme/value; conflicts are flagged for an admin to resolve (FR-02). |
| `asset_relations` | from_asset, to_asset, kind (runs_on, built_from, deployed_as, contains) |
| `components` | purl without version, ecosystem, name, namespace |
| `observations` | append-only: asset, component, version, location (path/layer), direct/transitive, source, method, collector + version, observed_at, confidence, evidence (JSON) |
| `inventory` | current state: one row per (asset, component, version, location), with first/last observed and the last observation id |
| `releases` | component, version, published_at, channel (stable, prerelease), yanked, source, checked_at |
| `lifecycles` | endoflife.date product/cycle, eol, support end, latest, linked purls |
| `advisories` | OSV id, aliases, summary, severity (CVSS vector/score), affected (JSON), published, modified, source, withdrawn |
| `findings` | inventory row × advisory group (or lifecycle/update finding); kind, verification state, risk score + factors, status (open, acknowledged, suppressed, resolved), timestamps |
| `feeds` | name, ecosystem, last_attempt, last_success, last_error, cursor |
| `coverage` | target (asset/integration), collector, scope checked, scope skipped + reason, last attempt/success, tool version (FR-16) |
| `teams`, `users`, `memberships`, `api_tokens` | ownership + RBAC |
| `audit_events` | actor, action, object, before/after, at (FR-14) |
| `jobs` | queue: kind, payload, run_at, attempts, locked_by, last_error |

Roles: `admin`, `security`, `engineer`, `viewer` (auditor). Risk acceptance is limited to `security` and `admin`, and requires a reason and an expiry (FR-09).

## 6. Collector contract

```go
type Adapter interface {
    Metadata() Metadata            // id, version, license, capabilities, permissions, network access
    Validate(cfg Config) error
    Collect(ctx context.Context, cfg Config) (ObservationBatch, error)
    Health(ctx context.Context, cfg Config) HealthStatus
}
```

`ObservationBatch` carries schema version, collector identity, target asset identifiers, observations, and a coverage report (what was checked, skipped and why). External plugins later send the same JSON.

## 7. Stage plan

| Stage | Delivers | Exit check |
|---|---|---|
| 1 Core inventory | Compose install, Postgres schema + migrations, auth/RBAC, ingest API, Linux agent (dpkg/rpm/apk + os-release), npm and Composer lockfile parsing (CLI dir scan + Git repo integration), CycloneDX/SPDX import, CycloneDX export, coverage ledger, dashboard: overview, assets, components, coverage | `docker compose up`, then the agent reports a host, a repo scan reports dependencies, and an SBOM imports. Everything appears in one inventory with source and timestamps. |
| 2 Intelligence | OSV feeds + matcher, npm/Packagist release data, endoflife.date, hourly refresh + targeted re-evaluation, Trivy image scanning, findings UI with evidence, feed health | Known-vulnerable fixtures produce confirmed findings with evidence; stale feeds are visible |
| 3 Alerts & workflow | Email, Slack, Teams, webhook; routing, SOS rules, dedupe/grouping, ack/assign/suppress, escalation, collector/feed failure alerts | Each connector is configurable independently; there are no duplicate incidents on reprocessing |
| 4 Remediation | Policies, allowlists, Renovate integration, host patch actions (opt-in agent mode), dry-run, approvals, staged rollout, verify-after-change | Unapproved components cannot be changed (test-enforced) |
| 5 Ecosystem | External plugin runtime + SDK, more ecosystems/distros/cloud (AWS first), Helm chart, self-audit workflow | A third party builds an adapter from the docs alone |

**Rough effort** (one experienced engineer, full-time): Stage 1 ≈ 6–8 weeks, Stage 2 ≈ 5–6, Stage 3 ≈ 4–5, Stage 4 ≈ 6–8, Stage 5 open-ended. A team of three cuts the calendar time by about half; the rest is review and integration overhead.

## 8. Open items

- First cloud provider (assumed AWS) and Windows collector timing (Stage 5).

## Implementation notes (what changed during the build)

- **Container images use Syft, not Trivy, for inventory.** Syft builds a CycloneDX SBOM straight from the registry and needs no vulnerability database. Stackurity's own OSV matcher then evaluates it like every other source. Syft is pinned and checksum-verified in the image.
- **Matching runs on our own OSV engine.** The comparators follow each ecosystem's rules: semver, Composer, dpkg, rpm, apk, PEP 440 and RubyGems. A Trivy or Grype second opinion (FR-15) is still possible later through SBOM import or a plugin.
- **Severity:** CVSS v3 and v4 are scored locally (v4 as in the FIRST reference calculator, with threat and environmental metrics when the vector carries them). When scores and the vendor label disagree, the higher one wins, because some advisories carry an all-"None" v3 vector next to a HIGH rating, and under-rating is the more dangerous error. Of a v3 and a v4 score at the same level, the higher score is kept.
- **Advisory grouping** uses the lowest CVE found in an advisory's id, aliases and upstream fields, so GHSA, OSV, DSA and DEBIAN-CVE records for one issue become one finding.
- **Risk defaults were calibrated on live data.** P1 starts at a score of 12. SOS needs known exploitation in production, or a critical score on an exposed production asset. The earlier "P1 with a fix" rule paged on every high-severity issue of an exposed critical app.
- **Incidents follow ownership changes** instead of resolving and reopening.
- **Remediation** (Stage 4) is built as policy → plan → staged actions:
  - Hosts take part only with a host-bound token plus the agent's local allowlist.
  - Success requires re-collected inventory plus health checks.
  - Repositories get Renovate configuration rather than server-side edits, because Renovate is AGPL and runs separately.
  - It was verified end to end on a Debian 12 container upgrading `libexpat1` from live OSV data.
- **Plugins** (Stage 5) are separate executables speaking versioned JSON over stdio (`pkg/plugin`). AWS support ships as the first-party `aws-managed` plugin, so the AWS SDK stays out of the server binary.
- **YAML:** `gopkg.in/yaml.v3` is archived, so the maintained `go.yaml.in/yaml/v3` is used instead.
- **Releases** are signed with Sigstore (keyless) and carry provenance attestations and SBOMs.
- **Operational signals** (after Stage 5, from reviewing a real patch-management plan against the product):
  - `stackurity scan --fail-on` gates CI by reading back the server's evaluation of its own upload, so priority and exceptions apply, rather than matching locally.
  - Evaluation jobs that are already running are re-queued when new data arrives. Before this, such a batch waited for the daily pass.
  - The Linux agent reports reboot-pending hosts and finds runtimes installed outside the package manager. Their lifecycle is tracked, but there is no vulnerability matching for them.
  - `replica_of` relations expose standby and staging drift.
  - Exceptions carry a mitigation and a policy-set maximum length.
  - A periodic evidence report summarises patch management for audits.
  - Deliberately left out: a SIEM, field-device version reporting (needs code in each app) and a vulnerability matcher for unmanaged binaries.

Still open (see README, "Known limitations"):

- multi-replica workers
- OIDC/SAML
- RHEL and SUSE advisory feeds
- Maven and Gradle
- trademark screening and copyright-holder decision
