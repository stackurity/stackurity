# API v1

Base path: `/api/v1`. Requests and responses are JSON. Errors look like this:

```json
{"error": {"code": "invalid", "message": "validation failed", "details": ["observations[3].purl \"x\" is not a valid purl"]}}
```

## Authentication

- **API tokens** (`Authorization: Bearer stk_...`) for the CLI, agents and integrations. User tokens carry a role no higher than their owner's *current* role. Collector tokens can only submit observations and SBOMs.
- **Session cookie** for the dashboard (`POST /auth/login`). Requests that use cookie authentication and change state must send `X-Stackurity-CSRF: 1`.

Roles, from least to most access: `viewer` (read, including the audit log), `engineer` (edit assets, trigger scans), `security` (risk acceptance and exceptions, notification channels and routes, remediation policies, plan approval), `admin` (users, teams, tokens, integrations, conflicts, deletion).

## Endpoints

| Method & path | Role | Purpose |
|---|---|---|
| `GET /meta` | none | Version and whether first-time setup is required |
| `POST /setup` | setup token | Create the first admin |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | none / any | Session handling |
| `POST /auth/password` | any signed-in user | Change your own password (`current_password`, `new_password`). Your other sessions are signed out |
| `POST /enroll` | none (rate limited) | Exchange a one-time enrollment code (`{"code", "hostname"}`) for a collector token and the agent settings chosen with it. Refusals do not say why |
| `GET`/`POST /enrollments`, `DELETE /enrollments/{id}` | admin | Create, list and revoke enrollment codes: `label`, `environment`, `app_dirs`, `discover_apps`, `uses` (1–500, default 1), `ttl_hours` (1–720, default 24). The code is returned once |
| `GET /install/agent.sh`, `GET /download/agent/linux-{amd64,arm64}[.sha256]` | none | The agent installer and the agent builds it downloads (bundled in the server image; `STACKURITY_AGENT_DIR`) |
| `POST /ingest` | collector, engineer+ | Submit an `ObservationBatch` (gzip accepted) |
| `POST /sbom/import?asset_name=&asset_kind=&environment=` | collector, engineer+ | Import a CycloneDX or SPDX JSON document |
| `GET /collections/{id}/result` | collector (own submissions), engineer+ | Whether a submitted collection has been evaluated (`status`: `pending`, `evaluated`, `failed`), then the asset's open findings and its count of `evaluation_gaps`. Used by `stackurity scan --fail-on` |
| `GET /overview` | viewer | Inventory, coverage and status counts |
| `GET /search?q=&limit=` | viewer | Global search of the current workspace, see [Search](#search) |
| `GET /assets?kind=&environment=&status=&owner_team_id=&q=&reboot_required=true` | viewer | List assets. `reboot_required=true` lists hosts that run older code than is installed |
| `GET /assets/{id}` | viewer | Asset and identifiers |
| `PATCH /assets/{id}` | engineer | Set name, environment, owner, criticality, exposure, tags |
| `DELETE /assets/{id}` | admin | Delete an asset and its history |
| `GET /assets/{id}/inventory?q=&type=&direct=&include_removed=` | viewer | Components on the asset, with evidence |
| `GET /assets/{id}/coverage`, `/collections`, `/relations` | viewer | Coverage ledger, collection history, relations |
| `POST`/`DELETE /assets/{id}/relations` | engineer | Add or remove `runs_on`, `built_from`, `deployed_as`, `contains`, `depends_on`, `replica_of` (a standby, staging or DR copy that should run the same versions as the target) |
| `GET /assets/{id}/stack` | viewer | Everything the asset relies on, followed through relations, with open findings grouped by layer (`web_server`, `os`, `runtime`, `data_store`, `libraries`, `declared`, `managed_service`, `other`). For an application this is its hosts, repository, images and dependencies (up to three hops); for a host, the applications running on it; for a repository, its deployments and their hosts |
| `GET /assets/{id}/drift?with=` | viewer | Components whose versions differ from another asset (`with`, or the asset this one is a `replica_of`). Each item is `behind`, `ahead`, `differs`, `only_here` or `only_there`, compared by the component's ecosystem rules |
| `GET /assets/{id}/sbom` | viewer | CycloneDX 1.6 export |
| `GET /components?q=&type=`, `GET /components/{id}` | viewer | Component explorer |
| `GET /inventory?component_id=&asset_id=` | viewer | Where a component is used |
| `GET /coverage?problems=true` | viewer | Coverage ledger across assets |
| `GET /reports/evidence?from=&to=` | viewer | Patch-management evidence for a period (dates, `to` inclusive; default the last 30 days, at most a year): assets and their collection status, hosts needing a reboot, evaluation gaps, open findings by severity and priority, overdue findings, findings resolved in the period with the share resolved within their deadline and the median days from first detection to resolution, every active exception with its reason, mitigation and expiry, and drift for each `replica_of` pair |
| `GET /audit?object_type=&object_id=` | viewer | Audit events |
| `GET`/`POST /tokens`, `DELETE /tokens/{id}` | any user | Personal tokens (admins: all tokens and collector tokens) |
| `GET /teams` | viewer | Teams |
| `POST`/`PATCH`/`DELETE /teams/{id}` | admin | Manage teams and members |
| `GET`/`POST /users`, `PATCH /users/{id}` | admin | Manage users |
| `GET /integrations`, `POST /integrations/{id}/run` | engineer | List integrations, trigger a run |
| `POST`/`PATCH`/`DELETE /integrations/{id}` | admin | Manage integrations |
| `GET /conflicts`, `POST /conflicts/{id}/resolve` | admin | Resolve asset identity conflicts by merging assets |
| `GET /jobs?state=` | admin | Background job queue |
| `GET /plugins` | admin | Installed plugins with their declared permissions, credentials and network access |
| `GET /jobs/{id}` | engineer | Status of one job, e.g. after *Run now* |
| `GET /admin/health` | instance admin | Platform health across workspaces: `status` (`ok`, `warning`, `critical`), `problems`, background `tasks` with their last success and error, job counts by kind and state, and jobs that failed in the last 24 hours ([install.md](install.md#health)) |
| `GET /facets` | viewer | Distinct environments, asset kinds and component types |
| `GET /findings?status=&kind=&severity=&verification=&asset_id=&component_id=&environment=&known_exploited=&q=&key=` | viewer | Vulnerability and end-of-life findings, known-exploited and most severe first |
| `GET /findings/summary` | viewer | Counts by severity, kind and verification, plus stale feeds and evaluation gaps |
| `GET /findings/{id}` | viewer | One finding, with every source advisory in its group |
| `GET /advisories/{id-or-CVE}` | viewer | Advisories in a group |
| `GET /components/{id}/intel` | viewer | Release data (latest stable, publish date, deprecation) and lifecycle cycles |
| `GET /feeds` | viewer | Intelligence feeds and their freshness |
| `POST /feeds/{name}/refresh` | engineer | Queue a manual refresh |
| `PATCH /feeds/{name}` | admin | Enable or disable a feed |
| `GET /evaluation-gaps` | viewer | Components that could not be evaluated, with the reason |
| `POST /evaluate` | engineer | Queue a full re-evaluation |
| `POST /findings/{id}/actions` | engineer (security for `suppress`, `accept_risk`, `reopen`) | Workflow action, see below |
| `POST /findings/actions` | as above | The same action on up to 500 findings (`ids`) |
| `GET /findings/{id}/events` | viewer | A finding's workflow history |
| `GET /incidents?status=&kind=&priority=&sos=&team_id=` | viewer | Incidents: findings grouped by issue and owner team |
| `GET /incidents/{id}` | viewer | An incident with its findings (and deliveries, for security and above) |
| `POST /incidents/{id}/actions` | as findings | Apply an action to every open finding in the incident |
| `GET /risk-policy` / `PUT /risk-policy` | viewer / admin | Priority weights, thresholds, deadlines and SOS rules |
| `GET /channels`, `GET /routes`, `GET /deliveries?status=&incident_id=` | security | Notification configuration and delivery log |
| `POST`/`PATCH`/`DELETE /channels/{id}`, `POST /channels/{id}/test` | admin | Email, Slack, Teams and webhook channels |
| `POST /routes`, `PUT`/`DELETE /routes/{id}` | admin | Which incidents go to which channel |
| `POST /deliveries/{id}/retry` | admin | Retry a failed or held delivery |
| `GET /users/directory` | engineer | Active users (id, email, name) for assignment |
| `GET /remediation/policies` | security | Remediation policies |
| `POST /remediation/policies`, `PUT`/`DELETE /remediation/policies/{id}` | admin | Manage policies ([remediation.md](remediation.md)) |
| `GET /remediation/plans?status=`, `GET /remediation/plans/{id}` | viewer | Plans and their per-asset actions |
| `POST /remediation/plans/{id}/decision` | security (admin for major) | `{"decision": "approve" \| "reject" \| "cancel", "note": "..."}` |
| `GET /assets/{id}/remediation` | viewer | Remediation actions for an asset |
| `POST /assets/{id}/remediation-token` | admin | Collector token bound to this host, required for remediation |
| `GET /agent/actions`, `POST /agent/actions/{id}/report` | host-bound token | Agent fetches approved changes and reports results |
| `GET /remediation/renovate.json?repository=&mode=exclusive` | collector, engineer | Renovate rules for approved repository plans |

Lists return `{"items": [...], "total": N, "limit": L, "offset": O}`. Pass `?limit=` (max 500) and `?offset=`.

## Search

`GET /search?q=lodash@4.17.20&limit=10` looks one query up everywhere at once and returns the matches grouped by type. `q` is trimmed and must be 2 to 200 characters; `%`, `_` and `\` match themselves. `limit` (default 10, max 50) applies to each group, and `more` says which groups had more matches.

```json
{"query": "...", "vulnerabilities": [...], "assets": [...], "components": [...], "teams": [...],
 "more": {"vulnerabilities": false, "assets": true, "components": false, "teams": false}}
```

- **vulnerabilities**: when the query looks like an id (one word with a digit and a `-` or `:`), advisories whose id, alias or group is the query, in any letter case (CVE, GHSA, DSA, USN, RHSA, ALAS and other OSV ids), and finding keys that contain it. Each result is a finding key with the workspace's open and resolved findings, the number of assets with an open finding, a sample of `assets` and `components`, and the public `advisory` when one is known. An advisory that affects nothing in the workspace is returned with `kind: ""` and zero counts.
- **components**: packages currently installed, matched on name or `namespace/name`. A version can be given as `name@version`, `name version` or a purl (`pkg:npm/lodash@4.17.20`, which also filters by type and namespace); `version_assets` and the sample `assets` then cover that version, where `3.0.2` also matches distro builds such as `3.0.2-0ubuntu1.10`. Maven coordinates (`group:artifact`) and npm scopes (`@scope/name`) work as names.
- **assets**: by name, any identifier (machine id, hostname, repository URL, image reference, ARN, SBOM serial) or the `digest` and `image` attributes. `match_scheme` and `match_value` say which identifier matched.
- **teams**: by name or email, with the assets they own and those assets' open findings.

Every result has a `rank`: `0` for an exact (case-insensitive) match of an id, name or identifier, `1` for a prefix, `2` for a substring; results are ordered by rank. Search only reads the current workspace; advisories are public data.

## ObservationBatch

The single ingest contract for agents, scanners, SBOM imports and plugins. See [`internal/model/batch.go`](../internal/model/batch.go).

```json
{
  "schema_version": "1",
  "collector": {"id": "linux-agent", "version": "0.1.0", "method": "agent"},
  "asset": {
    "kind": "host", "name": "web-1",
    "identifiers": [{"scheme": "machine-id", "value": "4c4c..."}],
    "environment": "production",
    "attributes": {"os": "debian", "os_version": "12"}
  },
  "observed_at": "2026-10-23T09:00:00Z",
  "observations": [{
    "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",
    "version": "3.0.11-1~deb12u2",
    "location": "/var/lib/dpkg/status",
    "scope": "os",
    "confidence": "confirmed",
    "evidence": {"source_package": "openssl"}
  }],
  "coverage": [{"scope": "dpkg", "status": "checked"}],
  "complete": true
}
```

- `relations` (optional) links the asset to others by identifier: `[{"kind": "runs_on", "to": [{"scheme": "machine-id", "value": "..."}]}]`. Kinds are `runs_on` and `built_from`. Targets the server does not know yet are skipped. When present, the list replaces the relations this collector reported before; relations added by hand are kept.
- An application on a host is identified as `{"scheme": "app-path", "value": "/srv/shop"}`, its only identifier, with a `runs_on` relation to the host. The server scopes the path to that host, which must already exist. A host-bound token may only report applications on its own host, and plugins cannot use this scheme.
- `complete: true` tells the server that this batch is the collector's whole view of the asset. Components missing from it are marked removed, and history is kept. Partial batches never remove anything.
- `coverage[].status` is one of `checked`, `skipped`, `failed`, `unsupported` or `partial`.
- Limits: 200,000 observations, 64 MiB on the wire, 256 MiB after decompression.

Schema changes follow semantic versioning on `schema_version`. A breaking change gets a new version, and the server accepts the previous version for at least one minor release.

## Findings

A finding is one issue on one inventory row:

- `kind` is `vulnerability` or `end_of_life`.
- `key` is the deduplication key. For vulnerabilities it is the lowest CVE among the advisory's id and aliases, otherwise the advisory id. For lifecycle findings it is `product:cycle`. GHSA, OSV and distro advisories for the same CVE become one finding, and `sources` lists all of them.
- `verification` says how much the finding can be trusted:
  - `confirmed`: an exact package and version from an authoritative local source falls in an affected range.
  - `needs_validation`: the installed version came from a low-confidence source. Severity is withheld (`unknown`) until the version is confirmed.
  - `stale`: the asset has not reported recently, so the component may no longer be installed.
- `fixed_version` is the highest "first fixed" version across the matching sources, so every source agrees the target is fixed. It is empty when no source lists a fix.
- `evidence` records the matched ranges, the OSV package and ecosystem, the comparator used, the feed and its last successful sync, and whether the CVE is in CISA KEV.

Findings resolve automatically when the component is upgraded or removed, or when an advisory is withdrawn. If the issue comes back, the finding reopens.

## Workflow

Each finding has a detection `status` (`open` or `resolved`), set automatically, and a workflow `state` that people set:

| Action | Resulting state | Notes |
|---|---|---|
| `acknowledge` | `acknowledged` | Stops acknowledgement escalation |
| `start` | `in_progress` | |
| `reset` | `new` | |
| `assign` | unchanged | `user_id` and/or `team_id`; `0` clears |
| `comment` | unchanged | `note` is recorded in the history |
| `suppress` | `suppressed` | Security role. `note` (reason) and `until` are required; `until` may be at most the risk policy's `exception_max_days` (default 365) ahead. Optional `mitigation` records what reduces the risk meanwhile |
| `accept_risk` | `risk_accepted` | Security role. Same fields and limit as `suppress` |
| `reopen` | `new` | Security role, from `suppressed` or `risk_accepted` |

When a suppression or risk acceptance expires, the finding returns to `new` and is announced again. Every action is recorded in the finding's history and in the audit log.

## Priority and SOS

Every open finding gets a priority from P1 to P4. The score is built from the CVSS score (CVSS v3.x or v4.0, whichever rates the advisory higher; `severity_source` on the advisory says which) or the severity when there is none, CISA KEV, internet exposure (unknown exposure counts a little), production environment, asset criticality, fix availability, whether it is overdue, and dev-only scope. It is then scaled down for unverified or stale evidence. `priority_factors` lists each contribution. Weights, thresholds and per-priority deadlines are configured in `/risk-policy`.

SOS rules are conditions over the same inputs. A rule based only on severity is rejected. Only confirmed findings can trigger SOS.

## Incidents and notifications

Findings with the same `kind` and `key` whose assets belong to the same owner team form one incident, so one CVE across fifty servers produces one alert. System problems also open incidents, and these resolve on their own once the problem is gone:

- a stale or failing feed (`feed`)
- a stale asset or failing integration (`collection`)
- a drop of more than half in an asset's collected inventory (`coverage`)
- in the default workspace only, a critical problem with the installation itself, such as a background task that keeps failing or intelligence that never synced (`platform`)

Routes send incidents to channels and filter by minimum priority, SOS only, kinds, environments and owner teams. Each incident produces at most one notification per event:

- `opened`
- `priority_raised`
- `escalated`: level 1 when the acknowledgement deadline has passed, level 2 when the fix deadline has passed. Only routes marked `escalation` receive these.
- `resolved`

Quiet hours delay everything except SOS. When `max_per_hour` is reached, further notifications are held and sent together in an hourly digest. Failed deliveries are retried with backoff up to 8 times.

Webhook channels receive the JSON message with these headers:

- `X-Stackurity-Event`
- `X-Stackurity-Delivery`
- `X-Stackurity-Timestamp`
- `X-Stackurity-Signature: sha256=HMAC(secret, timestamp + "." + body)`

To verify a delivery, recompute the HMAC over the timestamp and body, and reject old timestamps.

Delivery is at least once: if a server dies after sending but before recording it, the message is sent again a few minutes later. Receivers that must not act twice can deduplicate on `X-Stackurity-Delivery`.
