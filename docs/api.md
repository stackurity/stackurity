# API v1

Base path: `/api/v1`. Requests and responses are JSON.

- **Reference:** every operation, with its parameters, role and authentication, is in the [rendered API reference](https://stackurity.dev/api.html) and in the OpenAPI 3.1 document each server serves at `GET /api/v1/openapi.json` (no sign-in needed; the source is [internal/api/openapi.json](../internal/api/openapi.json)). Load it into Swagger UI, Postman or a client generator.
- **This page** lists every route the server serves, grouped by area, and describes what the answers contain.

Contents: [Authentication](#authentication) · [Projects and access](#projects-and-access) · [Conventions](#conventions) · Endpoints: [Account](#account), [Setup](#setup), [Agents and uploads](#agents-and-uploads), [Inventory](#inventory), [Findings and fixes](#findings-and-fixes), [Projects and people](#projects-and-people), [Notifications](#notifications), [Integrations](#integrations), [Intelligence](#intelligence), [Reports](#reports), [Automatic fixes](#automatic-fixes), [Instance administration](#instance-administration), [AI assistants, OAuth and MCP](#ai-assistants-oauth-and-mcp), [Health and discovery](#health-and-discovery) · Topics: [Inventory coverage](#inventory-coverage), [Uploads into a project](#uploads-into-a-project), [Onboarding](#onboarding), [Invitations](#invitations), [Search](#search), [ObservationBatch](#observationbatch), [Findings](#findings), [Upgrade recommendations](#upgrade-recommendations), [Remediation outcomes](#remediation-outcomes), [Workflow](#workflow), [Check again](#check-again), [Priority and SOS](#priority-and-sos), [Incidents and notifications](#incidents-and-notifications)

## Authentication

- **API tokens** (`Authorization: Bearer stk_...`) for the CLI, agents and integrations. User tokens carry a role no higher than their owner's *current* role. Collector tokens can only submit observations and SBOMs.
- **Session cookie** for the dashboard (`POST /auth/login`). Requests that use cookie authentication and change state must send `X-Stackurity-CSRF: 1`.
- **AI assistants** connect to `/mcp` (outside `/api/v1`) and sign in with OAuth 2.1; their access tokens (`stka_...`) work only there, not on this API. See [AI assistants, OAuth and MCP](#ai-assistants-oauth-and-mcp) and [ai-assistants.md](ai-assistants.md).

Roles, from least to most access: `viewer` (read, including the audit log; ask to ignore issues), `engineer` (edit assets, trigger scans, check again; ask to ignore issues), `security` (snooze, ignore and risk acceptance, deciding ignore requests, notification channels and routes, remediation policies, plan approval), `admin` (users, teams, tokens, integrations, conflicts, deletion). An **instance admin** operates the whole installation (workspaces, licence, stack packs, feeds, platform health), whatever their role in a workspace.

## Projects and access

A workspace (shown as the organisation in the dashboard) groups its assets into **projects**; one asset can be in several. The roles above apply either to the whole workspace (organisation-wide) or, through **access grants**, to chosen projects or single assets only. See [docs/design/projects.md](design/projects.md).

- **Members with project access only** (`GET /auth/me` returns `"access": "projects"` and an empty `role`) see only the assets of their projects and asset grants, and everything that hangs off them: findings, fix groups, incidents (their counts, names and priority recomputed from what they can see), components and their counts, search hits, reports, audit events about those objects, and exports. Routes for organisation data (users, teams, integrations, channels, routes, deliveries, jobs, secrets, enrollments, remediation plans and policies, ingest) answer 403. The database enforces this with row-level security, not only the API.
- **Roles from grants act per asset.** `GET /auth/me` returns `project_role`, the highest role from any grant. A change (`PATCH /assets/{id}`, relations, finding and incident actions) needs that role on each asset it touches; otherwise 403. An organisation-wide viewer with `engineer` on one project can act on that project's findings only.
- **Choosing a project.** Send `X-Stackurity-Project: <id>` (the dashboard does) or `?project_id=<id>` on any request; `0` or nothing means all projects. Project-scoped routes (the reading routes above, `GET /reports/evidence`, `GET /assets/{id}/sbom`, search, audit) then return only that project's assets and what hangs off them; other routes ignore it. A project the caller cannot see answers 404, a value that is not a number 400. The CLI sends the header for `--project` (or `STACKURITY_PROJECT`).
- **People and links.** Someone who assigns through a project role (their organisation role alone may not assign) can assign only to the people and teams of their projects (400 otherwise), and `GET /users/directory` gives them only those people. Grants are audited as object type `access_grant` and asset merges as `asset_merge`, which project-only members never see. Incidents shown to them carry no tracker `issues`, no `notified_priority`, and priority, SOS and escalation from their findings; `priority=`, `sos=` and `escalated=` filter on those.
- **Checks, ignore rules and requests** follow their assets. Ignoring an issue on every asset (`scope: everywhere`), approving such a request and ending such a rule need an organisation-wide `security` or `admin` role (403 otherwise). With `security` through a project grant, `GET /ignore-requests` lists the caller's own requests and those whose issues are all on assets where they hold it (`can_decide` is true), and they decide only those.
- **Tokens** of a member with project access only act as that member, never above their highest grant. Collector and host-bound agent tokens belong to the workspace and are not limited by projects.

## Conventions

- **Errors** look like this:

  ```json
  {"error": {"code": "invalid", "message": "validation failed", "details": ["observations[3].purl \"x\" is not a valid purl"]}}
  ```

- **Lists** return `{"items": [...], "total": N, "limit": L, "offset": O}`. Routes that page take `?limit=` (default 100, at most 500) and `?offset=`.
- **Limits and read-only organisations.** A request that would create an asset past the organisation's limit answers `402 asset_limit`, a new project past its limit `402 project_limit`. While an organisation is read-only, uploads, enrollment, integrations, checks and notifications answer `402 read_only`. See [asset-limits.md](asset-limits.md).
- **Editions.** Routes marked **licensed build** exist only in Stackurity Pro and Enterprise; in the Community build some answer `402` with the plan they need, and the others are not served. Routes marked **Stackurity Cloud** exist only on the hosted service. See [editions.md](editions.md).
- **Rate limits** answer `429`. Routes that need no sign-in are limited per address.

## Account

### `POST /auth/login`

**Who:** anyone

Signs in with `email` and `password` and starts a session (cookie). Limited per address and per account; 401 for a wrong email or password.

### `POST /auth/logout`

**Who:** any signed-in user

Ends the session.

### `GET /auth/me`

**Who:** any signed-in user or token

The caller: `user`, `role`, `workspace`, `workspaces`, `edition` and `features`, `access` (`organisation` or `projects`), `project_role`, `projects`, `default_project_id`, `read_only`, `report_mode` and `feedback_enabled`.

### `PUT /auth/default-project`

**Who:** any signed-in user

`{"project_id": N}` (0: all projects): the project the dashboard opens with. `GET /auth/me` returns it as `default_project_id`.

### `POST /auth/password`

**Who:** any signed-in user

Changes your own password (`current_password`, `new_password`). Your other sessions are signed out.

### `GET /auth/oidc/login`

**Who:** anyone · licensed build

Starts single sign-on with the configured OpenID Connect provider ([install.md](install.md#single-sign-on)).

### `GET /auth/oidc/callback`

**Who:** anyone · licensed build

Where the identity provider sends the browser back: signs the person in and starts a session.

### `POST /feedback`

**Who:** any signed-in user (10 an hour)

Sends feedback to the Stackurity team: `kind` (`bug`, `idea`, `question`), `message` (up to 5000 characters), optional `email` and `page`. 202 when delivered, 502 when the feedback service cannot be reached, 404 when feedback is turned off (`feedback_enabled: false`). See [network.md](network.md#feedback).

### `GET /tokens`

**Who:** any user

Your API tokens; admins see every token, including collector tokens.

### `POST /tokens`

**Who:** any user

Creates a token; the secret is returned once. A collector token can name a `project_id`: assets it creates are added to that project.

### `DELETE /tokens/{id}`

**Who:** any user (admins: any token)

Revokes a token.

### `GET /workspaces`

**Who:** any signed-in user

The organisations the caller belongs to, each with `workspace_id`, `name`, `slug`, `role` and `access`.

### `POST /workspaces/{id}/activate`

**Who:** a browser session

Switches the session to another of the caller's organisations and answers the caller as in that organisation. Tokens belong to one organisation and get 403. Audited as `workspace.enter`.

### `GET /slack/links`

**Who:** any signed-in user

The caller's linked Slack accounts in the current organisation (`team_id`, `team_name`, `slack_user_id`, `slack_user_name`, `created_at`, `last_used_at`).

### `DELETE /slack/links/{id}`

**Who:** any signed-in user

Unlinks one of the caller's Slack accounts (404 for anyone else's). Audited as `slack_link.delete`.

### `POST /slack/links/preview`

**Who:** a browser session

`{"token"}` from the link offered in Slack: the Slack account it would link, `linked_to_you`, `linked_to_other` and `signed_in_as`. 410 when the link was used, expired (15 minutes) or belongs to another organisation.

### `POST /slack/links/confirm`

**Who:** a browser session

`{"token"}`: links that Slack account to the caller (single use). 410 as above; 409 when it is linked to another account, which has to unlink it first. Audited as `slack_link.create`.

### `POST /signup`

**Who:** anyone · Stackurity Cloud

Starts a sign-up: email, name, organisation, password, challenge token (action `signup`) and `accept_terms`. Answers `202 check_email` whatever the address's state.

### `POST /signup/verify`

**Who:** anyone · Stackurity Cloud

Uses the emailed token once: creates the account and the organisation on its trial, and starts a session.

The assistants a person has connected (`/assistants`) and the OAuth consent page are under [AI assistants, OAuth and MCP](#ai-assistants-oauth-and-mcp).

## Setup

### `GET /meta`

**Who:** anyone

Version, whether first-time setup is required, and `features`: what this server supports that an older one would silently ignore. `upload_project` means `POST /ingest` and `POST /sbom/import` honour `project_id` (0.10); `stackurity` checks it before an upload with `--project`.

### `GET /openapi.json`

**Who:** anyone

This API as an OpenAPI 3.1 document.

### `POST /setup`

**Who:** the setup token

Creates the first admin (`setup_token` from the server log, `email`, `name`, `password`) and signs them in.

## Agents and uploads

### `POST /enroll`

**Who:** anyone (rate limited)

Exchanges a one-time enrollment code (`{"code", "hostname"}`) for a collector token and the agent settings chosen with it, including the code's `project_id`. Refusals do not say why. An optional `project_id` (`stackurity enroll --project`) is a check, not a choice: when the code adds hosts to another project or none, the answer is 403 and the code keeps its use.

### `GET /enrollments`

**Who:** admin

Enrollment codes.

### `POST /enrollments`

**Who:** admin

Creates an enrollment code, returned once: `label`, `environment`, `app_dirs`, `discover_apps`, `uses` (1–500, default 1), `ttl_hours` (1–720, default 24) and `project_id` (hosts enrolled with it, and the assets their agent reports, join that project when first created).

### `DELETE /enrollments/{id}`

**Who:** admin

Revokes an enrollment code.

### `GET /install/agent.sh`

**Who:** anyone · outside `/api/v1`

The agent installer script.

### `GET /download/agent/{platform}`

**Who:** anyone · outside `/api/v1`

The agent builds the installer downloads: `linux-amd64` and `linux-arm64`, each with a `.sha256`. They are bundled in the server image (`STACKURITY_AGENT_DIR`).

### `POST /ingest`

**Who:** collector token, engineer and above

Submits an [ObservationBatch](#observationbatch) (gzip accepted). `?project_id=` files the asset in a project; see [Uploads into a project](#uploads-into-a-project).

### `POST /sbom/import`

**Who:** collector token, engineer and above

Imports a CycloneDX or SPDX JSON document. Query: `asset_name`, `asset_kind`, `environment`, `project_id` (see [Uploads into a project](#uploads-into-a-project)). A collector token made for a project adds the assets it creates to it.

### `GET /collections/{id}/result`

**Who:** collector token (its own submissions), engineer and above

Whether a submitted collection has been evaluated (`status`: `pending`, `scoring`, `evaluated`, `failed`), then the asset's open findings and its count of `evaluation_gaps`. Used by `stackurity scan --fail-on`.

### `GET /agent/check`

**Who:** collector token, engineer and above

The agent's [check-again poll](#agent-poll) for the assets given as `asset_id` (repeated): `{"check": true, "poll_seconds": 45}` when someone asked for a fresh report.

### `GET /agent/actions`

**Who:** host-bound token

Approved remediation actions waiting for this host's agent (licensed build; always empty in Community). See [remediation.md](remediation.md).

### `POST /agent/actions/{id}/report`

**Who:** host-bound token · licensed build

The agent reports the progress and result of a remediation action.

## Inventory

### `GET /overview`

**Who:** viewer

Inventory, coverage and status counts, including assets by coverage state (`asset_coverage`) and components by row coverage (`component_coverage`).

### `GET /facets`

**Who:** viewer

Distinct environments, asset kinds and component types, for filters.

### `GET /search`

**Who:** viewer

Searches the current workspace for one query (`q`, `limit`). See [Search](#search).

### `GET /assets`

**Who:** viewer

Lists assets, paged. Query: `kind`, `environment`, `status`, `owner_team_id`, `q`, `reboot_required=true` (hosts running older code than is installed), `exposed=true|false` and `unfiled=true` (assets in no active project). Each asset has `projects`, the active projects it is in that the caller can see.

`exposed` is the exposure risk scoring uses: `internet_exposed` when set by hand, else what a collector observed (a Kubernetes workload's `exposure`, or for an image the workloads deployed as it).

### `GET /assets/{id}`

**Who:** viewer

One asset with its identifiers, and `agent_polled_at` (see [Check again](#check-again)).

### `PATCH /assets/{id}`

**Who:** engineer

Sets the name, environment, owner, criticality, exposure and tags.

### `DELETE /assets/{id}`

**Who:** admin

Deletes an asset and its history.

### `GET /assets/{id}/inventory`

**Who:** viewer

Components on the asset with evidence and [coverage](#inventory-coverage), paged. Query: `q`, `type`, `direct`, `include_removed`, `coverage`.

### `GET /assets/{id}/coverage-summary`

**Who:** viewer

How far the asset's findings can be trusted: its [coverage states](compatibility.md#coverage-states) with reasons, components by coverage, gap reasons and stale feeds.

### `GET /assets/{id}/coverage`

**Who:** viewer

The asset's coverage ledger, paged.

### `GET /assets/{id}/collections`

**Who:** viewer

The asset's last 50 collections.

### `GET /assets/{id}/relations`

**Who:** viewer

The asset's relations to other assets.

### `POST /assets/{id}/relations`

**Who:** engineer

Adds a relation: `runs_on`, `built_from`, `deployed_as`, `contains`, `depends_on` or `replica_of` (a standby, staging or DR copy that should run the same versions as the target).

### `DELETE /assets/{id}/relations`

**Who:** engineer

Removes a relation.

### `GET /assets/{id}/stack`

**Who:** viewer

Everything the asset relies on, followed through relations (up to three hops), with open findings grouped by layer (`web_server`, `os`, `runtime`, `data_store`, `libraries`, `declared`, `managed_service`, `platform`, `other`). For an application: its hosts, repository, images and dependencies; for a host, its applications; for a cluster, its workloads and images.

### `GET /assets/{id}/drift`

**Who:** viewer

Components whose versions differ from another asset (`with`, or the asset this one is a `replica_of`). Each item is `behind`, `ahead`, `differs`, `only_here` or `only_there`, compared by the component's ecosystem rules.

### `GET /assets/{id}/sbom`

**Who:** viewer

The asset's inventory as CycloneDX 1.6.

### `POST /assets/{id}/check`

**Who:** engineer

[Checks](#check-again) the whole asset again.

### `GET /components`

**Who:** viewer

The component explorer, paged. Query: `q`, `type`.

### `GET /components/{id}`

**Who:** viewer

One component.

### `GET /components/{id}/intel`

**Who:** viewer

Release data (latest stable, publish date, deprecation) and lifecycle cycles.

### `GET /components/{id}/upgrade`

**Who:** viewer

An [upgrade recommendation](#upgrade-recommendations) for each installed version with open findings (most findings first, at most 50; `total` counts all), with `version`, `distro` and `asset_count`.

### `GET /inventory`

**Who:** viewer

Where components are used, paged. Query: `component_id`, `asset_id`, `q`, `type`, `direct`, `include_removed`, `coverage`.

### `GET /coverage`

**Who:** viewer

The coverage ledger across assets, paged. Query: `asset_id`, `problems=true`.

### `GET /evaluation-gaps`

**Who:** viewer

Components that could not be evaluated, one entry per component and reason, with `coverage` (`unsupported` or `not_evaluated`); paged.

### `GET /conflicts`

**Who:** admin

Asset identity conflicts: assets that look like the same thing.

### `POST /conflicts/{id}/resolve`

**Who:** admin

Resolves a conflict by merging assets. The answer lists `projects_joined` and `grants_moved`, with a `notice`, when the kept asset joins the merged assets' projects or takes their access grants.

## Findings and fixes

### `GET /findings`

**Who:** viewer

Vulnerability and end-of-life findings, paged; SOS, priority, known-exploited and most severe first (`sort=asset` orders by asset name first). Resolved findings carry `resolution_kind` and `resolution_detail` ([Why a finding closed](#why-a-finding-closed)).

Query:

- `status` (`open`, `resolved`, `all`), `state` (`active`, `new`, `acknowledged`, `in_progress`, `suppressed`, `risk_accepted`, `regressed`), `kind`, `severity` and `priority` (comma-separated), `verification`, `known_exploited=true`, `sos=true`, `overdue=true`
- `asset_id`, `component_id`, `environment`, `key`, `q`, `fix_group` (a fix group id), `incident_id`
- `assignee_user`, `assignee_team`, `assignee=none` (unassigned)
- `new_within=N` (first seen in the last N days), `resolved_within=N` (resolved in the last N days, with `status=resolved`), `resolution_kind` (comma-separated)
- `second_check` (`agreed`, `disagreed`, `could_not_check`), `sort`, `limit`, `offset`

### `GET /findings/summary`

**Who:** viewer

Counts by severity, kind, verification, priority and state, plus SOS, overdue, unassigned, stale feeds, evaluation gaps, `regressed`, `until_fix`, `second_check_disagreed` and `resolved_7d`.

### `GET /findings/verify`

**Who:** viewer

What changed since `since` (RFC 3339 or `YYYY-MM-DD`; optional `asset_id`): findings `resolved` since then with their `cause`, `resolution_kind` and `counts_as_remediation`, the findings still open, those opened since, and each asset's last complete collection. `asset_rescanned_since` tells "fixed" from "not scanned again yet". Lists are capped at `limit` (default 100, at most 500) with a `total`; totals `remediated`, `closed_not_remediation` and `resolved_by_kind`.

### `GET /findings/{id}`

**Who:** viewer

One finding with every source advisory in its group, its `why` ([Findings](#findings)) and, while open, its `upgrade` recommendation.

### `GET /findings/{id}/explain`

**Who:** viewer

Why the finding matched (`why`) and why it has its priority: `risk` (score, each factor with its points, the policy version that produced it, the SLA and deadlines), the stored `evidence`, the matched `advisories`, the freshness of their `feeds`, and the asset's last complete `collection`. Includes `resolution_kind`, `resolution_detail` and `counts_as_remediation`. See [risk.md](risk.md).

### `GET /findings/{id}/upgrade`

**Who:** viewer

The [upgrade recommendation](#upgrade-recommendations) for the installed copy the finding is on, covering every open finding on it.

### `GET /findings/{id}/events`

**Who:** viewer

The finding's workflow history.

### `POST /findings/{id}/actions`

**Who:** engineer; security for `suppress`, `accept_risk`, `ignore`, `reopen`

Applies a [workflow action](#workflow) to the finding.

### `POST /findings/actions`

**Who:** as above

The same action on up to 500 findings (`ids`).

### `GET /fix-groups`

**Who:** viewer

Fixes (fix groups), most urgent first, paged. Query: `asset_id`, `kind`, `environment`, `q`, `bucket`, `group_by`. Package upgrades carry `target_version`, the version the title names ([Upgrade recommendations](#upgrade-recommendations)).

- `bucket`: `focus` (a fix exists, SOS or P1, on a production asset or one with no environment), `no_fix`, `old_kernels`, `non_production` or `lower_priority`. Every group is in exactly one, checked in that order.
- `group_by`: `fix` (the same change in several places is one entry with `places`, each with its group, asset, app directory and finding count) or `asset` (one entry per asset). The default is the workspace's setting (`GET /settings/fix-grouping`).

### `GET /fix-groups/summary`

**Who:** viewer

Groups and findings per kind, plus `focus` (focus groups, their findings and assets) and `hidden` (groups and findings per other bucket). Query: `asset_id`, `group_by` as for `GET /fix-groups`: grouped by fix, a fix needed in several places counts once.

### `GET /fix-groups/{id}`

**Who:** viewer

One fix group with its findings, paged.

### `POST /fix-groups/{id}/check`

**Who:** engineer

[Checks the fix again](#check-again): asks the asset's agent (or a server-side scan) for a fresh report. 201 with the new check, or 200 with the check already waiting.

### `POST /fix-groups/{id}/applied`

**Who:** engineer

"I applied this": the fix's active issues go to `in_progress` ("applied, waiting for a check") and a check is requested. Nothing is resolved by this call; returns `updated` and `check`.

### `GET /checks`

**Who:** viewer

Checks, newest first, paged. Query: `asset_id`, `fix_group`, `open=true` (not done yet).

### `GET /checks/{id}`

**Who:** viewer

One check.

### `GET /incidents`

**Who:** viewer

Incidents: findings grouped by issue and owner team, paged. Query: `status`, `kind`, `priority`, `sos=true`, `escalated=true`, `team_id`.

### `GET /incidents/{id}`

**Who:** viewer

An incident with its findings, tracker `issues`, and (for security and above) its deliveries.

### `POST /incidents/{id}/actions`

**Who:** as for findings

Applies a workflow action to every open finding in the incident.

### `POST /ignore-requests`

**Who:** viewer

Asks to ignore issues: `finding_ids` (up to 2,000 open findings) or `fix_group`, with `reason`, `scope`, `expiry`, `until`, `note` and `mitigation` as for the `ignore` action. Validated like an ignore; 201 with the request. See [Approval inbox](#approval-inbox).

### `GET /ignore-requests`

**Who:** viewer

The approval inbox, paged. `status`: `pending` (default), `approved`, `declined` or `all`. Security and admin users see every request, others their own; `can_decide` says which they may decide.

### `GET /ignore-requests/{id}`

**Who:** viewer (the requester, or security and admin users)

One request.

### `POST /ignore-requests/{id}/decision`

**Who:** security

`{"decision": "approve" | "decline", "note": "..."}`. Approval ignores the request's issues that are still open and active, as the decider; 409 when already decided.

### `GET /ignore-rules`

**Who:** viewer

[Ignore rules](#ignore-rules) in force (or all with `status=all`), with the open findings each ignores; paged.

### `DELETE /ignore-rules/{id}`

**Who:** security

Ends a rule: the open findings it ignores return to `new`.

### `GET /second-checks`

**Who:** viewer

The independent [second check](verification.md#second-check) of high-impact findings: open findings `agreed`, `disagreed` and `could_not_check`, `pending`, `logged_30d` and the 50 latest disagreements with their differences. A disagreement never changes a finding's verification, priority, SOS or alerts. `GET /findings?second_check=disagreed` lists the findings.

### `POST /evaluate`

**Who:** engineer

Queues a full re-evaluation of the workspace's inventory.

### `GET /risk-policy`

**Who:** viewer

Priority weights, thresholds, deadlines and SOS rules, with the policy `version` and `last_change` (who, when, versions, changed fields; null when never changed).

### `PUT /risk-policy`

**Who:** admin

Replaces the policy (fields left out take their defaults; unknown fields are rejected). Returns `version`, `previous_version` and the `changed` fields; audited as `risk_policy.update` with the policy before and after.

### `POST /risk-policy/preview`

**Who:** admin

Validates a proposed policy like `PUT` and returns its effect on open findings without saving: counts per priority and SOS `before` and `after`, what was raised or lowered, and a `sample` of up to 50 changed findings ([risk.md](risk.md#reproducibility-and-audit)).

### `GET /settings/fix-grouping`

**Who:** viewer

How fix lists show the same fix in several places: `fix_grouping` is `fix` (one entry per fix listing its places; the default) or `asset` (one entry per asset).

### `PUT /settings/fix-grouping`

**Who:** admin

Changes `fix_grouping`; audited as `settings.update`.

## Projects and people

### `GET /projects`

**Who:** viewer, or any grant

Projects the caller can see, with `asset_count` (members with project access only: theirs, each with their `role`). Organisation-wide callers also get `unfiled_assets`. `archived=true` (admins) includes archived projects.

### `GET /projects/{id}`

**Who:** viewer, or a grant on it

A project; for admins also its `grants`.

### `POST /projects`

**Who:** admin

`{"name", "description", "asset_ids"}`. `402 project_limit` at the organisation's project limit.

### `PATCH /projects/{id}`

**Who:** admin

`name`, `description`, `archived` (true archives: grants on it stop giving access and routes limited to it stop matching; false restores).

### `POST /projects/{id}/assets`

**Who:** admin

`{"asset_ids": [...]}` (1 to 5000): adds assets; returns `changed`.

### `DELETE /projects/{id}/assets`

**Who:** admin

The same body: removes assets; returns `changed`.

### `GET /access-grants`

**Who:** admin

Access grants with project, asset, person and team names. Query: `project_id`, `asset_id`, `user_id`, `team_id`.

### `POST /access-grants`

**Who:** admin

`{"project_id" or "asset_id", "user_id" or "team_id" or "email", "role"}`. With `email`, someone who is not a member joins with no organisation-wide role (an account is created with `password` when there is none; `account_created` says so). An existing grant for the same person or team and object has its role changed (200); a new one is 201.

### `PATCH /access-grants/{id}`

**Who:** admin

Changes a grant's `role`. Takes effect on the next request.

### `DELETE /access-grants/{id}`

**Who:** admin

Removes a grant.

### `GET /project-suggestions`

**Who:** admin

Groupings proposed from `runs_on`, `built_from` and `deployed_as` relations: unfiled assets related to a project's assets (`project_id`), or related assets all in no project (`suggested_name`). Nothing changes until someone adds the assets.

### `POST /project-suggestions/dismiss`

**Who:** admin

`{"key"}` hides a suggestion until its assets change.

### `GET /onboarding`

**Who:** admin

The [first-run flow](#onboarding): `state` (`new`, `skipped`, `done`), `show_flow`, `has_assets`, `project_id` and `project`, and `steps` (`project`, `asset`, `notifications`, `invite`, `assistant`), each read from what exists.

### `PUT /onboarding`

**Who:** admin

`{"state": "new" | "skipped" | "done", "project_id": N}`; audited as `onboarding.update`.

### `GET /onboarding/results`

**Who:** viewer

The waiting screen's poll: assets created since `since` (RFC 3339; default the last 24 hours) in the chosen project, newest first, at most 20. Each has `packages`, `issues`, `checked` (its first complete report is evaluated) and `fixes_now`.

### `GET /invitations`

**Who:** admin

[Invitations](#invitations): open ones, and the others of the last 30 days, with `status` (`pending`, `accepted`, `revoked`, `expired`). Never the link. Query: `project_id`.

### `POST /invitations`

**Who:** admin (30 an hour per organisation)

`{"email", "name", "role", "project_id"}` (`project_id` 0: an organisation-wide role). 201 with `invitation` and `emailed`; when the email was not sent, `link` (shown once) and `email_problem`. A member gets the project role at once (`granted`, `grant`); an organisation-wide invitation for a member is 409.

### `DELETE /invitations/{id}`

**Who:** admin

Withdraws a pending invitation: its link stops working.

### `POST /invitations/preview`

**Who:** anyone (rate limited)

`{"token"}`: what the link is for (`workspace`, `project`, `role`, `email`, `invited_by`, `expires_at`, `account_exists`) and `signed_in_as`. 410 for any link that does not work, without saying why.

### `POST /invitations/accept`

**Who:** anyone, or the invitee's session (rate limited)

`{"token", "name", "password"}`: joins the invitation's organisation with its role and answers `workspace_id`, `project_id`, `role`, `account_created` and `joined`. 410 when the link does not work; 409 `sign_in_required` or `wrong_account`.

### `GET /users`

**Who:** admin

Members of the organisation. Each has `role` (`none`: a member with no organisation-wide role, access through projects only) and `access` (`organisation` or `projects`).

### `POST /users`

**Who:** admin

Adds a user to the organisation with a role (`none` allowed). Off on Stackurity Cloud, where people join by invitation.

### `PATCH /users/{id}`

**Who:** admin

Changes a member's role, name or status.

### `DELETE /users/{id}`

**Who:** admin

Removes a member from the organisation; their account and other organisations are untouched. The organisation must keep an active admin. Audited as `user.remove`.

### `GET /users/directory`

**Who:** engineer

Active users (id, email, name) for assignment. Members with project access only get themselves and the people granted one of their projects.

### `GET /teams`

**Who:** viewer

Teams.

### `POST /teams`

**Who:** admin

Creates a team with its members (who must belong to the organisation).

### `PATCH /teams/{id}`

**Who:** admin

Changes a team and its members.

### `DELETE /teams/{id}`

**Who:** admin

Deletes a team.

## Notifications

How incidents become messages, the route `events` and the webhook format are in [Incidents and notifications](#incidents-and-notifications).

### `GET /notification-options`

**Who:** security

What the server offers: `slack_app` (Add to Slack), `platform_email` (`enabled`; when enabled `from`, `max_recipients` and `quota` with `per_minute`, `per_hour`, `per_day`), `secrets` (stored secrets work) and `base_url`.

### `GET /channels`

**Who:** security

Notification channels.

### `POST /channels`

**Who:** admin

Creates a channel: email, email sent by Stackurity (`stackurity_email`, hosted only), Slack, Teams, webhook or Jira. Slack channels made with Add to Slack come from `POST /integrations/slack/oauth` instead.

### `PATCH /channels/{id}`

**Who:** admin

Changes a channel. Add to Slack channels (`config.slack_app`) can only be renamed and switched on or off.

### `DELETE /channels/{id}`

**Who:** admin

Deletes a channel and takes it out of every route's `event_channels`. Deleting the last Add to Slack channel of a Slack workspace removes the app from it.

### `POST /channels/{id}/test`

**Who:** admin

Sends a test message; for Jira, checks access without creating an issue.

### `GET /routes`

**Who:** security

Notification routes.

### `POST /routes`

**Who:** admin

Creates a route: which incidents go to which channel, and what is sent. Fields include `channel_id`, `events`, `event_channels` (Slack only: some events to other Slack channels), `min_priority`, `new_min_priority` (the threshold of `new_issues`), `project_ids`, summary time and day, quiet hours and `max_per_hour`. `mode` is still accepted; see [Incidents and notifications](#incidents-and-notifications).

### `PUT /routes/{id}`

**Who:** admin

Replaces a route. Without `events`, the route keeps its events; `event_channels` and `new_min_priority` keep their values unless sent.

### `DELETE /routes/{id}`

**Who:** admin

Deletes a route.

### `GET /deliveries`

**Who:** security

The delivery log, paged. Query: `status`, `incident_id`, `channel_id`. Each delivery has `held_by`: `""`, `hourly_limit` or `email_quota`.

### `POST /deliveries/{id}/retry`

**Who:** admin

Retries a failed or held delivery.

### `GET /email-recipients`

**Who:** security

Addresses of `stackurity_email` channels that are not members, with `status` `pending` (not confirmed yet) or `confirmed`.

### `POST /email-recipients/resend`

**Who:** admin

`{"email"}`: a new confirmation link to a pending address. 202; 429 `too_soon` within 10 minutes of the last; 404 for an unknown or confirmed address.

### `POST /email-recipients/confirm`

**Who:** anyone (rate limited)

`{"token"}` from the link `/email/confirm#emc_...` (7 days, once): answers `email` and `organisation`; 410 `link_invalid`.

### `POST /email-recipients/block`

**Who:** anyone (rate limited)

`{"token"}` from a confirmation email's "Never email me again" link (`/email/block#emc_...`): the address is blocked for every organisation on the server and its pending requests removed. Answers `email`; 410 `link_invalid`.

### `POST /email/unsubscribe`

**Who:** anyone (rate limited)

`{"token"}` from an email's "Stop these emails" link (`/email/unsubscribe#...`, signed for one organisation and address): the address leaves that organisation's `stackurity_email` channels. Answers `email` and `organisation`; 410 `link_invalid`.

### `POST /email/unsubscribe/one-click`

**Who:** anyone (rate limited) · outside `/api/v1`

One-click unsubscribe (RFC 8058) from the `List-Unsubscribe` header, with the token as `?t=`. Same effect and answers as `POST /api/v1/email/unsubscribe`.

### `POST /email/block/one-click`

**Who:** anyone (rate limited) · outside `/api/v1`

One-click "never email me again" with the token as `?t=`. Same effect and answers as `POST /api/v1/email-recipients/block`.

## Integrations

### `GET /integrations`

**Who:** engineer

Integrations (repository and image scans, plugins).

### `POST /integrations`

**Who:** admin

Creates an integration.

### `PATCH /integrations/{id}`

**Who:** admin

Changes an integration.

### `DELETE /integrations/{id}`

**Who:** admin

Deletes an integration.

### `POST /integrations/{id}/run`

**Who:** engineer

Runs an integration now; follow it with `GET /jobs/{id}`.

### `GET /jobs`

**Who:** admin

The background job queue (the latest 200). Query: `state`.

### `GET /jobs/{id}`

**Who:** engineer

Status of one job, for example after *Run now*.

### `GET /plugins`

**Who:** admin

Installed plugins with their declared permissions, credentials and network access ([plugins.md](plugins.md)).

### `GET /secrets`

**Who:** admin

Names of the organisation's stored secrets (never values), and `enabled`: whether the server can store secrets. Channels and integrations refer to them as `secret:NAME`.

### `PUT /secrets/{name}`

**Who:** admin

`{"value"}` (up to 16 KiB): stores or replaces a secret, encrypted. Names use letters, digits, `.`, `-` and `_` (up to 64). 409 when the server has no `STACKURITY_SECRET_KEY`. Audited as `secret.put`.

### `DELETE /secrets/{name}`

**Who:** admin

Deletes a stored secret. Audited as `secret.delete`.

### `POST /integrations/slack/install`

**Who:** admin

Starts Add to Slack: `{"return_to"}` (a dashboard path); answers `url`, Slack's consent page. 404 `not_configured` without the Slack app ([slack-app.md](slack-app.md)).

### `GET /integrations/slack/install`

**Who:** anyone · outside `/api/v1`

The Slack app's Direct install URL ([slack-app.md](slack-app.md#installs-started-from-slack)). Signed out: 302 to Slack's consent page without a state, as Slack requires; Slack then returns to `/integrations/slack/oauth/callback` with a code that is never exchanged, and the page there starts a proper install. Signed in: the dashboard page that picks the organisation (one where the person is an admin) and calls `POST /integrations/slack/install`.

### `POST /integrations/slack/oauth`

**Who:** admin

Finishes Add to Slack with `{"code", "state"}` from Slack's redirect to `/integrations/slack/oauth/callback`: 201 with `channel`, `return_to`, `team_name` and `slack_channel`. 400 `slack_state` for a state that is missing (an install started from Slack's side), unknown, used, expired (10 minutes) or someone else's, before Slack is called; 502 `slack_refused`.

### `POST /integrations/slack/events`

**Who:** Slack (the app's signing secret)

The Slack app's Event Subscriptions URL: `url_verification`, and `app_uninstalled` or `tokens_revoked`, which switch that Slack workspace's app channels off in every organisation and delete their webhooks and tokens.

### `POST /integrations/slack/actions`

**Who:** Slack (a channel's signing secret)

Slack's interactivity Request URL: the form-encoded `payload` with `X-Slack-Request-Timestamp` and `X-Slack-Signature`. 200 once verified (the answer goes to Slack's `response_url`); 401 for a request that cannot be verified, is older than 5 minutes or was already received. See [Acting from Slack](#acting-from-slack).

## Intelligence

### `GET /advisories/{key}`

**Who:** viewer

The advisories in a group, by group key or CVE id.

### `GET /feeds`

**Who:** viewer

Intelligence feeds and their freshness.

### `POST /feeds/{name}/refresh`

**Who:** engineer

Queues a manual refresh of a feed.

### `PATCH /feeds/{name}`

**Who:** instance admin

Enables or disables a feed. Feeds are shared by every workspace.

### `GET /packs`

**Who:** any signed-in user

The enabled [stack packs](packs.md) (`installed`) and, in a workspace, `suggestions`: packs that would read files its repositories hold. 404 when packs are off on the server.

### `GET /packs/{id}/archive`

**Who:** any signed-in user

Downloads an enabled pack, for clients that run it themselves (`stackurity scan`, the agent); they check its signature first.

## Reports

### `GET /reports/evidence`

**Who:** viewer · licensed build (402 in Community)

Patch-management evidence for a period (`from`, `to`: dates, `to` inclusive; default the last 30 days, at most a year). See [Evidence report](#evidence-report).

### `GET /reports/outcomes`

**Who:** viewer

[Remediation outcomes](#remediation-outcomes) over the last `days` (1 to 365, default 90).

### `GET /audit`

**Who:** viewer

Audit events, paged. Query: `object_type`, `object_id`.

### `GET /usage`

**Who:** viewer (organisation-wide)

[Monitored assets](asset-limits.md) against the organisation's limits: `monitored`, `limit` (null: none), `at_limit`, `by_kind`, `stale`, `workloads` (not counted), `refused` and `refused_recently`; `projects`, `project_limit`, `projects_at_limit`; `read_only` (`since`, `reason`; null when not) and `report_mode` (`full` or `trial`).

## Automatic fixes

Automatic fixing is in the licensed build ([remediation.md](remediation.md)). In the Community build `GET /agent/actions` and `GET /assets/{id}/remediation` answer an empty list; the policy list, plan list, plan decisions, new policies, the remediation token and Renovate rules answer 402; the other routes are not served.

### `GET /remediation/policies`

**Who:** security · licensed build (402 in Community)

Remediation policies.

### `POST /remediation/policies`

**Who:** admin · licensed build

Creates a policy.

### `PUT /remediation/policies/{id}`

**Who:** admin · licensed build

Replaces a policy.

### `DELETE /remediation/policies/{id}`

**Who:** admin · licensed build

Deletes a policy.

### `POST /remediation/policies/preview`

**Who:** admin · licensed build

Which fixable packages and assets a proposed policy (optionally replacing policy `?id=`) would authorise or stop authorising, without saving ([remediation.md](remediation.md#previewing-a-policy-change)).

### `GET /remediation/plans`

**Who:** viewer · licensed build (402 in Community)

Plans and their per-asset actions. Query: `status`.

### `GET /remediation/plans/{id}`

**Who:** viewer · licensed build

One plan with its actions.

### `POST /remediation/plans/{id}/decision`

**Who:** security (admin for a major upgrade) · licensed build

`{"decision": "approve" | "reject" | "cancel", "note": "..."}`.

### `GET /assets/{id}/remediation`

**Who:** viewer

Remediation actions for an asset (always empty in Community).

### `POST /assets/{id}/remediation-token`

**Who:** admin · licensed build

A collector token bound to this host, which remediation requires.

### `GET /remediation/renovate.json`

**Who:** collector token, engineer and above · licensed build

Renovate rules for the approved plans of a repository. Query: `repository`, `mode=exclusive`.

## Instance administration

### `GET /admin/workspaces`

**Who:** instance admin

Workspaces with `member_count`, `asset_count`, `monitored`, `asset_limit` (null: none), `projects`, `project_limit`, `read_only_at`, `read_only_reason` and `report_mode`.

### `POST /admin/workspaces`

**Who:** instance admin

Creates a workspace (`name`, `slug`) and its first admin (`admin_email`, `admin_name`, `admin_password`). 201 with `workspace` and `admin`. See [install.md](install.md#workspaces).

### `PATCH /admin/workspaces/{id}`

**Who:** instance admin

Takes `name`, `disabled`, `plan`, `asset_limit` and `project_limit` (`-1` removes a limit), `read_only` with `read_only_reason`, and `report_mode` (`full` or `trial`). See [asset-limits.md](asset-limits.md).

### `GET /admin/health`

**Who:** instance admin

Platform health across workspaces: `status` (`ok`, `warning`, `critical`), `problems` (each with `last_success`, `last_error`, `scope`, `next_step` and `docs`), background `tasks`, jobs, notification `deliveries`, `failing_channels` and `email_quota`. See [install.md](install.md#health).

### `GET /updates`

**Who:** instance admin

Whether a newer release exists: `enabled`, `current`, `latest`, `update_available`, `security`, `checked_at` and the newer `releases` with their notes. It reads the stored result of the periodic release check and contacts nothing itself ([network.md](network.md#update-check)).

### `GET /admin/license`

**Who:** instance admin

The installation's licence `status`, `active_assets`, and `managed_by_env` (set by `STACKURITY_LICENSE`). See [install.md](install.md#editions-and-licences).

### `PUT /admin/license`

**Who:** instance admin

`{"key"}`: installs a licence key. 400 for a key that is not valid; 409 when the licence is set by `STACKURITY_LICENSE`. Audited as `license.install`.

### `DELETE /admin/license`

**Who:** instance admin

Removes the licence key (409 when set by `STACKURITY_LICENSE`). Audited as `license.remove`.

### `GET /admin/packs`

**Who:** instance admin

[Stack packs](packs.md): `installed`, the built-in `catalog`, and `suggestions` from the unsupported files across workspaces.

### `POST /admin/packs/install`

**Who:** instance admin

`{"id"}`: installs a pack from the built-in catalogue. Answers `id`, `version`, `trust` and `rescans_queued`.

### `POST /admin/packs/upload`

**Who:** instance admin

Installs a pack file sent as the request body (at most 32 MiB). Its signature must be trusted ([packs.md](packs.md#signatures)); 400 `invalid` or `rejected` otherwise.

### `PATCH /admin/packs/{id}`

**Who:** instance admin

`{"enabled": true | false}`.

### `POST /admin/packs/{id}/rollback`

**Who:** instance admin

Reinstalls the pack's previous version.

### `DELETE /admin/packs/{id}`

**Who:** instance admin

Removes a pack: its files show as unsupported again from the next scan.

### `GET /billing`

**Who:** admin · Stackurity Cloud

The organisation's plan: status (`trial`, `trial_ended`, `awaiting_payment`, `active`, `past_due`, `halted`, `cancelling`, `cancelled`), plans, limits, read-only and deletion dates, `billing_enabled` and `contact_url`. `upgrade` (or null) is an upgrade that applies now and is billed from the next invoice: `from_plan`, `charge` (the amount for the rest of the period and when it is billed) and `message`.

### `POST /billing/subscribe`

**Who:** admin, a browser session · Stackurity Cloud

`plan_id`, `extra_assets`, `country` (asked once; decides the currency), `replace`. Answers `billing`, `payment_url` (a page to pay on, or null) and `message` (what happened, for the admin; empty for an ordinary change). An upgrade the payment provider applies only at the end of the period (a card mandate it changes then) applies now: `message` and `billing.upgrade` say what is added to the next invoice. 409 `replace_required` when the payment provider cannot change the subscription's plan (UPI, e-mandate, an Indian card): asked again with `"replace": true`, it is cancelled and replaced by the bigger plan, paid on `payment_url`. 503 `billing_off` while billing is off; 409 while a payment is being confirmed.

### `POST /billing/cancel`

**Who:** admin, a browser session · Stackurity Cloud

Cancels the plan at the end of the period; the organisation then becomes read-only.

### `GET /billing/invoices`

**Who:** admin · Stackurity Cloud

Invoices of the organisation's subscriptions.

### `PUT /admin/trials/{id}`

**Who:** instance admin · Stackurity Cloud

`trial_ends_at` (RFC 3339, in the future and within a year): extends one organisation's trial at once. Audited as `cloud.trial_extended`.

### `GET /billing/pay/{id}`

**Who:** admin, a browser session · Stackurity Cloud · outside `/api/v1`

The payment page for a subscription.

### `POST /billing/pay/{id}`

**Who:** admin, a browser session · Stackurity Cloud · outside `/api/v1`

The payment provider's answer from the payment page. A valid signature sends the admin to Plan and billing, which shows the payment as being confirmed until it is.

### `POST /webhooks/razorpay`

**Who:** Razorpay (its signature) · Stackurity Cloud · outside `/api/v1`

Payment events from Razorpay.

## AI assistants, OAuth and MCP

Assistants connect to `/mcp` and sign in with OAuth 2.1 (authorization code with PKCE). [ai-assistants.md](ai-assistants.md#how-sign-in-works) describes the flow, its limits and what is audited. Everything here except the consent and connection routes under `/api/v1` is at the server root, and all of it needs `STACKURITY_BASE_URL` (404 without it).

### `GET /.well-known/oauth-protected-resource/mcp`

**Who:** anyone

Protected resource metadata (RFC 9728) for `/mcp`. A request to `/mcp` without a token gets 401 with `WWW-Authenticate` pointing here.

### `GET /.well-known/oauth-protected-resource`

**Who:** anyone

The same metadata, at the root location.

### `GET /.well-known/oauth-authorization-server`

**Who:** anyone

Authorization server metadata (RFC 8414): the registration, authorization, token and revocation endpoints and what they support.

### `POST /oauth/register`

**Who:** anyone (rate limited)

Dynamic client registration (RFC 7591). Assistants can instead use an HTTPS client id that points to their client metadata document.

### `POST /oauth/token`

**Who:** a registered client

Exchanges an authorization code (with its PKCE verifier) or a refresh token for a one-hour access token (`stka_...`) and a new refresh token.

### `POST /oauth/revoke`

**Who:** a registered client

Revokes a token (RFC 7009), ending the connection.

### `POST /mcp`

**Who:** an assistant's access token, or an API token

The MCP endpoint (Streamable HTTP, stateless): one JSON answer per request. Honours `X-Stackurity-Project`.

### `GET /mcp`

**Who:** anyone

405: the endpoint keeps no session and opens no event stream.

### `DELETE /mcp`

**Who:** anyone

405, for the same reason.

### `POST /api/v1/oauth/authorize/preview`

**Who:** a browser session

The consent page's view of an authorization request (`response_type`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`, `scope`, `resource`): the `client`, `signed_in_as`, the active `workspace`, and the `projects` and `roles` the person may give. 400 with `error.redirect` when the request is wrong, or without it when the client or redirect URI cannot be trusted.

### `POST /api/v1/oauth/authorize`

**Who:** a browser session

The same parameters with `decision` (`allow` or `deny`), `workspace_id` (409 if the session switched organisation), `project_id` (0: the whole organisation), `role` and `allow_changes` (default false). Answers `redirect`: the client's redirect URI with a single-use `code` (2 minutes) or `error=access_denied`, plus `state` and `iss`. A role above the caller's is 403. Audited as `assistant.authorize`.

### `GET /api/v1/assistants`

**Who:** a browser session

The caller's connected assistants in every organisation (`client_name`, `redirect_host`, `workspace_name`, `project_name`, `role`, `allow_changes`, `created_at`, `last_used_at`), and `mcp_url`: the address to add in an assistant (empty while `/mcp` is off).

### `PATCH /api/v1/assistants/{id}`

**Who:** a browser session

`{"allow_changes": true | false}` for one of the caller's assistants (404 for anyone else's). Audited as `assistant.update`.

### `DELETE /api/v1/assistants/{id}`

**Who:** a browser session

Disconnects one of the caller's assistants: its tokens stop working at once (404 for anyone else's). Audited as `assistant.revoke`.

## Health and discovery

These are at the server root, outside `/api/v1`, and need no sign-in. See [install.md](install.md#health).

### `GET /healthz`

**Who:** anyone

Liveness: `{"status": "ok"}` while the process serves requests.

### `GET /readyz`

**Who:** anyone

Readiness: 200 `{"status": "ready"}`, or 503 `database_unavailable` (the database does not answer within 2 seconds) or `schema_newer` (a newer version migrated the database; see [install.md](install.md#upgrading)).

### `GET /.well-known/openai-apps-challenge`

**Who:** anyone

The token from `STACKURITY_OPENAI_APPS_CHALLENGE`, as text, for OpenAI's domain check when Stackurity is submitted as a ChatGPT app; 404 when unset.

## Inventory coverage

Inventory rows carry `coverage`, whether vulnerability intelligence covered that row: `evaluated`, `stale_intelligence` (evaluated against a feed that is stale or failing), `not_evaluated` or `unsupported` (with `coverage_reason`), or `awaiting` (not evaluated yet). `coverage_feed` names the feed used and `evaluated_at` when. The `coverage` filter takes one of these or `gaps` (`not_evaluated` and `unsupported`).

An evaluated row can carry a `coverage_reason` too, saying how it is reported: kernel headers ("not running code") and the other packages of a kernel version, whose findings are on the kernel image ([compatibility.md](compatibility.md#kernels)).

`lifecycle_note` is set on a distribution package whose upstream release is end of life: `status` is `distribution_supported` (no finding: the distribution release still provides security updates), `distribution_ended` (the release itself is end of life) `third_party_build` (the finding stands) or `follows_upstream` (the package's maintainer stops fixing it on the upstream date, as Red Hat and Microsoft do for .NET; the finding stands), with `text`, `subject`, `upstream_eol`, `distribution` and `distribution_eol` ([compatibility.md](compatibility.md#lifecycle-of-distribution-packages)).

## Evidence report

`GET /reports/evidence` (licensed build) covers a period:

- assets and their collection status, hosts needing a reboot, and evaluation gaps;
- open findings by severity, priority and evidence state (`open.by_evidence`), and overdue findings;
- findings remediated in the period (upgraded, fixed or removed), with the share resolved within their deadline and the median days from first detection to resolution; findings closed without remediation (advisory withdrawn or changed) are counted apart;
- every active exception with its reason, mitigation, expiry and `verification`;
- drift for each `replica_of` pair.

In trial report mode every report and export carries a watermark ([asset-limits.md](asset-limits.md#trial-reports)).

## Uploads into a project

`POST /ingest` and `POST /sbom/import` take `?project_id=` (0.10; `/sbom/import` took it from admins since 0.9). It is what `stackurity scan`, `stackurity agent` and `stackurity sbom import` send for `--project`.

- An organisation **admin** (a session or an admin's token) files the uploaded asset in the project, whether the upload created it or not. The addition is audited as `project.assets_add`.
- A **collector token made for a project** (`POST /tokens` with `project_id`, or an enrollment code with one) may name that project, which it fills anyway with the assets it creates. It never moves an asset that already existed. Naming any other project is 403.
- **Anyone else** (engineers and security, collector tokens without a project) gets 403 for `project_id`: filing assets in projects is for admins. Members with project access only cannot upload at all. `X-Stackurity-Project` alone is ignored for them, so a dashboard upload with a project chosen is not refused.
- The project must exist, be active and belong to the caller's workspace (404 otherwise); a value that is not a number is 400. A refused upload stores nothing.
- The answer adds `project_id` and `in_project` (whether the asset is in the project now). A server before 0.10 ignores `project_id` on `/ingest` and answers without these fields; `GET /meta` lists `upload_project` in `features` so clients can check first.

## Onboarding

A new organisation's admins see the first-run flow while `GET /onboarding` says `show_flow`: the state is `new` and there are no assets. Organisations with assets never see it (migration `0033` marks them `done`). Skipping sets `skipped`: the dashboard then shows a checklist on Home until every step is done or someone hides it (`done`). The steps are read from data, so doing them elsewhere counts: an active project; an asset (in the flow's project, when one is chosen); an enabled route (for that project, or for every asset); an invitation not withdrawn, or a second member.

Assets added through the flow land in its project: the install command's enrollment code, the CI token and the SBOM upload all carry `project_id`.

## Invitations

An invitation lets someone join the organisation with a role on one project (or, with no project, an organisation-wide role). The link is `https://<server>/invite#<token>`: the token is in the fragment, which browsers do not send to servers or in `Referer`, and travels to the API only in request bodies.

- **Tokens** are 32 random bytes, stored only as their SHA-256, single use, valid for 7 days, and can be withdrawn. Inviting the same person to the same project again withdraws the open one.
- **Rate limits**: following links (preview and accept together) 10 a minute per address; sending invitations 30 an hour per organisation.
- **Accepting** takes the organisation, project and role from the stored invitation only; the request has no field that could change them (unknown fields are refused). An account with the invitation's email must be signed in, as itself (409 otherwise); a new account is created with the name and password given (at least 12 characters). A person who is not yet a member joins with project access only (or with the invitation's organisation-wide role); a member's organisation-wide role is never changed, and a higher grant they already hold on the project is kept. A disabled account, an archived project or a disabled organisation make the link invalid. API tokens cannot accept.
- **Email**: the link goes through the organisation's first enabled email channel. Without one, or when sending fails, `POST /invitations` returns the link once, for the admin to send.
- **Audit**: `invitation.create`, `invitation.revoke`, `invitation.accept` (with `user.create`, `access.grant` and `auth.login` for a new account) in the organisation's audit log.

## Search

`GET /search?q=lodash@4.17.20&limit=10` looks one query up everywhere at once and returns the matches grouped by type. `q` is trimmed and must be 2 to 200 characters; `%`, `_` and `\` match themselves. `limit` (default 10, max 50) applies to each group, and `more` says which groups had more matches.

```json
{"query": "...", "vulnerabilities": [...], "findings": [...], "assets": [...], "components": [...], "teams": [...], "members": [...],
 "more": {"vulnerabilities": false, "findings": false, "assets": true, "components": false, "teams": false, "members": false}}
```

- **vulnerabilities**: when the query looks like an id (one word with a digit and a `-` or `:`), advisories whose id, alias or group is the query, in any letter case (CVE, GHSA, DSA, USN, RHSA, ALAS and other OSV ids), and finding keys that contain it. Each result is a finding key with the workspace's open and resolved findings, the number of assets with an open finding, a sample of `assets` and `components`, and the public `advisory` when one is known. An advisory that affects nothing in the workspace is returned with `kind: ""` and zero counts.
- **findings**: open findings whose title contains the query (3 characters or more), one result per finding key and title, with the number of open findings, the assets they are on and a sample of those `assets`. Keys already returned under `vulnerabilities` are left out.
- **components**: packages currently installed, matched on name or `namespace/name`. A version can be given as `name@version`, `name version` or a purl (`pkg:npm/lodash@4.17.20`, which also filters by type and namespace); `version_assets` and the sample `assets` then cover that version, where `3.0.2` also matches distro builds such as `3.0.2-0ubuntu1.10`. Maven coordinates (`group:artifact`) and npm scopes (`@scope/name`) work as names.
- **assets**: by name, any identifier (machine id, hostname, repository URL, image reference, ARN, SBOM serial) or the `digest` and `image` attributes. `match_scheme` and `match_value` say which identifier matched.
- **teams**: by name or email, with the assets they own and those assets' open findings.
- **members**: for engineers and above (who can already read the user directory; empty for viewers), members of the current workspace by name or email, with their `role` in this workspace, whether the account is `disabled`, and `open_assigned`, the open findings assigned to them here. Accounts that are not members of the workspace are never returned.

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

- `relations` (optional) links the asset to others by identifier: `[{"kind": "runs_on", "to": [{"scheme": "machine-id", "value": "..."}]}]`. Kinds are `runs_on`, `built_from` and `deployed_as` (a Kubernetes workload to the image it runs). Targets the server does not know yet are skipped. When present, the list replaces the relations this collector reported before; relations added by hand are kept.
- An application on a host is identified as `{"scheme": "app-path", "value": "/srv/shop"}`, its only identifier, with a `runs_on` relation to the host. The server scopes the path to that host, which must already exist. A host-bound token may only report applications on its own host, and plugins cannot use this scheme.
- `asset.kind` is `host`, `repository`, `image`, `application`, `managed_service`, `sbom`, `cluster` or `workload`.
- An asset attribute `exposure` of `external` or `internal` (set on Kubernetes workloads) is used as the asset's internet exposure for risk scoring unless an operator set it by hand. An image takes the exposure of the workloads deployed as it.
- `complete: true` tells the server that this batch is the collector's whole view of the asset. Components missing from it are marked removed, and history is kept. Partial batches never remove anything.
- `coverage[].status` is one of `checked`, `skipped`, `failed`, `unsupported` or `partial`.
- Limits: 200,000 observations, 64 MiB on the wire, 256 MiB after decompression.

Schema changes follow semantic versioning on `schema_version`. A breaking change gets a new version, and the server accepts the previous version for at least one minor release.

## Findings

A finding is one issue on one inventory row:

- `kind` is `vulnerability` or `end_of_life`.
- `key` is the deduplication key. For vulnerabilities it is the lowest CVE among the advisory's id and aliases, otherwise the advisory id. For lifecycle findings it is `product:cycle`. GHSA, OSV and distro advisories for the same CVE become one finding, and `sources` lists all of them.
- `verification` says how much the finding can be trusted: `confirmed`, `needs_validation`, `stale` or `rejected`, defined in [verification.md, "Evidence states"](verification.md#evidence-states). A confirmed finding is a confirmed advisory match, not a confirmed exploit.
- `GET /findings/{id}` and `GET /findings/{id}/explain` include `why`: one `sentence` saying why it matched (installed version and where it was read, the advisory range and version rules, the source and its last refresh, the fix), with the evidence state, `missing_information` and the independent `second_check`. See [verification.md, "Why it matched"](verification.md#why-it-matched).
- `fixed_version` is the highest "first fixed" version across the matching sources, so every source agrees the target is fixed. It is empty when no source lists a fix.
- `evidence` records the matched ranges, the OSV package and ecosystem, the comparator used, the feed and its last successful sync, and whether the CVE is in CISA KEV.
- The finding page shows this as **How this was decided**: each matched advisory (linked to osv.dev) with its feed, the advisory ecosystem and the affected range that matched, the installed version and ecosystem, and the version rules used (`comparator`: `debian` is Debian version rules, `rpm` RPM epoch:version-release, `apk` Alpine, `semver` SemVer, `pep440`, `rubygems`, `maven`, `nuget`, `composer`, `generic`), plus the evidence state with a one-line reason. The evidence state is the `verification`, except that a confirmed finding evaluated while its feed was stale (`evidence.feed_stale`) is shown as `stale_intelligence` (confirmed version, stale advisory data). `GET /reports/outcomes` counts open findings by evidence state in `open.by_evidence`; the evidence report (Pro) does the same in `open.by_evidence` and lists each exception's `verification`.

Findings resolve automatically when the component is upgraded or removed, or when an advisory is withdrawn. If the issue comes back, the finding reopens. Both are recorded in the finding's history (`GET /findings/{id}/events`) as `resolved` (the note is the resolution) and `reopened` (with the earlier resolution in `detail`), by actor `matcher`.

An issue that was fixed by an upgrade or a removal and comes back on the same asset (the same component and advisory, on the same or another inventory row) is **regressed**: `regressed_at` is set, the history gets a `regressed` event, work that was in progress goes back to `new`, and the issue is urgent in notifications whatever its priority. Two cases are not regressions: an upgrade that leaves the component vulnerable (the old and new versions overlap) and an issue closed only because the intelligence changed (`resolution_kind` `advisory_withdrawn` or `advisory_changed`), which reopens as before.

### Why a finding closed

A resolved finding has a `resolution` sentence and a machine-readable `resolution_kind`, with the facts in `resolution_detail`:

| `resolution_kind` | When | Remediation? |
| --- | --- | --- |
| `remediated` | The installed version changed ("upgraded to V") | yes |
| `removed` | A complete inventory no longer lists the component ("component no longer installed") | yes |
| `superseded` | Upgraded, but the new version is still affected: the issue continues as finding `resolution_detail.successor` | no |
| `advisory_withdrawn` | Every advisory behind it was withdrawn by its source (`source`, `feed`, `withdrawn_at`) | no |
| `advisory_changed` | The advisory or lifecycle data no longer lists the installed version, which did not change | no |
| `not_evaluated` | The row could no longer be evaluated (its feed was disabled, or the version could not be compared) | no |
| `other` | A resolution recorded before 0.13 that could not be classified | no |

The `resolution` sentence gives the facts, for example "fixed by remediation plan #N (upgraded to V)", "advisory withdrawn by Ubuntu on 2026-10-27" or "advisory updated: UBUNTU-CVE-2026-2 no longer lists mysql-8.0 8.0.42". Reports count only `remediated` and `removed` as remediation. `GET /findings?status=resolved&resolution_kind=advisory_withdrawn,advisory_changed` lists the others. The matcher's `resolved` history events carry the kind and facts in `detail`.

Findings also carry `display_state`, `regressed_at`, `until_fix`, `ignore_reason` and `exception_id`; see [The seven states](#the-seven-states).

## Upgrade recommendations

`upgrade` objects are built only from stored data: the fixed versions advisories give for the open findings on one installed copy, the registry's release list, and endoflife.date release lines. Nothing is guessed: when data is missing the response says so.

- `minimum_fixed_version`: the highest `fixed_version` across the open vulnerability findings, compared by the ecosystem's rules.
- `recommended_version` and `basis`:
  - `distro_fixed` for OS packages (deb, rpm, apk): the distribution's fixed build. Registry releases do not apply (`release_data: not_applicable`).
  - `latest_in_line`: the newest stable, non-withdrawn release at or above the minimum in the installed version's major line. If the fix only exists in a later major line, the newest such release in that line, and `requires_major` is true.
  - `minimum_fixed`: there is no release data (`release_data: none` or `failed`), or no stable release at or above the minimum is recorded (for example the fix is a pre-release).
  - `supported_line`: the installed release line is end of life, so the end-of-life finding is resolved only by moving to the newest release of the oldest supported line after it (from release data, else endoflife.date's latest), provided that is at or above the minimum fix.
  - `none`: no source lists a fixed version.
- `change_type` (`patch`, `minor`, `major`, `distro`), `requires_subscription` (the fixed build is only in Ubuntu Pro or SUSE LTSS, paid subscriptions; the rationale names the free path), `recommended_yanked`, `minimum_fixed_yanked` and `installed_yanked` (withdrawn by the registry, with `yanked_reason`), and the package's `deprecated` notice.
- `lifecycle`, `target_lifecycle` and `supported_line`: release lines with `status` `supported`, `security_only` or `end_of_life`.
- `fixes` and `unfixed`: the finding keys the recommended version resolves and those it does not. `rationale` gives the reasons in plain language.

Package upgrade groups in the action plan (`GET /fix-groups`) carry `recommended_version`, `target_version`, `change_type`, `requires_major`, `recommended_yanked` and `rationale`; `to_version` stays the minimum fixed version. `target_version` is the version the `title` and `action` name: the recommended version when it is a newer stable release in the minimum fix's own major line ("Upgrade ip-address 10.1.0 → 10.7.5", with 10.7.4 in `to_version`), otherwise `to_version`. A major upgrade or a withdrawn release never heads the title; the action then mentions the recommendation. Below 1.0 the recommendation heads the title only within the same minor line (0.33 to 0.33.x, not 0.34). `GET /fix-groups/summary` takes `group_by` like `GET /fix-groups`: grouped by fix, a fix needed in several places counts once. A group's `needs` (`ubuntu-pro`, `SUSE LTSS`) says a paid channel also publishes fixes for some of its findings; it is informational, and `action` is always the free path.

## Remediation outcomes

`GET /reports/outcomes` returns `days`, the risk `policy_version` and a `report`:

- `resolved`: findings remediated in the window that are still resolved: `remediated` (the installed version changed) plus `removed` (the component is gone). See [Why a finding closed](#why-a-finding-closed).
- `closed_not_remediation`: findings that closed in the window with nothing changed on the asset, `total` and `by_kind` (`advisory_withdrawn`, `advisory_changed`, `superseded`, `not_evaluated`, `other`). They are not in `resolved`, `time_to_remedy` or `sla`.
- `time_to_remedy`: `mean_days` (MTTR) and `median_days` from detection, or from the last reopening, to resolution, by `priority` and `kind`, for remediated and removed findings; `all` rows are totals.
- `causes`: every closure by `cause` with its `resolution_kind`, `counts_as_remediation` and `evidence`: `upgraded` (a newer inventory shows another version), `remediation` (a verified remediation action) and `removed` (a complete inventory no longer lists it) count as remediation; `superseded` (`evidence: fresh_collection`), `advisory_withdrawn` and `advisory_changed` (`evidence: intelligence`), `not_evaluated` (`evidence: coverage`) and `other` do not.
- `sla`: per priority, the policy's `fix_days`, remediated findings resolved within that many days of first detection out of those remediated, and open and overdue counts now.
- `reopened`: reopenings and distinct findings in the window, and of the resolutions recorded in the window how many were later reopened. `events_since` is when resolutions and reopenings started being recorded.
- `open`: active, overdue, excepted (suppressed or accepted) and on stale assets, now.
- `remediation`: plans by status and actions by status created in the window, the success rate (verified out of verified, failed and rolled back), rollback actions and recent failures; `null` when there were none.

Every rate comes with the counts it is computed from and is `null` when there is nothing to divide by.

## Workflow

Each finding has a detection `status` (`open` or `resolved`), set automatically, and a workflow `state` that people set:

| Action | Resulting state | Notes |
|---|---|---|
| `acknowledge` | `acknowledged` | Stops acknowledgement escalation |
| `start` | `in_progress` | |
| `reset` | `new` | |
| `assign` | unchanged | `user_id` and/or `team_id`; `0` clears |
| `comment` | unchanged | `note` is recorded in the history |
| `suppress` | `suppressed` | Security role ("Snooze"); see below |
| `accept_risk` | `risk_accepted` | Security role; fields as `suppress` |
| `ignore` | `risk_accepted` | Security role; see [Ignore rules](#ignore-rules) |
| `reopen` | `new` | Security role; see below |

- **`suppress`** ("Snooze" in the dashboard): `note` (the reason) and `until` are required; `until` may be at most the risk policy's `exception_max_days` (default 365) ahead. Optional `mitigation` records what reduces the risk meanwhile. With `"until_fix": true` the issue is snoozed until a fix ships: `until` is optional and defaults to the exception limit as a backstop; refused when a free fixed version already exists.
- **`accept_risk`** takes the same fields and limit as `suppress`, and sets `ignore_reason` `accepted_risk`.
- **`ignore`** takes `reason`, `scope`, `expiry`, `until` (for `expiry: date`), `note` (required) and `mitigation`.
- **`reopen`** works from `suppressed` or `risk_accepted`. A finding reopened from an ignore rule is not ignored by that rule again.

When a snooze, risk acceptance or ignore expires, or a free fixed version appears for one that waits for a fix, the finding returns to `new` with an `expired` or `fix_available` event and is announced again. Every action is recorded in the finding's history and in the audit log. Engineers and viewers cannot snooze or ignore: they ask through the [approval inbox](#approval-inbox).

### The seven states

The dashboard shows seven states. They map onto the stored `status` and `state`, which are unchanged; `display_state` on every finding gives the mapping:

| Shown | `display_state` | Stored |
|---|---|---|
| New | `new` | `status` open, `state` `new` |
| To do | `to_do` | `status` open, `state` `acknowledged` |
| In progress | `in_progress` | `status` open, `state` `in_progress` |
| Fixed | `fixed` | `status` `resolved` |
| Regressed | `regressed` | `status` open, `regressed_at` set, `state` `new` or `acknowledged` |
| Snoozed | `snoozed` | `state` `suppressed` |
| Accepted | `accepted` | `state` `risk_accepted` (with `ignore_reason`) |

`GET /findings?state=regressed` lists the regressed issues; `GET /findings/summary` adds `regressed` and `until_fix` (snoozed or ignored issues waiting for a fix). Snoozed and accepted issues stay in `by_state` (`suppressed`, `risk_accepted`), so the counts of hidden issues include them.

### Ignore rules

`ignore` records why an issue is ignored, where, and until when:

- `reason`: `accepted_risk`, `false_positive`, `mitigated` or `no_fix`. A false positive also sets the finding's `verification` to `rejected` (the matcher keeps it; reopening restores its own value).
- `scope`: `asset` (the default) or `everywhere`: every asset in the workspace with the same component and advisory, including assets and findings found later.
- `expiry`: `date` (with `until`, at most `exception_max_days` ahead), `until_fix` (until a free fixed version exists, with `exception_max_days` as a backstop; refused when one exists already) or `never` (false positives only).

Each ignore is stored as a rule for one issue (component and advisory) on one asset or everywhere; a new ignore with the same scope replaces the earlier rule. Every minute the rules are applied to new and regressed findings they cover, with an `ignored` event. When a rule's date passes it ends (`ended_reason: expired`) and its findings return to `new`. `DELETE /ignore-rules/{id}` ends a rule by hand.

### Approval inbox

Engineers and viewers ask for an ignore with `POST /ignore-requests`; the request records who asked, why, the scope and the expiry, and changes nothing. Security and admin users approve or decline it (`POST /ignore-requests/{id}/decision`), with an optional note. Approval ignores the issues that are still open and active, with the decider as the actor and the request in each finding's history. Requests and decisions are in the audit log (`ignore_request.create`, `ignore_request.approve`, `ignore_request.decline`).

## Check again

A check asks for fresh evidence about an asset or about one fix on it. An action reported as done never closes an issue: only a fresh report does, and issues close on their own when it no longer has them.

- `method` says who has to report: `agent` (the agent on a host, which [polls](#agent-poll)), `integration` (a server-side scan of a Git repository or image, queued at once) or `report` (the next upload, such as `stackurity scan` in CI).
- `status`: `waiting` (no report yet), `evaluating` (a complete report arrived after the request and is being matched) or `done`.
- `outcome` when done: `passed` (none of the issues it was about is left), `partly_fixed` (some are gone, `remaining` are left), `still_open` (none is gone) or `expired` (no report within 7 days). `fixed`, `remaining` and, for a whole asset, `new_issues` give the counts; an issue counts as left when it is open on the asset in any state, on any version.
- `reason` is `check`, or `applied` for "I applied this". `requested_by`, `requested_at`, `picked_up_at` (when the agent asked for it), `collection_id` (the report that answered it) and `completed_at` record what happened. `agent_polled_at` (also on `GET /assets/{id}`) is when the asset's agent last polled: null for agents older than 0.7.

Requesting a check while one with the same scope is still waiting for a report returns that check.

### Agent poll

Agents from 0.7 on ask `GET /agent/check?asset_id=1&asset_id=2` between collections, every 45 seconds plus up to a third of that as jitter (`--check-interval`, 0 turns it off), with the assets their last report went to and their own token. A host-bound token is only answered for its host and the applications on it (the assets ingest accepts from it); other ids are ignored. The answer is `{"check": true|false, "poll_seconds": 45}`; the agent follows `poll_seconds` between 15 seconds and 10 minutes. When `check` is true it collects and reports at once. The request is a lookup in a small index; the server records the poll on the asset at most every 5 minutes. A server without the endpoint (404) makes the agent stop polling. Agents older than 0.7 never poll: they report on their `--interval` (6 hours by default) and when they start, so restarting one reports at once.

## Priority and SOS

Every open finding gets a priority from P1 to P4. The score is built from the CVSS score (CVSS v3.x or v4.0, whichever rates the advisory higher; `severity_source` on the advisory says which) or the severity when there is none, CISA KEV, internet exposure (unknown exposure counts a little), production environment (no environment counts a little), asset criticality, fix availability, whether it is overdue, and dev-only scope. It is then scaled down for unverified or stale evidence (a score at or below zero is not scaled). SOS rules that require an exposed or production asset also match an asset whose exposure or environment is unknown. [risk.md](risk.md) explains every factor and the guarantees the scoring keeps. `priority_factors` lists each contribution and `priority_policy_version` the risk policy version that produced them. Weights, thresholds and per-priority deadlines are configured in `/risk-policy`.

SOS rules are conditions over the same inputs. A rule based only on severity is rejected. Only confirmed findings can trigger SOS.

## Incidents and notifications

Findings with the same `kind` and `key` whose assets belong to the same owner team form one incident, so one CVE across fifty servers produces one alert. System problems also open incidents, and these resolve on their own once the problem is gone:

- a stale or failing feed (`feed`)
- a stale asset or failing integration (`collection`)
- a drop of more than half in an asset's collected inventory (`coverage`)
- in the operators' workspace only (the default workspace, or `STACKURITY_PLATFORM_WORKSPACE`), a critical problem with the installation itself, such as a background task that keeps failing or intelligence that never synced (`platform`)

Routes send to channels and filter by SOS only, kinds, environments, owner teams and projects. People get a few grouped messages that link to the dashboard, never one message per incident. A route's `events` decide which (the dashboard calls them the integration's **Trigger**):

| Event | Sends |
|---|---|
| `urgent` | new issues at `min_priority` (the urgent threshold, default `P1`) or above, SOS or known exploited, right away |
| `new_issues` | new issues at `new_min_priority` (default `P4`: every issue) or above, right away |
| `regressed` | issues that came back after a fix, right away |
| `overdue` | with `escalation` (licensed), at most one message a day when urgent issues pass their fix deadline |
| `connected` | a new asset's first scan, once |
| `problems` | collection, feed, coverage and platform problems at `min_priority` or SOS, right away |
| `daily_summary` | a daily summary at `summary_time` |
| `weekly_summary` | a weekly summary on `summary_day` at `summary_time` |

Everything sent right away in one evaluation cycle goes in one `urgent` message per route and destination. `event_channels` (Slack routes only) sends some events to other Slack channels of the organisation instead of the route's, as `{"daily_summary": 12}`; every other event goes to `channel_id`. A route may send both summaries; each keeps its own period (`last_summary_at` for the daily one, `last_weekly_summary_at` for the weekly one, both read-only).

`mode` is still accepted and returned, for older clients:

| `mode` | `events` |
|---|---|
| `urgent_summary` (default) | `urgent`, `regressed`, `overdue`, `connected`, `problems`, `daily_summary` |
| `urgent_weekly` | the same with `weekly_summary` instead of `daily_summary` |
| `urgent_only` | `urgent`, `regressed`, `overdue`, `connected`, `problems` |
| `daily` | `daily_summary` |
| `weekly` | `weekly_summary` |

A route's `mode` is the one its events match, or `custom`. On `POST` and `PUT`: when `mode` is left out, `custom`, or the route's current mode, the `events` sent are used (on `PUT` without `events`, the route keeps its events). When `mode` changes to one of the modes above, the route gets that mode's events; `events` sent with it must match that mode or be the route's current events unchanged (a client sending back what it read), otherwise 400. `event_channels` and `new_min_priority` keep their values unless sent (overrides for events the route no longer sends are dropped). New clients send `events` without `mode`. Deleting a channel takes it out of every route's `event_channels`; while an override channel is disabled, its events go to the route's channel. Migration `0047` gave every existing route its mode's events, so none changed behaviour.

`summary_time` (`"HH:MM"`, default `09:00`) and quiet hours are in the route's `timezone`; `summary_day` is a weekday name (default `monday`). New routes default to `min_priority` `P1` and `new_min_priority` `P4`.

The `event` of each message:

- `urgent`: at most one per route and destination per evaluation cycle, only when the cycle produced what the route sends right away: new issues (`urgent`: at `min_priority` or above, SOS, or known exploited; `new_issues`: at `new_min_priority` or above, then titled "N new issues" with the urgent ones counted), issues that came back (`regressed`), or a problem with collection, feeds or the platform at `min_priority` (`problems`). Summarised per asset (up to 5, then "+N more") with up to 3 fixes each from **Fixes**.
- `summary`: daily or weekly at `summary_time` (`daily_summary`, `weekly_summary`): new issues by asset, issues fixed (with the fix that closed them, when `send_resolved`), the top 3 fixes still open, overdue counts (when `escalation`, licensed), and open problems. Skipped when nothing changed. A summary is never held by `max_per_hour`.
- `overdue` (licensed, routes with `escalation` and the `overdue` event): at most one per route per day, when urgent (P1 or SOS) issues have just passed their fix deadline; groups every overdue urgent issue by fix. Escalation levels (1: acknowledgement deadline passed, 2: fix deadline passed) are still recorded on incidents and findings.
- `connected` (the `connected` event): when a new asset's first complete collection has been evaluated (or six hours after it appeared, if no complete collection arrives): "commmerceblog connected: 1,676 packages checked, 412 issues found, 3 fixes need you". See [A quiet first scan](#a-quiet-first-scan).
- `test`: **Send test**.

Resolved incidents are not announced; summaries count fixed issues. Quiet hours delay everything except SOS. When `max_per_hour` is reached, further messages are held (`held_by` `hourly_limit`) and counted in the route's next summary, never sent one by one; a route without a summary gets them in one `digest` message an hour instead ("Stackurity: 4 urgent messages held by the hourly limit", one line per held message). Email sent by Stackurity (`stackurity_email`) also counts against the organisation's email limits per minute, hour and day (in emails, one per recipient): over them, a message is held the same way (`held_by` `email_quota`, "email limit per hour reached; included in the next summary"), and a summary or digest waits until the limit frees. Held messages are never dropped. Failed deliveries are retried with backoff up to 8 times, no sooner than a receiver's `Retry-After`. A delivery that cannot succeed until the configuration changes (Jira rejecting the credentials, an unknown project) fails at once.

Jira channels (`"kind": "jira"`) keep one issue per incident instead, whatever the route's `mode`: the first matching event (`opened`, `priority_raised`) creates the issue, later changes are queued as `updated` deliveries (findings joined or left, priority changed), `escalated` for routes marked `escalation` (one comment per issue) and `resolved`. Quiet hours, limits and summaries do not apply to them. Incidents in lists and in `GET /incidents/{id}` carry the issues that follow them:

```json
"issues": [{"tracker": "jira", "key": "SEC-42", "url": "https://acme.atlassian.net/browse/SEC-42", "channel_id": 7}]
```

`channel_id` is `null` once the channel is deleted; the link is kept.

A route to Jira may be limited to one project (`project_ids` with one id; more than one is 400). It keeps its own issue per incident, describing only that project's part: the project's assets and findings, their counts and priority, escalations, and links opened in the project (`?project=`). The content is read through a connection narrowed to the project, so row-level security keeps other projects' assets out. The issue is created when the project's part matches the route (announced, or the project's finding appeared or came back, after the route was created), updated as that part changes, resolved when none of the project's findings remain open (even while the incident stays open elsewhere), and told if they open again. Its label adds `-route-<route>-project-<project>` to the incident's label. An unscoped route on the same channel keeps its whole-incident issue. Such issues are listed with their project for organisation-wide roles, and never shown to members with project access:

```json
"issues": [{"tracker": "jira", "key": "SEC-42", "url": "...", "channel_id": 7},
           {"tracker": "jira", "key": "SHOP-9", "url": "...", "channel_id": 8, "project_id": 3}]
```

```json
{"kind": "jira", "name": "security-jira", "secret_ref": "secret:JIRA_TOKEN",
 "config": {"url": "https://acme.atlassian.net", "deployment": "cloud", "username": "bot@acme.io", "project": "SEC",
            "issue_type": "Task", "labels": ["security"], "priorities": {"P1": "Highest", "P2": "High"},
            "resolve_transition": "Done"}}
```

### Notification messages

Webhook channels receive each message as JSON. Fields are only ever added, never renamed or removed. Grouped messages (`urgent`, `summary`, `overdue`, `connected`) look like this:

```json
{
  "event": "urgent",
  "title": "commmerceblog: 6 new urgent issues",
  "priority": "P1",
  "sos": true,
  "route": "security-oncall",
  "summary": ["commmerceblog: 6 new urgent issues (2 known exploited)", "  Top fix: Install security updates and reboot (clears 2,913 issues)"],
  "sections": [
    {"items": [
      {"text": "commmerceblog: 6 new urgent issues (2 known exploited)",
       "link": "https://stackurity.example.com/fixes/issues?asset_id=12&priority=P1",
       "items": [{"text": "Top fix: Install security updates and reboot (clears 2,913 issues)",
                  "link": "https://stackurity.example.com/fixes/12:security_updates"}]}
    ]}
  ],
  "counts": {"urgent": 6, "assets": 1, "problems": 0},
  "link": "https://stackurity.example.com/",
  "settings_link": "https://stackurity.example.com/settings/notifications?tab=routes",
  "at": "2026-10-26T09:12:00Z"
}
```

- `summary` holds the item texts as plain lines (details indented), for receivers that only show text.
- `sections[].title` names the part of a message: `Came back after a fix` (urgent and summary), `New issues`, `Connected`, `Fixed`, `Top fixes still open`, `Overdue`, `Stackurity needs attention`.
- `counts` keys: `urgent`, `assets`, `problems`, `regressed` (urgent); `new`, `new_urgent`, `fixed` (remediated or removed only), `no_longer_affected` (closed because the advisory was withdrawn or changed, listed apart under Fixed), `connected`, `connected_issues`, `regressed`, `open_fixes`, `overdue`, `overdue_urgent`, `ack_overdue`, `problems`, `held` (summary); `overdue_urgent`, `fixes` (overdue); `assets`, `issues` (connected).
- Each fix in a message (an item whose `link` is `/fixes/{id}`) has `actions`: `[{"kind": "assign", "label": "Assign to me", "link": ".../fixes/{id}?action=assign"}, {"kind": "snooze", ...}, {"kind": "open", ...}]`. Each action also carries `fix`, the fix group id. Slack shows them as URL buttons (on up to 8 items per message), email and Teams as links. They open the fix in the dashboard with the action ready; the person confirms it there after signing in. Following a link changes nothing. On a Slack channel with a signing secret, Assign to me and Snooze 1 week act from inside Slack instead (see [Acting from Slack](#acting-from-slack)).
- A route limited to projects (`project_ids`) opens every link in its project (`?project=N`): its only project, or for a route on several the first of them the item's asset is in.
- Issues that came back after a fix are urgent whatever their priority: the next urgent message on routes with the `regressed` event lists them per asset ("web-1: 3 issues came back after a fix"), once, and summaries count them in their own section rather than as new issues.
- Summaries also carry `"period": {"from": "...", "to": "..."}`.

### Acting from Slack

A Slack channel added with **Add to Slack** ([slack-app.md](slack-app.md), `config.slack_app`) gets interactive buttons verified with the server's Slack app signing secret, accepted only from the Slack workspace (`config.team_id`) the app was installed into: the click's `team.id` or, in a Slack Connect channel, the clicking person's own `user.team_id`. People of another Slack workspace in a shared channel cannot use the buttons (their Open link works). Adding the app to the same Slack channel again refreshes that integration (its webhook, and switches it back on) instead of making a second one. A Slack channel whose `config` has `signing_secret_ref` (a secret reference such as `secret:SLACK_SIGNING` to a Slack app's signing secret) gets interactive buttons: **Assign to me** and **Snooze 1 week** act from inside Slack, **Open** stays a link. Without it the message is exactly as described above. The channel's incoming webhook must belong to the same Slack app, whose Interactivity Request URL is `https://<your server>/api/v1/integrations/slack/actions` (setup: [install.md](install.md#acting-from-slack)).

- Each button's `value` is `stk1|<channel id>|<assign|snooze|open>|<fix id>`. A click is accepted only when the signing secret of that channel verifies Slack's `v0` signature over the exact body, the channel is an enabled Slack channel of an enabled organisation, the timestamp is within 5 minutes, the signature has not been seen before, Slack's `response_url` is on `hooks.slack.com` (or `hooks.slack-gov.com`), and the click comes from the Slack workspace of the channel's webhook URL.
- The first click of a Slack user gets an ephemeral reply with a link, `/slack/link#<token>`, that works once, for 15 minutes, in the channel's organisation only. The signed-in person confirms it there.
- A linked click runs as that person, exactly like `POST /findings/actions` from the dashboard on the fix's open issues (up to 2,000): Assign to me needs engineer (or a project role of engineer on every issue's asset), Snooze needs security, and people with access to some projects only cannot touch other projects' fixes. Snooze sets `suppress` until 7 days later with the note "Snoozed for 1 week from Slack". Audit entries are the dashboard's (`finding.assign`, `finding.suppress`) with `"source": "slack"`, `slack_user_id` and `slack_team_id` in `detail`.
- The answer goes to `response_url`: the message is updated with a line under the clicked buttons ("Assigned to Nirmal (3 issues)", "Snoozed until 3 Nov by Nirmal (3 issues)"), or an ephemeral reply says why the click was refused.
- Every `link` is a dashboard page: the home page, an asset, a fix (`/fixes/{id}`) or a filtered **All issues** list (`/fixes/issues?...`; summaries add `new_within` or `resolved_within` for their period). Links need `STACKURITY_BASE_URL`.
- Jira issue events (`opened`, `priority_raised`, `escalated`, `resolved`, `updated`) and `test` keep the per-incident shape: `incident_id`, `kind`, `key`, `title`, `priority`, `summary`, `recommended_action`, `link`.

### A quiet first scan

Connecting an asset tells people once, in the `connected` message, and nothing else about what it already had. A finding is part of an asset's **first-scan backlog** while the asset is not announced yet, or when it was first seen before the asset's announcement (assets created since 0.9; `assets.quiet_backlog`). The backlog:

- raises no `urgent` message and no "came back after a fix" alert, even when its incident appears after the announcement;
- creates no Jira issue (an incident whose open findings are all backlog);
- is never escalated (no escalation level is recorded on its incidents or findings) and is not counted in `overdue` messages or in summaries' overdue, newly overdue and not-acknowledged counts;
- is not "new issues" in summaries: the `Connected` section says "1,676 packages checked, 412 issues found", and the title "1 asset connected, 412 issues found".

Issues first seen after the announcement, and issues that come back after it, alert and escalate as usual. Assets that existed before 0.9 keep their deadlines as they were.

Every delivery carries these headers:

- `X-Stackurity-Event`
- `X-Stackurity-Delivery`
- `X-Stackurity-Timestamp`
- `X-Stackurity-Signature: sha256=HMAC(secret, timestamp + "." + body)`

To verify a delivery, recompute the HMAC over the timestamp and body, and reject old timestamps.

Delivery is at least once: if a server dies after sending but before recording it, the message is sent again a few minutes later. Receivers that must not act twice can deduplicate on `X-Stackurity-Delivery`.
