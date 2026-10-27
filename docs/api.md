# API v1

Base path: `/api/v1`. Requests and responses are JSON. Errors look like this:

```json
{"error": {"code": "invalid", "message": "validation failed", "details": ["observations[3].purl \"x\" is not a valid purl"]}}
```

## Authentication

- **API tokens** (`Authorization: Bearer stk_...`) for the CLI, agents and integrations. User tokens carry a role no higher than their owner's *current* role. Collector tokens can only submit observations and SBOMs.
- **Session cookie** for the dashboard (`POST /auth/login`). Requests that use cookie authentication and change state must send `X-Stackurity-CSRF: 1`.

Roles, from least to most access: `viewer` (read, including the audit log; ask to ignore issues), `engineer` (edit assets, trigger scans, check again; ask to ignore issues), `security` (snooze, ignore and risk acceptance, deciding ignore requests, notification channels and routes, remediation policies, plan approval), `admin` (users, teams, tokens, integrations, conflicts, deletion).

## Projects and access

A workspace (shown as the organisation in the dashboard) groups its assets into **projects**; one asset can be in several. The roles above apply either to the whole workspace (organisation-wide) or, through **access grants**, to chosen projects or single assets only. See [docs/design/projects.md](design/projects.md).

- **Members with project access only** (`GET /auth/me` returns `"access": "projects"` and an empty `role`) see only the assets of their projects and asset grants, and everything that hangs off them: findings, fix groups, incidents (their counts, names and priority recomputed from what they can see), components and their counts, search hits, reports, audit events about those objects, and exports. Routes for organisation data (users, teams, integrations, channels, routes, deliveries, jobs, secrets, enrollments, remediation plans and policies, ingest) answer 403. The database enforces this with row-level security, not only the API.
- **Roles from grants act per asset.** `GET /auth/me` returns `project_role`, the highest role from any grant. A change (`PATCH /assets/{id}`, relations, finding and incident actions) needs that role on each asset it touches; otherwise 403. An organisation-wide viewer with `engineer` on one project can act on that project's findings only.
- **Choosing a project.** Send `X-Stackurity-Project: <id>` (the dashboard does) or `?project_id=<id>` on any request; `0` or nothing means all projects. Project-scoped routes (the reading routes above, `GET /reports/evidence`, `GET /assets/{id}/sbom`, search, audit) then return only that project's assets and what hangs off them; other routes ignore it. A project the caller cannot see answers 404, a value that is not a number 400. The CLI sends the header for `--project` (or `STACKURITY_PROJECT`).
- **People and links.** Someone who assigns through a project role (their organisation role alone may not assign) can assign only to the people and teams of their projects (400 otherwise), and `GET /users/directory` gives them only those people. Grants are audited as object type `access_grant` and asset merges as `asset_merge`, which project-only members never see. Incidents shown to them carry no tracker `issues`, no `notified_priority`, and priority, SOS and escalation from their findings; `priority=`, `sos=` and `escalated=` filter on those.
- **Checks, ignore rules and requests** follow their assets. Ignoring an issue on every asset (`scope: everywhere`), approving such a request and ending such a rule need an organisation-wide `security` or `admin` role (403 otherwise). With `security` through a project grant, `GET /ignore-requests` lists the caller's own requests and those whose issues are all on assets where they hold it (`can_decide` is true), and they decide only those.
- **Tokens** of a member with project access only act as that member, never above their highest grant. Collector and host-bound agent tokens belong to the workspace and are not limited by projects.

## Endpoints

| Method & path | Role | Purpose |
|---|---|---|
| `GET /meta` | none | Version, whether first-time setup is required, and `features`: what this server supports that an older one would silently ignore. `upload_project` means `POST /ingest` and `POST /sbom/import` honour `project_id` (0.10); `stackurity` checks it before an upload with `--project` |
| `POST /setup` | setup token | Create the first admin |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | none / any | Session handling |
| `POST /feedback` | any signed-in user (rate limited, 10 an hour) | Send feedback to the Stackurity team: `kind` (`bug`, `idea`, `question`), `message` (up to 5000 characters), optional `email` and `page` (a path). The server adds its version and edition and forwards it to `STACKURITY_FEEDBACK_URL`; answers 202 when delivered, 502 when the feedback service cannot be reached, and 404 when feedback is turned off (`GET /auth/me` then has `feedback_enabled: false`). See [network.md](network.md#feedback) |
| `POST /auth/password` | any signed-in user | Change your own password (`current_password`, `new_password`). Your other sessions are signed out |
| `POST /enroll` | none (rate limited) | Exchange a one-time enrollment code (`{"code", "hostname"}`) for a collector token and the agent settings chosen with it, including the code's `project_id` (null when it has none). Refusals of a code do not say why. Optional `project_id` (`stackurity enroll --project`) is a check, not a choice: when the code adds hosts to another project or to none, the answer is 403 and the code keeps its use. Servers before 0.10 answer 400 to the unknown field, also without using the code |
| `GET`/`POST /enrollments`, `DELETE /enrollments/{id}` | admin | Create, list and revoke enrollment codes: `label`, `environment`, `app_dirs`, `discover_apps`, `uses` (1–500, default 1), `ttl_hours` (1–720, default 24), `project_id` (hosts enrolled with the code, and the assets their agent reports, are added to that project when first created). The code is returned once |
| `GET /install/agent.sh`, `GET /download/agent/linux-{amd64,arm64}[.sha256]` | none | The agent installer and the agent builds it downloads (bundled in the server image; `STACKURITY_AGENT_DIR`) |
| `POST /ingest?project_id=` | collector, engineer+ | Submit an `ObservationBatch` (gzip accepted). `project_id` files the asset in a project, see [Uploads into a project](#uploads-into-a-project) |
| `POST /sbom/import?asset_name=&asset_kind=&environment=&project_id=` | collector, engineer+ | Import a CycloneDX or SPDX JSON document. `project_id` files the asset in a project, see [Uploads into a project](#uploads-into-a-project). A collector token made for a project adds the assets it creates to it |
| `GET /collections/{id}/result` | collector (own submissions), engineer+ | Whether a submitted collection has been evaluated (`status`: `pending`, `scoring` (matched, findings not prioritised yet), `evaluated` (matched and prioritised), `failed`), then the asset's open findings and its count of `evaluation_gaps`. Used by `stackurity scan --fail-on` |
| `GET /overview` | viewer | Inventory, coverage and status counts, including assets by coverage state (`asset_coverage`) and components by row coverage (`component_coverage`) |
| `GET /search?q=&limit=` | viewer | Global search of the current workspace, see [Search](#search) |
| `GET /assets?kind=&environment=&status=&owner_team_id=&q=&reboot_required=true&exposed=&unfiled=true` | viewer | List assets. `reboot_required=true` lists hosts that run older code than is installed. `exposed=true` or `false` filters by `exposed`, the exposure risk scoring uses: `internet_exposed` when set by hand, else what a collector observed (a Kubernetes workload's `exposure`, or for an image the workloads deployed as it). `unfiled=true` lists the assets in no active project. Each asset has `projects`, the active projects it is in that the caller can see |
| `GET /assets/{id}` | viewer | Asset and identifiers |
| `PATCH /assets/{id}` | engineer | Set name, environment, owner, criticality, exposure, tags |
| `DELETE /assets/{id}` | admin | Delete an asset and its history |
| `GET /assets/{id}/inventory?q=&type=&direct=&include_removed=&coverage=` | viewer | Components on the asset, with evidence and coverage (see below) |
| `GET /assets/{id}/coverage-summary` | viewer | How far the asset's findings can be trusted: its [coverage states](compatibility.md#coverage-states) with reasons, components by coverage, gap reasons and stale feeds |
| `GET /assets/{id}/coverage`, `/collections`, `/relations` | viewer | Coverage ledger, collection history, relations |
| `POST`/`DELETE /assets/{id}/relations` | engineer | Add or remove `runs_on`, `built_from`, `deployed_as`, `contains`, `depends_on`, `replica_of` (a standby, staging or DR copy that should run the same versions as the target) |
| `GET /assets/{id}/stack` | viewer | Everything the asset relies on, followed through relations, with open findings grouped by layer (`web_server`, `os`, `runtime`, `data_store`, `libraries`, `declared`, `managed_service`, `platform`, `other`). For an application this is its hosts, repository, images and dependencies (up to three hops); for a host, the applications running on it; for a cluster, its workloads and their images; for an image, the workloads deployed as it; for a repository, its deployments and their hosts |
| `GET /assets/{id}/drift?with=` | viewer | Components whose versions differ from another asset (`with`, or the asset this one is a `replica_of`). Each item is `behind`, `ahead`, `differs`, `only_here` or `only_there`, compared by the component's ecosystem rules |
| `GET /assets/{id}/sbom` | viewer | CycloneDX 1.6 export |
| `GET /components?q=&type=`, `GET /components/{id}` | viewer | Component explorer |
| `GET /components/{id}/upgrade` | viewer | An [upgrade recommendation](#upgrade-recommendations) for each installed version with open findings (most findings first, at most 50; `total` counts all), with `version`, `distro` and `asset_count` |
| `GET /inventory?component_id=&asset_id=&coverage=` | viewer | Where a component is used |
| `GET /coverage?problems=true` | viewer | Coverage ledger across assets |
| `GET /reports/evidence?from=&to=` | viewer | Patch-management evidence for a period (dates, `to` inclusive; default the last 30 days, at most a year): assets and their collection status, hosts needing a reboot, evaluation gaps, open findings by severity and priority, overdue findings, findings resolved in the period with the share resolved within their deadline and the median days from first detection to resolution, every active exception with its reason, mitigation and expiry, and drift for each `replica_of` pair |
| `GET /reports/outcomes?days=` | viewer | [Remediation outcomes](#remediation-outcomes) over the last `days` (1 to 365, default 90) |
| `GET /audit?object_type=&object_id=` | viewer | Audit events |
| `GET /usage` | viewer (organisation-wide) | [Monitored assets](asset-limits.md) against the organisation's limit: `monitored`, `limit` (null: none), `at_limit`, `by_kind`, `stale`, `workloads` (not counted), `refused` (the most recent new assets refused at the limit) and `refused_recently` (last 7 days). At the limit, requests that would create an asset answer `402` with code `asset_limit` |
| `GET`/`POST /tokens`, `DELETE /tokens/{id}` | any user | Personal tokens (admins: all tokens and collector tokens). A collector token can name a `project_id`: assets it creates are added to that project (the first-run flow's repository step) |
| `PUT /auth/default-project` | any signed-in user | `{"project_id": N}` (0: all projects): the project the dashboard opens with. `GET /auth/me` returns it as `default_project_id`, with `projects` (the projects the caller can choose), `access` and `project_role` |
| `GET /projects?archived=true` | viewer, or any grant | Projects the caller can see (members with project access only: theirs, each with their `role`), with `asset_count`; organisation-wide callers also get `unfiled_assets`, the assets in no active project. `archived=true` (admins) includes archived projects |
| `GET /projects/{id}` | viewer, or a grant on it | A project; for admins also its `grants` |
| `POST /projects` | admin | `{"name", "description", "asset_ids"}` |
| `PATCH /projects/{id}` | admin | `name`, `description`, `archived` (true archives: grants on it stop giving access and routes limited to it stop matching; false restores) |
| `POST`/`DELETE /projects/{id}/assets` | admin | `{"asset_ids": [...]}` (1 to 5000): add or remove assets; returns `changed` |
| `GET /access-grants?project_id=&asset_id=&user_id=&team_id=` | admin | Access grants, with project, asset, person and team names |
| `POST /access-grants` | admin | `{"project_id" or "asset_id", "user_id" or "team_id" or "email", "role"}`. With `email`, someone who is not a member joins with no organisation-wide role (an account is created with `password` when there is none; `account_created` says so). A grant that exists for the same person or team and project or asset has its role changed (200); a new one is 201 |
| `PATCH`/`DELETE /access-grants/{id}` | admin | Change a grant's `role`, or remove it. Takes effect on the next request |
| `GET /project-suggestions`, `POST /project-suggestions/dismiss` | admin | Groupings proposed from `runs_on`, `built_from` and `deployed_as` relations: assets in no project related to a project's assets (`project_id`), or related assets all in no project (`suggested_name`). Nothing changes until someone adds the assets; `{"key"}` hides one until its assets change |
| `GET /onboarding` | admin | The [first-run flow](#onboarding): `state` (`new`, `skipped`, `done`), `show_flow` (state `new` and no assets yet), `has_assets`, `project_id` and `project` (chosen in the flow), and `steps` (`project`, `asset`, `notifications`, `invite`), each read from what exists. When every step is done the state becomes `done` |
| `PUT /onboarding` | admin | `{"state": "new" \| "skipped" \| "done", "project_id": N}`; audited as `onboarding.update` |
| `GET /onboarding/results?since=` | viewer | The waiting screen's poll: assets created since `since` (RFC 3339; default the last 24 hours), newest first, at most 20, in the chosen project (`project_id` or the header). Each has `packages`, `issues` (active), `checked` (its first complete report has been evaluated, so the counts are final) and `fixes_now` (fixes in Home's focus) |
| `GET /invitations?project_id=` | admin | [Invitations](#invitations): open ones, and the others of the last 30 days, with `status` (`pending`, `accepted`, `revoked`, `expired`). Never the link |
| `POST /invitations` | admin (30 an hour per organisation) | `{"email", "name", "role", "project_id"}` (`project_id` 0: an organisation-wide role). 201 with `invitation` and `emailed`; when the email was not sent, `link` (shown once) and `email_problem`. Inviting the same person to the same project again replaces the open invitation. Someone already a member gets the project role at once (`granted`, `grant`); an organisation-wide invitation for a member is 409 |
| `DELETE /invitations/{id}` | admin | Withdraw a pending invitation: its link stops working |
| `POST /invitations/preview` | none (rate limited) | `{"token"}`: what the link is for (`workspace`, `project`, `role`, `email`, `invited_by`, `expires_at`, `account_exists`) and `signed_in_as`. 410 for any link that does not work, without saying why |
| `POST /invitations/accept` | none, or the invitee's session (rate limited) | `{"token", "name", "password"}`. Joins the invitation's organisation with its role (see [Invitations](#invitations)); answers `workspace_id`, `project_id`, `role`, `account_created` and `joined`, and the browser session then works in that organisation. 410: the link does not work; 409 `sign_in_required` or `wrong_account` |
| `POST /integrations/slack/actions` | none: Slack's signature (see [Acting from Slack](#acting-from-slack)) | Slack's interactivity Request URL. Form-encoded `payload` as Slack sends it, with `X-Slack-Request-Timestamp` and `X-Slack-Signature`. 200 once verified (the answer goes to Slack's `response_url`), 401 for any request that cannot be verified, is older than 5 minutes or was already received, 400 for a verified payload with an unexpected team, user or `response_url` |
| `GET /slack/links` | any signed-in user | The caller's linked Slack accounts in the current organisation (`team_id`, `team_name`, `slack_user_id`, `slack_user_name`, `created_at`, `last_used_at`) |
| `DELETE /slack/links/{id}` | any signed-in user | Unlink one of the caller's Slack accounts (404 for anyone else's). Audited as `slack_link.delete` |
| `POST /slack/links/preview` | a browser session | `{"token"}` from the link offered in Slack: the Slack account it would link, `linked_to_you`, `linked_to_other`, and `signed_in_as`. 410: the link was used, expired (15 minutes) or belongs to another organisation |
| `POST /slack/links/confirm` | a browser session | `{"token"}`: links that Slack account to the caller (single use). 410 as above; 409 when it is linked to another account, which has to unlink it first. API tokens get 403. Audited as `slack_link.create` |
| `GET /teams` | viewer | Teams |
| `POST`/`PATCH`/`DELETE /teams/{id}` | admin | Manage teams and members (members must belong to the workspace) |
| `GET`/`POST /users`, `PATCH /users/{id}` | admin | Manage users. `role` `none` keeps someone a member with no organisation-wide role (access through projects only); each user has `access`: `organisation` or `projects` |
| `GET /integrations`, `POST /integrations/{id}/run` | engineer | List integrations, trigger a run |
| `POST`/`PATCH`/`DELETE /integrations/{id}` | admin | Manage integrations |
| `GET /conflicts`, `POST /conflicts/{id}/resolve` | admin | Resolve asset identity conflicts by merging assets. The answer lists `projects_joined` and `grants_moved`, with a `notice`, when the kept asset joins the merged assets' projects or takes their access grants |
| `GET /jobs?state=` | admin | Background job queue |
| `GET /plugins` | admin | Installed plugins with their declared permissions, credentials and network access |
| `GET /jobs/{id}` | engineer | Status of one job, e.g. after *Run now* |
| `GET`/`POST /admin/workspaces`, `PATCH /admin/workspaces/{id}` | instance admin | Workspaces with `member_count`, `asset_count`, `monitored` and `asset_limit` (null: none). `PATCH` takes `name`, `disabled`, `plan` and `asset_limit` (`-1` removes the limit; see [asset-limits.md](asset-limits.md)) |
| `GET /admin/health` | instance admin | Platform health across workspaces: `status` (`ok`, `warning`, `critical`), `problems` (each with `last_success`, `last_error`, `scope`, `next_step` and `docs`; objects are named only for the caller's active workspace), background `tasks` with their last success and error, job counts by kind and state, jobs that failed in the last 24 hours, notification `deliveries` by channel kind and state, the age of the oldest due notification and `failing_channels` ([install.md](install.md#health)) |
| `GET /facets` | viewer | Distinct environments, asset kinds and component types |
| `GET /findings?status=&kind=&severity=&verification=&asset_id=&component_id=&environment=&known_exploited=&q=&key=&new_within=&resolved_within=&sort=` | viewer | Vulnerability and end-of-life findings, SOS, priority, known-exploited and most severe first. `new_within=N` keeps findings first seen in the last N days, `resolved_within=N` those resolved in the last N days (with `status=resolved`), and `sort=asset` orders by asset name first |
| `GET /findings/summary` | viewer | Counts by severity, kind, verification, priority and state, plus SOS, overdue, unassigned, stale feeds, evaluation gaps and `resolved_7d` (resolved in the last 7 days) |
| `GET /fix-groups?asset_id=&kind=&environment=&q=&bucket=` | viewer | Fixes (fix groups), most urgent first. `bucket` is `focus` (a fix exists, SOS or P1, on a production asset or one with no environment), `no_fix`, `old_kernels`, `non_production` or `lower_priority`; every group is in exactly one, checked in that order |
| `GET /fix-groups/summary?asset_id=` | viewer | Groups and findings per kind, plus `focus`: the number of focus groups and their findings, groups and findings per other bucket (`hidden`), and the assets with focus groups |
| `GET /fix-groups/{id}?limit=&offset=` | viewer | One fix group with its findings, paged |
| `POST /fix-groups/{id}/check` | engineer | [Check again](#check-again) the fix: asks the asset's agent (or a server-side scan) for a fresh report. 201 with the new check, or 200 with the check already waiting for a report |
| `POST /fix-groups/{id}/applied` | engineer | "I applied this": the fix's active issues go to `in_progress` with the reason "applied, waiting for a check", and a check is requested. Nothing is resolved by this call. Returns `updated` and `check` |
| `POST /assets/{id}/check` | engineer | Check the whole asset again |
| `GET /checks?asset_id=&fix_group=&open=true&limit=&offset=` | viewer | Checks, newest first; `open=true` keeps the ones not done |
| `GET /checks/{id}` | viewer | One check |
| `GET /findings/{id}` | viewer | One finding, with every source advisory in its group and, while it is open, its `upgrade` recommendation |
| `GET /findings/{id}/upgrade` | viewer | The [upgrade recommendation](#upgrade-recommendations) for the installed copy the finding is on, covering every open finding on it |
| `GET /findings/{id}/explain` | viewer | Why the finding matched (`why`, as in `GET /findings/{id}`) and why it has its priority: `risk` (priority, score, each factor with its points, `policy_version`: the risk policy that produced this priority, `current_policy_version` and `policy_changed`, the current thresholds, the SLA for the priority, deadlines), the stored `evidence`, the matched `advisories` (id, feed, severity, dates, an osv.dev link), the freshness of the `feeds` they came from, and the asset's last (complete) `collection` time |
| `GET /findings/verify?since=&asset_id=&limit=` | viewer | What changed since `since` (RFC 3339 time or `YYYY-MM-DD`): findings `resolved` since then with their `cause`, findings that existed then and are `still_open`, `opened_since`, and each asset's last complete collection. `asset_rescanned_since` tells "fixed" from "not scanned again yet". Lists are capped at `limit` (default 100, max 500) with a `total` |
| `GET /advisories/{id-or-CVE}` | viewer | Advisories in a group |
| `GET /components/{id}/intel` | viewer | Release data (latest stable, publish date, deprecation) and lifecycle cycles |
| `GET /feeds` | viewer | Intelligence feeds and their freshness |
| `POST /feeds/{name}/refresh` | engineer | Queue a manual refresh |
| `PATCH /feeds/{name}` | instance admin | Enable or disable a feed (feeds are shared by every workspace) |
| `GET /second-checks` | viewer | The independent second check of high-impact findings: open findings `agreed`, `disagreed` and `could_not_check`, `pending` (covered, not checked yet), `logged_30d` and the 50 latest logged disagreements with their differences and inputs. `GET /findings?second_check=disagreed` (or `agreed`, `could_not_check`) lists the findings; every finding carries `second_check` and `second_check_reason`, and `GET /findings/summary` counts `second_check_disagreed`. A disagreement never changes a finding's verification, priority, SOS or alerts. Narrowed to the caller's projects |
| `GET /evaluation-gaps` | viewer | Components that could not be evaluated, one entry per component and reason, with `coverage` (`unsupported` or `not_evaluated`) |
| `POST /evaluate` | engineer | Queue a full re-evaluation |
| `POST /findings/{id}/actions` | engineer (security for `suppress`, `accept_risk`, `ignore`, `reopen`) | Workflow action, see below |
| `POST /findings/actions` | as above | The same action on up to 500 findings (`ids`) |
| `GET /findings/{id}/events` | viewer | A finding's workflow history |
| `GET /incidents?status=&kind=&priority=&sos=&team_id=` | viewer | Incidents: findings grouped by issue and owner team |
| `GET /incidents/{id}` | viewer | An incident with its findings (and deliveries, for security and above) |
| `POST /incidents/{id}/actions` | as findings | Apply an action to every open finding in the incident |
| `POST /ignore-requests` | viewer | Ask to ignore issues: `finding_ids` (up to 2,000 open findings) or `fix_group` (its active issues), with `reason`, `scope`, `expiry`, `until`, `note` and `mitigation` as for the `ignore` action. Validated like an ignore; 201 with the request |
| `GET /ignore-requests?status=&limit=&offset=` | viewer | The approval inbox. `status` is `pending` (default), `approved`, `declined` or `all`. Security and admin users see every request; others see their own. `can_decide` says which |
| `GET /ignore-requests/{id}` | viewer | One request (its requester, or security and admin users) |
| `POST /ignore-requests/{id}/decision` | security | `{"decision": "approve" \| "decline", "note": "..."}`. Approval ignores the request's issues that are still open and active, as the decider; 409 when already decided |
| `GET /ignore-rules?status=all` | viewer | [Ignore rules](#ignore-rules) in force (or every one with `status=all`), with the open findings each ignores |
| `DELETE /ignore-rules/{id}` | security | End a rule: the open findings it ignores return to `new` |
| `GET /risk-policy` / `PUT /risk-policy` | viewer / admin | Priority weights, thresholds, deadlines and SOS rules, with the policy `version`. `PUT` replaces the policy (fields left out take their defaults; unknown fields are rejected), returns `version`, `previous_version` and the `changed` fields, and writes a `risk_policy.update` audit event holding the policy before and after. `GET` includes `last_change` (who, when, versions, changed fields; null when never changed) |
| `POST /risk-policy/preview` | admin | Validates a proposed policy like `PUT` and returns its effect on the workspace's open findings without saving anything: `before` / `after` counts per priority, `sos_before` / `sos_after`, `priority_changed` (`raised`, `lowered`), `sos_changed`, `score_changed`, `stored_differs`, and `sample` (at most `sample_limit`, 50) of changed findings with factor deltas ([risk.md](risk.md#reproducibility-and-audit)) |
| `GET /channels`, `GET /routes`, `GET /deliveries?status=&incident_id=` | security | Notification configuration and delivery log |
| `POST`/`PATCH`/`DELETE /channels/{id}`, `POST /channels/{id}/test` | admin | Email, Slack, Teams, webhook and Jira channels; for Jira, test checks access without creating an issue |
| `POST /routes`, `PUT`/`DELETE /routes/{id}` | admin | Which incidents go to which channel. `project_ids` limits a route to those projects' assets: its messages count and name only them, and only their collection and coverage problems. Not available for Jira channels (400) |
| `POST /deliveries/{id}/retry` | admin | Retry a failed or held delivery |
| `GET /users/directory` | engineer | Active users (id, email, name) for assignment. Members with project access only get themselves and the people granted one of their projects |
| `GET /remediation/policies` | security | Remediation policies |
| `POST /remediation/policies`, `PUT`/`DELETE /remediation/policies/{id}` | admin | Manage policies ([remediation.md](remediation.md)) |
| `POST /remediation/policies/preview?id=` | admin | Which fixable packages and assets a proposed policy would authorise or stop authorising, without saving ([remediation.md](remediation.md#previewing-a-policy-change)) |
| `GET /remediation/plans?status=`, `GET /remediation/plans/{id}` | viewer | Plans and their per-asset actions |
| `POST /remediation/plans/{id}/decision` | security (admin for major) | `{"decision": "approve" \| "reject" \| "cancel", "note": "..."}` |
| `GET /assets/{id}/remediation` | viewer | Remediation actions for an asset |
| `POST /assets/{id}/remediation-token` | admin | Collector token bound to this host, required for remediation |
| `GET /agent/actions`, `POST /agent/actions/{id}/report` | host-bound token | Agent fetches approved changes and reports results |
| `GET /agent/check?asset_id=` | collector, engineer | The agent's [check-again poll](#agent-poll): `{"check": true, "poll_seconds": 45}` when someone asked for a fresh report from one of the listed assets |
| `GET /remediation/renovate.json?repository=&mode=exclusive` | collector, engineer | Renovate rules for approved repository plans |

Inventory rows carry `coverage`, whether vulnerability intelligence covered
that row: `evaluated`, `stale_intelligence` (evaluated against a feed that is
stale or failing), `not_evaluated` or `unsupported` (with `coverage_reason`),
or `awaiting` (not evaluated yet). `coverage_feed` names the feed used and
`evaluated_at` when. The `coverage` filter takes one of these or `gaps`
(`not_evaluated` and `unsupported`). An evaluated row can carry a
`coverage_reason` too, saying how it is reported: kernel headers ("not
running code") and the other packages of a kernel version, whose findings are
on the kernel image ([compatibility.md](compatibility.md#kernels)).

`lifecycle_note` is set on a distribution package whose upstream release is
end of life: `status` is `distribution_supported` (no finding: the
distribution release still provides security updates), `distribution_ended`
(the release itself is end of life) or `third_party_build` (the finding
stands), with `text`, `subject`, `upstream_eol`, `distribution` and
`distribution_eol` ([compatibility.md](compatibility.md#lifecycle-of-distribution-packages)).

Lists return `{"items": [...], "total": N, "limit": L, "offset": O}`. Pass `?limit=` (max 500) and `?offset=`.

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

An issue that was fixed by an upgrade or a removal and comes back on the same asset (the same component and advisory, on the same or another inventory row) is **regressed**: `regressed_at` is set, the history gets a `regressed` event, work that was in progress goes back to `new`, and the issue is urgent in notifications whatever its priority. Two cases are not regressions: an upgrade that leaves the component vulnerable (the old and new versions overlap) and an issue closed only because the intelligence changed (resolution "no longer affected (re-evaluated ...)"), which reopens as before.

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

Package upgrade groups in the action plan (`GET /fix-groups`) carry `recommended_version`, `change_type`, `requires_major`, `recommended_yanked` and `rationale`; `to_version` stays the minimum fixed version. A group's `needs` (`ubuntu-pro`, `SUSE LTSS`) says a paid channel also publishes fixes for some of its findings; it is informational, and `action` is always the free path.

## Remediation outcomes

`GET /reports/outcomes` returns `days`, the risk `policy_version` and a `report`:

- `resolved`: findings resolved in the window that are still resolved.
- `time_to_remedy`: `mean_days` (MTTR) and `median_days` from detection, or from the last reopening, to resolution, by `priority` and `kind`; `all` rows are totals.
- `causes`: `upgraded` (a newer inventory shows another version), `remediation` (a verified remediation action), `removed` (a complete inventory no longer lists it), all with `evidence: fresh_collection`; `reevaluated` (advisory or lifecycle data changed, `evidence: intelligence`).
- `sla`: per priority, the policy's `fix_days`, findings resolved within that many days of first detection out of those resolved, and open and overdue counts now.
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
| `suppress` | `suppressed` | Security role ("Snooze" in the dashboard). `note` (reason) and `until` are required; `until` may be at most the risk policy's `exception_max_days` (default 365) ahead. Optional `mitigation` records what reduces the risk meanwhile. With `"until_fix": true` the issue is snoozed until a fix ships: `until` is optional and defaults to the exception limit as a backstop; refused when a free fixed version already exists |
| `accept_risk` | `risk_accepted` | Security role. Same fields and limit as `suppress`; sets `ignore_reason` `accepted_risk` |
| `ignore` | `risk_accepted` | Security role. See [Ignore rules](#ignore-rules): `reason`, `scope`, `expiry`, `until` (for `expiry: date`), `note` (required) and `mitigation` |
| `reopen` | `new` | Security role, from `suppressed` or `risk_accepted`. A finding reopened from an ignore rule is not ignored by that rule again |

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

Routes send to channels and filter by SOS only, kinds, environments and owner teams; `min_priority` is the urgent threshold. People get a few grouped messages that link to the dashboard, never one message per incident. A route's `mode` decides which:

| `mode` | Sends |
|---|---|
| `urgent_summary` (default) | urgent messages right away and a daily summary |
| `urgent_only` | urgent messages right away (with issues that came back, `connected` and, with `escalation`, `overdue` messages), no summary |
| `daily` | a daily summary only |
| `weekly` | a weekly summary only, on `summary_day` |

`summary_time` (`"HH:MM"`, default `09:00`) and quiet hours are in the route's `timezone`; `summary_day` is a weekday name (default `monday`). `last_summary_at` (read-only) is the end of the period the last summary covered. New routes default to `min_priority` `P1`.

The `event` of each message:

- `urgent`: at most one per route per evaluation cycle, only when the cycle produced new urgent issues for the route (at `min_priority` or above, SOS, or known exploited), or a problem with collection, feeds or the platform at that priority. Summarised per asset (up to 5, then "+N more") with up to 3 fixes each from **Fixes**.
- `summary`: daily or weekly at `summary_time`: new issues by asset, issues fixed (with the fix that closed them, when `send_resolved`), the top 3 fixes still open, overdue counts (when `escalation`, licensed), and open problems. Skipped when nothing changed. A summary is never held by `max_per_hour`.
- `overdue` (licensed, routes with `escalation`, `urgent_summary` or `urgent_only` mode): at most one per route per day, when urgent (P1 or SOS) issues have just passed their fix deadline; groups every overdue urgent issue by fix. Escalation levels (1: acknowledgement deadline passed, 2: fix deadline passed) are still recorded on incidents and findings.
- `connected`: when a new asset's first complete collection has been evaluated (or six hours after it appeared, if no complete collection arrives): "commmerceblog connected: 1,676 packages checked, 412 issues found, 3 fixes need you". See [A quiet first scan](#a-quiet-first-scan).
- `test`: **Send test**.

Resolved incidents are not announced; summaries count fixed issues. Quiet hours delay everything except SOS. When `max_per_hour` is reached, further messages are held and counted in the route's next summary, never sent one by one; a route in `urgent_only` mode, which has no summary, gets them in one `digest` message an hour instead ("Stackurity: 4 urgent messages held by the hourly limit", one line per held message). Failed deliveries are retried with backoff up to 8 times, no sooner than a receiver's `Retry-After`. A delivery that cannot succeed until the configuration changes (Jira rejecting the credentials, an unknown project) fails at once.

Jira channels (`"kind": "jira"`) keep one issue per incident instead, whatever the route's `mode`: the first matching event (`opened`, `priority_raised`) creates the issue, later changes are queued as `updated` deliveries (findings joined or left, priority changed), `escalated` for routes marked `escalation` (one comment per issue) and `resolved`. Quiet hours, limits and summaries do not apply to them. Incidents in lists and in `GET /incidents/{id}` carry the issues that follow them:

```json
"issues": [{"tracker": "jira", "key": "SEC-42", "url": "https://acme.atlassian.net/browse/SEC-42", "channel_id": 7}]
```

`channel_id` is `null` once the channel is deleted; the link is kept.

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
- `counts` keys: `urgent`, `assets`, `problems`, `regressed` (urgent); `new`, `new_urgent`, `fixed`, `connected`, `connected_issues`, `regressed`, `open_fixes`, `overdue`, `overdue_urgent`, `ack_overdue`, `problems`, `held` (summary); `overdue_urgent`, `fixes` (overdue); `assets`, `issues` (connected).
- Each fix in a message (an item whose `link` is `/fixes/{id}`) has `actions`: `[{"kind": "assign", "label": "Assign to me", "link": ".../fixes/{id}?action=assign"}, {"kind": "snooze", ...}, {"kind": "open", ...}]`. Each action also carries `fix`, the fix group id. Slack shows them as URL buttons (on up to 8 items per message), email and Teams as links. They open the fix in the dashboard with the action ready; the person confirms it there after signing in. Following a link changes nothing. On a Slack channel with a signing secret, Assign to me and Snooze 1 week act from inside Slack instead (see [Acting from Slack](#acting-from-slack)).
- A route limited to projects (`project_ids`) opens every link in its project (`?project=N`): its only project, or for a route on several the first of them the item's asset is in.
- Issues that came back after a fix are urgent whatever their priority: the next urgent message on routes in **Urgent right away + daily summary** or **Urgent only** mode lists them per asset ("web-1: 3 issues came back after a fix"), once, and summaries count them in their own section rather than as new issues.
- Summaries also carry `"period": {"from": "...", "to": "..."}`.

### Acting from Slack

A Slack channel whose `config` has `signing_secret_ref` (a secret reference such as `secret:SLACK_SIGNING` to a Slack app's signing secret) gets interactive buttons: **Assign to me** and **Snooze 1 week** act from inside Slack, **Open** stays a link. Without it the message is exactly as described above. The channel's incoming webhook must belong to the same Slack app, whose Interactivity Request URL is `https://<your server>/api/v1/integrations/slack/actions` (setup: [install.md](install.md#acting-from-slack)).

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
