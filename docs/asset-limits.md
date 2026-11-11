# Monitored-asset limits, project limits, read-only and trial reports

An instance administrator can limit how many assets each organisation (workspace) monitors and how many projects it has, make an organisation read-only, and shorten its reports. A self-hosted installation has none of this unless an administrator sets it: every limit is unset (unlimited), no organisation is read-only and reports are complete. Nothing in Stackurity sets them on its own; a hosted service sets them from each organisation's plan.

The monitored-asset limit is described first; [project limits](#project-limits), [read-only organisations](#read-only-organisations) and [trial reports](#trial-reports) follow it and work the same way.

A limit never stops monitoring. At the limit, Stackurity refuses **new** assets only. Every asset already monitored keeps being collected, evaluated and alerted on, whatever happens to the limit afterwards.

## What counts as a monitored asset

An asset of the organisation that has not been merged into another, of one of these kinds:

| Kind | Counted | Notes |
| --- | --- | --- |
| `host` | yes | A server or VM with the agent, or reported by a collector |
| `application` | yes | A deployed application, including one created by an SBOM upload with an application name |
| `repository` | yes | A Git repository: from a Git integration or a CI scan |
| `image` | yes | A container image: from an image integration, an image scan, or found running by the Kubernetes plugin |
| `cluster` | yes | A Kubernetes cluster |
| `managed_service` | yes | A cloud service such as a managed database |
| `sbom` | yes | A standalone SBOM import |
| `workload` | **no** | A Kubernetes workload is described by its cluster and the images it runs. With a limit set, a new workload is added only when its cluster is already monitored |

- Stale assets (not seen recently) count until they are deleted. Delete assets you no longer run to make room.
- Merging two assets that are the same machine frees one place.
- Assets created before a limit was set all stay, even when there are more of them than the limit.

## What happens at the limit

| Where a new asset would come from | At the limit |
| --- | --- |
| Agent or collector upload (`POST /ingest`), CI scans, image scans | `402` with code `asset_limit`; the agent and the CLI show the message and do not retry |
| SBOM import (`POST /sbom/import`) | `402 asset_limit` |
| Enrollment codes | A new code cannot be made (`POST /enrollments`); an existing code cannot be redeemed and is not used up, so it works once there is room |
| Integrations (Git repositories, images, plugins such as Kubernetes) | A new integration cannot be made. A scheduled run keeps updating the assets it already monitors; new ones are left out and the integration shows how many and why. The run is not retried |

The message says how many assets the organisation monitors and its limit, for example: *this organisation monitors 5 of 5 assets allowed, so the new host "web-9" was not added. Assets already monitored keep being checked.*

Every refused asset is remembered (kind, name, which collector sent it, how many attempts, when) so admins can see what is waiting; the most recent 200 are kept.

## In the dashboard

- A banner tells everyone in the organisation when it is at its limit, with a link for admins.
- **Settings → Usage** (admins) shows monitored assets against the limit, by kind, how many are stale, workloads (not counted), and the assets refused recently.
- **Admin → Workspaces** (instance administrators) shows each organisation's usage and sets its limit.

## Setting a limit

Instance administrators set the limit under **Admin → Workspaces**, or with the API:

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"asset_limit": 50}'      # -1 removes the limit
```

`GET /api/v1/usage` (any organisation-wide role) returns `monitored`, `limit` (null for none), `at_limit`, `by_kind`, `stale`, `workloads`, `refused` and `refused_recently`.

## How it is enforced

Every path that creates an asset goes through one place in the store, which runs in the same database transaction as the new asset. With a limit set, it takes a per-organisation lock, counts the monitored assets and refuses when the count has reached the limit, so collectors racing for the last place cannot go over it. The count ignores project narrowing, so a member who works in one project still counts the whole organisation. Organisations without a limit skip the check entirely.

## Project limits

`project_limit` caps the active (not archived) projects of an organisation. Unset means no limit.

- At the limit, creating a project, or taking one out of the archive, answers `402` with code `project_limit`: *this organisation has 3 of 3 projects allowed, so no new project can be made. Existing projects are kept.*
- A lower limit never archives or deletes a project: an organisation with more projects than its limit keeps them all, and only new ones are refused. Archiving a project makes room.
- Checked in the transaction that adds the project, under a per-organisation lock, so two admins cannot both take the last place.
- **Settings → Usage** shows projects against the limit, and **Admin → Workspaces** shows and sets it.

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"project_limit": 3}'    # -1 removes the limit
```

## Read-only organisations

A read-only organisation keeps everything it has and can be used to look at it, but nothing new comes in and nothing goes out:

| | While read-only |
| --- | --- |
| Signing in, viewing, searching, reports, exports | Work |
| Settings (people, projects, deleting assets) | Work |
| Uploads of any kind (`POST /ingest`, `POST /sbom/import`, CI scans, image scans), for new and existing assets | `402` with code `read_only` and the reason; the agent and the CLI show it and do not retry |
| Enrollment | No new codes (`POST /enrollments`); an existing code is not redeemed and not used up |
| Integrations | No new ones, no runs (`POST /integrations`, `POST /integrations/{id}/run`); scheduled runs stop |
| Checking again (`POST /assets/{id}/check`, `POST /fix-groups/{id}/check`), `POST /evaluate` | `402 read_only` |
| Notifications | None are sent: the alert and digest tasks skip the organisation, and testing a channel or retrying a delivery answers `402 read_only` |
| Background evaluation | Stops: daily and feed-triggered evaluations and the second check skip the organisation, so its findings stay as they were |

Every member sees a banner with the reason (and admins of a hosted service a link to Plan and billing). Assets go stale as they stop reporting, which is the truth.

The state is `read_only_at` (when it started; kept when it is set again, so it measures how long the organisation has been read-only) and `read_only_reason`, shown to members:

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"read_only": true, "read_only_reason": "Paused while the contract is renewed."}'   # false: writable again
```

Uploads are refused in the store, where every path that collects goes through, so a new route cannot forget the check.

## Plan limits

`plan_limits` caps how many rules of each kind, and how many members, an organisation may have, which kinds of notification channel it may add, and whether projects over its project limit are read-only. Unset (`{}`, the default) means no limit: a self-hosted installation has none unless an instance administrator sets them, and a hosted service sets them from each organisation's plan.

| Field | Limits |
| --- | --- |
| `rule_limits.alert_rules` | Notification rules: the organisation's, a project's and an asset's own, and a project's or asset's edited copy of an inherited rule. Turning an inherited rule off for a project or asset does not count |
| `rule_limits.channels` | Notification channels, the organisation's, projects' and assets' together, including those made by Add to Slack and Add to Teams |
| `rule_limits.owner_rules`, `ci_trusts`, `vex_sources`, `teams` | Owner rules, CI trusts, VEX sources, teams |
| `rule_limits.api_tokens` | API tokens people make (not revoked, not expired). Agents', enrollment and CI tokens are not counted |
| `max_members` | Members plus pending invitations. Accepting an invitation already sent is not refused, and inviting the same address again takes no new place |
| `allowed_channel_kinds` | The kinds of channel that can be added: `stackurity_email`, `email`, `slack_app` (Add to Slack), `slack` (webhook), `teams_app`, `teams`, `webhook`, `jira`, `pagerduty`, `servicenow`. Left out: every kind |
| `over_limit_read_only` | Projects beyond `project_limit` (the newest, by creation) are read-only: an asset that is only in such projects collects nothing new (`402 read_only`, naming the projects), and can still be viewed and alerted on for what is already known. Assets in an active project, and assets in no project, are not affected. Without it, a lower project limit keeps every project collecting, as before |
| `check_again_cooldown_seconds` | How long after a Check again on an asset (or one of its fixes) the next may be asked for: `429` with code `check_cooldown`, `Retry-After` and `retry_at` in the details. A check still waiting for its report answers as before; "I applied this", scheduled checks and agent reports are not held to it |
| `api_requests_per_hour` | People's and API tokens' requests to the organisation an hour, counted across replicas: `429 rate_limited` with `Retry-After` when used up. What agents and CI send (uploads, SBOM imports, enrollment, the agent's own endpoints, CI tokens) and anything a collector token does is not counted |
| `sbom_imports_per_month` | SBOM imports (`POST /sbom/import`) a calendar month (UTC): `402 plan_limit` when used up; a failed import gives its place back |
| `history_days` | How far back people's lists go: issues and incidents resolved, and software removed, before it are not shown in the dashboard, the API's lists or the outcomes report (which starts no earlier). Nothing is deleted, open issues and current software are always shown, and lifting the limit shows everything at once. Background work (evaluation, notifications) is not affected |
| `inactive_pause_days` | When nobody in the organisation has signed in for that many days, its administrators are emailed 15 and 5 days before, then it is paused: nothing new is collected and no notifications are sent (as read-only, with its own reason), everything is kept, and the next sign-in by any member resumes it at once. An organisation already idle longer when the limit is set still gets both warnings first. 20 days or more |
| `plan`, `next_plan` | The plan's name, and the plan a refusal tells people to upgrade to |

A kind left out of `rule_limits` is unlimited. At a limit, only new ones are refused, with `402` and code `plan_limit`: *your plan allows 3 alert rules, and this organisation has 3, so no new one can be added: the ones you have keep working, and can be changed or deleted. Upgrade to Starter for more.* A channel of a kind the plan does not include is refused the same way. Nothing is deleted or switched off when a limit is lowered.

The limits are enforced by the database (a trigger on each table, under a per-organisation lock), so every path that adds a row is held to them, including the Slack and Teams installs, accepting an invitation, a new account given access to a project, and a project's copy of an inherited rule. Add to Slack and Add to Teams check before sending anyone to Slack or Teams.

**Settings → Usage** shows each limit against what is used, the channels the plan includes and the read-only projects; the page where each kind is added (Integrations, Teams, API tokens, Owners, CI, VEX, Users) shows "2 of 3 used", and at the limit what still works and the plan to upgrade to. Read-only projects say so on the Projects page.

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"plan_limits": {"plan": "Free", "next_plan": "Starter", "max_members": 2,
       "rule_limits": {"alert_rules": 3, "channels": 2, "teams": 1},
       "allowed_channel_kinds": ["stackurity_email", "slack_app"], "over_limit_read_only": true}}'   # {} removes them
```

## Trial reports

`report_mode` is `full` (the default) or `trial`. In trial mode reports and exports are shortened and watermarked, not refused:

- **Evidence report** (`GET /reports/evidence`, licensed build), **outcomes report** (`GET /reports/outcomes`): every list of rows (exceptions, replica drift, reopened findings, failed remediation actions, and the outcomes executive summary's overdue issues and owners) keeps its first 10 rows. Summary counts stay complete. The answer carries `trial`: `watermark`, `rows_per_list`, `omitted` (rows left out, per list) and `notes` ("exceptions: trial: 5 more not shown").
- **SBOM export** (`GET /assets/{id}/sbom`): the first 10 components, with metadata properties `stackurity:report_mode` = `trial`, `stackurity:watermark` and `stackurity:trial_note`, and the header `X-Stackurity-Report-Mode: trial`.
- The dashboard shows the watermark as a banner on report pages (also when printed), and under each shortened list how many more there are. The JSON a report page downloads is the API's answer, watermark included.

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"report_mode": "trial"}'   # or "full"
```

`GET /api/v1/usage` also returns `projects`, `project_limit`, `projects_at_limit`, `read_only` (`since` and `reason`, or null), `report_mode` and `plan` (the plan limits and their use, or null); `GET /api/v1/auth/me` returns `read_only` and `report_mode` with the workspace, for every member.
