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
- **Settings → Workspaces** (instance administrators) shows each organisation's usage and sets its limit.

## Setting a limit

Instance administrators set the limit under **Settings → Workspaces**, or with the API:

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
- **Settings → Usage** shows projects against the limit, and **Settings → Workspaces** shows and sets it.

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

## Trial reports

`report_mode` is `full` (the default) or `trial`. In trial mode reports and exports are shortened and watermarked, not refused:

- **Evidence report** (`GET /reports/evidence`, licensed build), **outcomes report** (`GET /reports/outcomes`): every list of rows (exceptions, replica drift, reopened findings, failed remediation actions) keeps its first 10 rows. Summary counts stay complete. The answer carries `trial`: `watermark`, `rows_per_list`, `omitted` (rows left out, per list) and `notes` ("exceptions: trial: 5 more not shown").
- **SBOM export** (`GET /assets/{id}/sbom`): the first 10 components, with metadata properties `stackurity:report_mode` = `trial`, `stackurity:watermark` and `stackurity:trial_note`, and the header `X-Stackurity-Report-Mode: trial`.
- The dashboard shows the watermark as a banner on report pages (also when printed), and under each shortened list how many more there are. The JSON a report page downloads is the API's answer, watermark included.

```sh
curl -X PATCH https://stackurity.example/api/v1/admin/workspaces/2 \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"report_mode": "trial"}'   # or "full"
```

`GET /api/v1/usage` also returns `projects`, `project_limit`, `projects_at_limit`, `read_only` (`since` and `reason`, or null) and `report_mode`; `GET /api/v1/auth/me` returns `read_only` and `report_mode` with the workspace, for every member.
