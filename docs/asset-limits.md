# Monitored-asset limits

An instance administrator can limit how many assets each organisation (workspace) monitors. A self-hosted installation has no limit unless one is set; a hosted service sets limits from each organisation's plan.

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
