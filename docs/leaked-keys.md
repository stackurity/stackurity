# Leaked keys

## Alerts

Open critical and high leaks raise one incident per asset (kind `leak`): `P1` when one is critical, otherwise `P2`. The incident is sent where new issues go right away (a route's **Urgent** and **New issues** triggers, at their priority thresholds), not with problems about Stackurity itself, and it follows the route's projects, owner teams and environments like any issue. It resolves when no critical or high leak is open on the asset, after a complete scan no longer sees them or they are dismissed.

Low and medium leaks never alert. On a server they are mostly keys kept in the application's configuration file, where they belong: the dashboard lists them under **Where keys are kept**, apart from the leaks that need action.

The message names the kind of key, the file and line, and one line saying why it matters and what to do (the same line the dashboard, the API's `why` and MCP's `list_leaks` show):

| Where the key is | What the line says |
|---|---|
| A file the web server may send (`served`) | Rotate the key and move the file out of the document root |
| A repository | Everyone with access to it, and every clone, has the key; rotate it, as deleting the file does not remove it from history |
| A container image | Anyone who can pull the image has it; rotate it and pass it to the container when it starts |
| A file every account on the server can read (`world_readable`) | Restrict it to the application's user (`chmod 640`) |
| The application's code | It is in its repository too; move it to configuration and rotate it |
| The application's configuration file | Listed so you know where the key lives when you rotate it |

The fix for a leaked key is always to rotate it: revoke it and issue a new one. Removing it from the file does not undo the leak. The value is never sent to the server, stored or shown: a leak holds the file, the line, the setting's name, a fingerprint (a slow salted hash, so the same key in two places is recognised) and a masked preview such as `sk_live_…4f2a`.

## Dismissing a leak

People with the security role (on the asset, with a project grant) can dismiss a leak: a test key kept on purpose, or one already rotated. Add a note saying which. A dismissed leak stays dismissed whatever later scans see, and can be opened again. Dismissing and opening again are recorded in the activity log.

A leak a complete scan no longer sees is resolved as gone, and opens again if a later scan sees it. A scan that could not read everything (the scan's limits, unreadable files) resolves nothing; the asset's **Leaked keys** tab says the scan was incomplete and why. An asset never scanned for keys says so, rather than showing no leaks.

## API and MCP

- [`GET /leaks`](api.md#get-leaks): leaked keys across the organisation, filterable by `status`, `severity` (comma-separated, e.g. `critical,high`) and `asset_id`.
- [`GET /assets/{id}/leaks`](api.md#get-assetsidleaks): one asset's, with its last key scans.
- [`POST /leaks/{id}/dismiss`](api.md#post-leaksiddismiss) and [`POST /leaks/{id}/undismiss`](api.md#post-leaksidundismiss).
- `list_leaks` for AI assistants ([AI assistants](ai-assistants.md)), read-only.

Collectors send leaks in the batch's `leaks` field ([ObservationBatch](api.md#observationbatch)), only to servers whose `GET /meta` lists the `leaks` feature.
