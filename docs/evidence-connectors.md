# Compliance evidence connectors: Vanta and Drata

Stackurity can send its vulnerability-management evidence to the compliance platform you already use, so the controls there stay current without anyone exporting a report. It supplies evidence to Vanta and Drata; it does not replace them, and it changes nothing in your estate.

Set up under **Integrations → Compliance evidence** (organisation admins). The connectors are part of the **Compliance add-on** (available on any paid plan, included in Enterprise) and exist only in the licensed build. Without the add-on the card shows what it would do and how to get it, and nothing is sent. In the Community build the routes are not served, even with a licence.

## What is sent, and when

Everything comes from one place: the evidence pack for the last 30 days, the same data as the [evidence report](api.md#evidence-report). Nothing is built separately for a vendor, so the numbers in Vanta or Drata match those in Stackurity.

| Data | Vanta | Drata |
|---|---|---|
| The assets Stackurity monitors (servers, repositories, images, applications) | Vulnerable components (`PUT /v1/resources/vulnerable_component`) | The custom connection's `assets` resource |
| Open vulnerabilities, with package, version, severity, CVE and fix | Package vulnerabilities (`PUT /v1/resources/package_vulnerability_connectors`) | The custom connection's `vulnerabilities` resource, with priority, fix-by date and SLA status (`within`, `overdue` or `no_deadline`), first seen, known exploited and end of life |
| The evidence file (`stackurity-evidence-YYYY-MM-DD.json`, the evidence pack: monitoring coverage, open findings with SLA status, time to fix against your policy, exceptions and closures) | Uploaded to the Vanta document you choose, then submitted | Added to one evidence item, "Stackurity vulnerability management evidence", renewed monthly |

- **When.** Every day by default; each connection can sync every 6 hours, every 12 hours, every day or every week. **Sync now** queues one at once (at most once every 5 minutes). The first sync starts a few minutes after connecting.
- **Full replace.** Each sync sends the complete set and replaces what Stackurity sent before, so a fixed vulnerability or a removed asset disappears from the vendor at the next sync. A sync that fails replaces nothing.
- **SLA status.** Vanta has no field for a deadline or SLA status. For Vanta, fix-by dates, whether each vulnerability is within its deadline, and the share fixed within the deadline travel in the evidence file only. Drata's custom resource carries them on each vulnerability as well.
- **What is never sent.** No credentials, tokens or secret values, no source code, and nothing from another organisation.
- **History.** Each sync is recorded with its counts and any error (the newest 50 per connection, under **Recent syncs**).
- **Pause and Disconnect.** Pausing stops the schedule and keeps the connection. Disconnecting deletes the stored tokens or key; for Vanta the server first asks Vanta to suspend the token. What was already sent stays in the vendor until you remove it there.

## Vanta

An administrator picks the Vanta region (United States, Europe or Australia), chooses **Connect Vanta**, approves on Vanta's page and comes back to Stackurity. Then they choose the Vanta document the evidence file goes to. Until a document is chosen, only the assets and vulnerabilities are sent.

- **OAuth 2.0.** Stackurity is a Vanta partner app: the authorisation code is exchanged at once (Vanta's codes expire after 30 seconds), and the access token (one hour) is refreshed when needed. Tokens are sealed with `STACKURITY_SECRET_KEY`, bound to the organisation and the connection, and never returned by the API or shown in the dashboard.
- **Scopes:** `connectors.self:write-resource connectors.self:read-resource self:write-document self:read-document`.
- **Rate.** Vanta allows about 10 requests a minute per token and sends no `Retry-After`, so requests are spaced at least 6 seconds apart, with a back-off on HTTP 429.
- **Reconnect needed.** When Vanta refuses the refresh token, the connection shows **Reconnect needed** with the reason, and syncs stop until someone chooses **Reconnect Vanta**.
- When the operator has not registered the Vanta app, the row says **Not set up on this server**.

### Setting up the Vanta app (operators)

Stackurity Cloud has the app. On your own server:

1. Register an application in Vanta's developer portal as a partner integration, with the redirect URI `https://<your server>/api/v1/auth/vanta/callback` (the server's `STACKURITY_BASE_URL` with that path) and the scopes above.
2. Set `STACKURITY_VANTA_CLIENT_ID` / `_FILE` and `STACKURITY_VANTA_CLIENT_SECRET` / `_FILE` (the `_FILE` form names a file holding the value), with `STACKURITY_BASE_URL` and `STACKURITY_SECRET_KEY`, and restart.
3. Set the resource ids Vanta assigns to the app's resource types: `STACKURITY_VANTA_COMPONENT_RESOURCE_ID` / `_FILE` (vulnerable components) and `STACKURITY_VANTA_VULNERABILITY_RESOURCE_ID` / `_FILE` (package vulnerabilities). A connection's own settings can override them.

Both or neither: neither set means Vanta is not available on this server; only one set stops the server with a configuration error.

## Drata

An administrator creates an API key in Drata (with access to custom connections and evidence), then in Stackurity enters the key, the Drata region (United States, Europe or Asia Pacific) and the Drata workspace ID, and chooses **Connect Drata**.

- **"Custom Connections and Tests" must be enabled** on the Drata account. Without it Drata refuses the custom connection and the sync fails with that reason.
- The key is checked with one read call (`GET /workspaces`) before it is saved; a key Drata refuses is not stored, and the form says why (HTTP 401: the key is wrong or revoked; 403: it lacks a permission). The key is sealed with `STACKURITY_SECRET_KEY` and never shown again; the field starts empty when reconnecting.
- On the first sync Stackurity creates a custom connection called "Stackurity" with two resources, `assets` and `vulnerabilities`, and remembers their ids. Each sync replaces the data through an upload session (at most 500 records per request) that is completed at the end, or cancelled on an error so Drata keeps the previous data.
- Drata allows 500 requests a minute per key; a sync uses a handful.
- Drata needs no setting from the operator.

## Network

Each request goes through the server's outbound guard with a new connection, no proxy from the environment and no redirects ([network.md](network.md#compliance-evidence-connectors)). They are made only for an organisation that connected a vendor; a server with no connection makes none.

## Not confirmed yet

These parts follow the vendors' public documentation but have not been tried against a real account. They are kept in one place each in the code so they are easy to correct:

- Vanta: whether a partner app may call the documents API (upload and submit). If Vanta answers 403, the sync records "Vanta did not allow the evidence upload" and still counts the assets and vulnerabilities (status **partial**).
- Vanta: the `resourceId` of each resource type, which comes from the partner app's set-up.
- Drata: the exact body for creating a custom connection, how an upload session's id is made (Stackurity generates a UUID), and the shape of the evidence-file upload answer (`fileKey`).
- Drata: where its dashboard shows the API keys page and the workspace ID.
