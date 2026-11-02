# Connect Jira (the Stackurity Atlassian app)

With an Atlassian OAuth 2.0 app configured on the server, people connect Jira Cloud in one click: **Settings → Integrations → Jira → Connect Jira**, approve on Atlassian's page, and they are back in Stackurity choosing the site, project, issue type and the status that means done from lists read from their Jira. Nobody creates an API token, types a site address or an account email, or pastes anything.

Stackurity Cloud has this app. On your own server it is optional: without it, Jira integrations use an API token (Jira Cloud) or a personal access token (Jira Data Center and Server) as before, and **Connect Jira** is hidden. Jira Data Center and Server have no OAuth 2.0 (3LO); they always use a personal access token. Where the app is configured, new Jira integrations default to Connect Jira, and **Use an API token instead** is always there.

## What the app asks for

Scopes (classic): **`read:jira-work`** and **`write:jira-work`**, and **`offline_access`** for a refresh token. That is what the issue lifecycle and the setup lists need:

| Call | Scope |
|---|---|
| list projects (`/project/search`), read a project and its issue types (`/project/{key}`), statuses (`/project/{key}/statuses`), priorities (`/priority`) | `read:jira-work` |
| find the incident's issue by its label (`/search/jql`), read comments and transitions | `read:jira-work` |
| create the issue, comment, set its priority, transition it | `write:jira-work` |

Not `read:jira-user`: with Connect Jira, **Send test** checks access by reading the project instead of `/myself`. The app stores no Atlassian account ids or personal data: the connection keeps the sites it reaches (cloud id, name, address) and the tokens.

Every call goes to `https://api.atlassian.com/ex/jira/{cloudid}/rest/api/3/...` with the connection's access token. Issue links still point at the site (`https://<site>.atlassian.net/browse/SEC-1`).

## How it works

1. **Connect Jira** (`POST /api/v1/integrations/jira/install`, admins) stores a random state, only its SHA-256, bound to the organisation and the person (and to the connection, for **Reconnect**), valid once for 10 minutes, and sends the browser to Atlassian's consent page (`https://auth.atlassian.com/authorize`, `prompt=consent`).
2. Atlassian sends the browser back to `/integrations/jira/oauth/callback?code=...&state=...`. That dashboard page, in the signed-in session, posts the code and state to `POST /api/v1/integrations/jira/oauth`. A state that is unknown, used, expired, another person's or another organisation's is refused before Atlassian is called.
3. The server exchanges the code (`https://auth.atlassian.com/oauth/token`, with the client ID and secret) and reads the Jira sites the grant reaches (`https://api.atlassian.com/oauth/token/accessible-resources`). Sites of other products, and entries without an HTTPS address, are left out.
4. The access and refresh tokens are sealed (AES-GCM with `STACKURITY_SECRET_KEY`, bound to the organisation and the connection, like stored secrets) in `jira_connections`. They are never returned by the API or shown in the dashboard, and they are not workspace secrets, so no other integration can be pointed at them. **Connect Jira needs `STACKURITY_SECRET_KEY`.**
5. The administrator picks a site, a project, an issue type, optionally the status the issue moves to when the incident resolves, and Jira priorities, from lists read with the connection. The integration stores the connection id and the site's cloud id; its address is taken from the site.

### Tokens

An access token lasts about an hour. Before it expires, the server refreshes it. Atlassian rotates refresh tokens: each refresh returns a new refresh token and disables the old one. So a refresh holds the connection's row lock from reading the refresh token until the new access and refresh tokens are stored together; another worker or replica that needs a token at the same time waits, then uses the new one instead of spending the old refresh token again. A token Jira refuses before it expires is refreshed once and the request retried.

When Atlassian refuses the refresh token (`invalid_grant`: the person removed the app from their Atlassian account, it went 90 days unused, or their password changed), the connection is marked **Reconnect needed**, its Jira integrations show the reason as their last error, and deliveries fail at once with that reason in the delivery log instead of retrying. **Reconnect** on the integration runs Connect Jira again for the same connection; failed deliveries can then be retried. An outage at Atlassian (a network error, HTTP 5xx or 429) is retried like any delivery and does not mark the connection.

### Disconnecting

**Disconnect** on the integration (or `DELETE /api/v1/integrations/jira/connections/{id}`) deletes the connection and its tokens; the Jira integrations that used it are switched off with a note. Atlassian offers no API to revoke a 3LO grant, so the dashboard links to [id.atlassian.com/manage-profile/apps](https://id.atlassian.com/manage-profile/apps), where the person who connected it removes **Stackurity** from their account.

One issue per incident is kept exactly as with an API token ([Jira](install.md#jira)): the creation is claimed in the database, and the label `stackurity-incident-<workspace>-<incident>` is searched for before creating. Only the authentication differs.

## Create the app

1. At [developer.atlassian.com/console/myapps](https://developer.atlassian.com/console/myapps), **Create → OAuth 2.0 integration**, name it **Stackurity**, accept the terms, **Create**.
2. **Permissions → Jira API → Add**, then **Configure → Edit Scopes** (classic scopes): tick **View Jira issue data** (`read:jira-work`) and **Create and manage issues** (`write:jira-work`). **Save**. (`offline_access` is not listed there; Stackurity asks for it on the consent page.)
3. **Authorization → OAuth 2.0 (3LO) → Configure**: **Callback URL** `https://<your server>/integrations/jira/oauth/callback` (your `STACKURITY_BASE_URL`; on Stackurity Cloud, `https://app.stackurity.dev/integrations/jira/oauth/callback`). **Save changes**.
4. **Settings**: copy the **Client ID** and **Secret**.
5. Give them to the server and restart it:

   | Variable | Value |
   |---|---|
   | `STACKURITY_JIRA_CLIENT_ID` (or `_FILE`) | Client ID |
   | `STACKURITY_JIRA_CLIENT_SECRET` (or `_FILE`, a file holding it) | Secret |

   Both, or neither: setting only one stops the server at start with a message. `STACKURITY_BASE_URL` and `STACKURITY_SECRET_KEY` must be set. The start-up log prints the callback URL and the scopes.
6. **Distribution**: until it is shared, only the app's owner can connect it. To let other Atlassian organisations connect (needed for a service like Stackurity Cloud), **Distribution → Edit**, **Sharing**, fill in the vendor and privacy policy, and answer the personal data question (the app stores no personal data: no account ids).
7. In Stackurity, **Settings → Integrations → Jira → Connect Jira**, **Accept** on Atlassian's page, pick the site, project and issue type, **Add integration**, then **Send test**.

To rotate the secret, generate a new one in the app's **Settings**, update the variable and restart. Connections keep working: their refresh tokens are not tied to the secret.

The server connects to `auth.atlassian.com` and `api.atlassian.com` only when the app is configured and someone connects Jira ([network.md](network.md)). Requests go through the same outbound guard as other integrations and never follow redirects.
