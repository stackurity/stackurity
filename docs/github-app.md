# The Stackurity GitHub App ("Install on GitHub")

With a GitHub App configured on the server, people cover their repositories in one click: **Settings → Integrations → Git repository → Install on GitHub**, pick the repositories on GitHub's own install screen, and the first results arrive within minutes. Nobody creates, pastes or renews a personal access token, and no CI step is needed.

Stackurity Cloud has this app. On your own server it is optional: without it, **Install on GitHub** is hidden and repositories are covered as before, by a [Git integration](install.md#repositories) with a read-only token, or by `stackurity scan` in CI. All three put a repository on the same asset (its `git-url` identity), so they can be mixed.

It is part of Stackurity Community (the core), like the Git integration it builds on: collecting inventory is free ([open core](design/open-core.md)).

## What the app asks for

- **Repository permissions: Contents (read-only) and Metadata (read-only).** Nothing else: the app cannot write to a repository, open issues or pull requests, or read anything outside the repositories the customer grants.
- **Events: `push`**, to rescan when a lockfile changes. GitHub also sends every app its `installation` and `installation_repositories` events (installed, suspended, uninstalled, repositories added or removed); no subscription is needed for those.
- **Request user authorization (OAuth) during installation**, used once at install to prove the person can see the installation (below). The user token is revoked straight away and never stored.

## How it works

1. **Install on GitHub** (`POST /api/v1/integrations/github/install`, admins) stores a random state, only its SHA-256, bound to the organisation and the person, valid once for 10 minutes, and sends the browser to the app's install page on GitHub. There the person picks the GitHub account or organisation and **All repositories** or **Only select repositories**.
2. GitHub sends the browser back to `/integrations/github/callback?code=...&installation_id=...&state=...`. That dashboard page, in the signed-in session, posts them to `POST /api/v1/integrations/github/setup`. A state that is unknown, used, expired, another person's or another organisation's is refused before GitHub is called.
3. **The `installation_id` in the address is not trusted.** Anyone can type another organisation's number into it. The server exchanges the code for the person's GitHub user token and checks that GitHub lists that installation of this app among the ones they can see (`GET /user/installations`), then reads the installation with the app's own JWT (`GET /app/installations/{id}`). The user token is then revoked. An installation the person cannot see on GitHub is refused (403) and audited as `github_app.refused`.
4. **An installation belongs to one organisation.** Binding one that another Stackurity organisation already holds is refused (409), whoever asks; the other organisation is not named. To move it, disconnect it there (or uninstall the app on GitHub) first.
5. The server lists the repositories the installation grants and makes one integration per repository (kind `github_app`, named `owner/repository`), then queues their first scans, 15 seconds apart for each installation, so a 500-repository organisation does not hold up everyone else's work.
6. **Each scan** signs a JWT with the app's private key (RS256, valid 9 minutes), mints an installation token for that one repository with `contents: read` and `metadata: read` (`POST /app/installations/{id}/access_tokens`), and makes the same hardened shallow clone as a Git integration: HTTPS only, no hooks, submodules, LFS or scripts, a size and time limit, and the clone deleted afterwards. The token is passed to git in its environment, never on the command line or in the address, is redacted from git's errors, and is dropped when the scan ends: **no installation token or user token is ever stored**. The clone address is built from the server's GitHub address and the repository's name, never taken from a webhook or an API answer.
7. Scans run on the normal integration schedule (every 6 hours; changeable per repository, 15 minutes to a week), as the fallback, and after a **push to the default branch that changes a file a scan reads**: a lockfile or manifest the scanner knows (`package-lock.json`, `yarn.lock`, `go.mod`, `composer.json`, ...), one an installed stack pack reads, or `.gitignore`. A push to another branch, or one that changes only other files, is ignored. A push GitHub lists with no commits (a force push to an older commit) or with 20 or more (GitHub lists at most 20) is scanned, since what changed is not known. Pushes within a few seconds of each other make one scan, and a push during a scan makes one more after it.
8. The repositories are listed again once a day, after an install or a change on GitHub, and with **Sync** in the dashboard, so a missed webhook is caught up.

### Webhooks

GitHub posts events to `/api/v1/integrations/github/webhook`. The endpoint is public; its own checks are:

- `X-Hub-Signature-256` must be the HMAC-SHA256 of the exact body with the webhook secret, compared in constant time, before anything in the request is read. A missing or wrong signature gets 401.
- Each delivery is handled once: a redelivery (the same `X-GitHub-Delivery`) or the same signed body sent again under another delivery id is acknowledged and ignored. Deliveries are remembered for 30 days.
- An event for an installation not connected to an organisation changes nothing.

| Event | What happens |
|---|---|
| `installation` `deleted` (uninstalled on GitHub) | The installation is marked uninstalled for good; its repositories' integrations are switched off with a note. Assets, findings and history are kept. Install the app again to resume (a new installation). |
| `installation` `suspend` / `unsuspend` | Switched off with a note / switched back on (only the integrations Stackurity switched off; one someone switched off stays off), then the repositories are listed again. |
| `installation_repositories` `removed` | Those repositories leave the scope: their integrations are switched off with a note, and each one's asset is resolved as **removed**, not deleted: its issues close as removed, and the asset and its history stay (as for an application its host no longer reports). An asset whose latest report came from elsewhere (a CI scan) is left to that source. |
| `installation_repositories` `added`, `installation` `created` or `new_permissions_accepted` | The repositories are listed again from GitHub's API (the payload is not relied on) and new ones are added and scanned. |
| `push` | As in step 7. |

### Limits

- **Asset limit** ([asset-limits.md](asset-limits.md)): a new repository is added only while the organisation has room, counting the app's repositories still waiting for their first scan. One whose asset already exists (from CI or a Git integration) needs no room. The others wait, and the installation shows "N repositories are not scanned: this organisation is at its limit of L monitored assets"; they are added by the next listing once there is room. A scheduled scan of a repository already monitored keeps running.
- **Rate**: at most 30 installation tokens, so 30 clones, a minute for one installation across every replica; further scans wait a minute or two. When GitHub answers with its own rate limit (`Retry-After`, or `X-RateLimit-Remaining: 0`), the scan or listing waits until then.
- **Concurrency**: scans are ordinary jobs, so a replica runs at most its worker concurrency (2) at a time, whatever the installation's size; first scans are spread out as in step 5. At most 5,000 repositories of one installation are read.
- **Outbound connections** go through the same check as every request made for an organisation (`internal/netguard`, [network.md](network.md)). A GitHub Enterprise Server on a private address needs `STACKURITY_PRIVATE_CIDRS` (or `STACKURITY_PRIVATE_TARGETS`).

### In the dashboard

**Settings → Integrations** lists each repository with the other integrations, and the **Git repository** card shows **Install on GitHub** and the connected GitHub accounts, with:

- **Add or remove repositories**: GitHub's page for the installation. Changes there reach Stackurity by webhook.
- **Sync**: list the repositories again now (`POST /api/v1/integrations/github/installations/{installation_id}/sync`).
- **Disconnect**: stops scanning, keeps the history, and uninstalls the app from that GitHub account so it keeps no access Stackurity does not use (`DELETE /api/v1/integrations/github/installations/{installation_id}`). Installing the app again later picks up the same integrations, assets and history.

A repository's integration can be switched off, run now and rescheduled like any other. Its name, configuration and credentials are the app's and cannot be changed. Deleting it leaves that repository out until it is removed from the installation and granted again.

Audit entries: `github_app.install`, `github_app.refused`, `github_app.sync`, `github_app.disconnect`.

## Installs started on GitHub

The app's public page (`https://github.com/apps/<slug>`) lets people install it from GitHub's side. Such an install comes back without Stackurity's state, so Stackurity cannot tell which organisation asked; it binds nothing. The callback page says so and offers **Continue**, which starts a proper install: sign in if needed, then GitHub shows the existing installation, where **Save** comes back with a state. A member of a GitHub organisation who cannot install apps there can only request it (`setup_action=request`); once an owner approves, an admin clicks **Install on GitHub** again.

## Register the app

One GitHub App serves every organisation on the server. Register it once, under the GitHub account or organisation that will own it (for Stackurity Cloud, the `stackurity` organisation).

1. Copy [`github-app-manifest.json`](github-app-manifest.json). On your own server, replace `https://app.stackurity.dev` with your `STACKURITY_BASE_URL` in its three URLs, and set `"public": false` if only your own GitHub organisation will install it. Change `name` if it is taken on GitHub (app names are unique on GitHub).
2. Save this as a local HTML file, with the manifest pasted into `value`, and open it in a browser signed in to GitHub as an owner of the organisation (replace `ORG`; for an app owned by a personal account use `https://github.com/settings/apps/new`, and on GitHub Enterprise Server your server's address):

   ```html
   <form action="https://github.com/organizations/ORG/settings/apps/new?state=register" method="post">
     <input type="hidden" name="manifest" value='{ ...the manifest... }'>
     <button type="submit">Register the Stackurity GitHub App</button>
   </form>
   ```

   Click the button, check the page GitHub shows (name, URLs, **Contents: Read-only**, **Metadata: Read-only**, **Push** event, **Request user authorization (OAuth) during installation** ticked) and click **Create GitHub App**.
3. GitHub sends the browser to the manifest's `redirect_url` with `?code=...` in the address. Within an hour, exchange that code for the app's credentials (no token needed; the code works once):

   ```sh
   curl -s -X POST https://api.github.com/app-manifests/CODE/conversions > app.json
   jq -r .id app.json; jq -r .slug app.json; jq -r .client_id app.json
   jq -r .client_secret app.json > client-secret; jq -r .webhook_secret app.json > webhook-secret; jq -r .pem app.json > private-key.pem
   chmod 600 client-secret webhook-secret private-key.pem; rm app.json
   ```

   (On GitHub Enterprise Server: `https://<server>/api/v3/app-manifests/CODE/conversions`.) Without the manifest, create the app by hand in **Settings → Developer settings → GitHub Apps → New GitHub App** with the same settings, generate a private key, and set a webhook secret of your own (`openssl rand -hex 32`).
4. Give them to the server and restart it:

   | Variable | Value |
   |---|---|
   | `STACKURITY_GITHUB_APP_ID` (or `_FILE`) | App ID (`id`) |
   | `STACKURITY_GITHUB_APP_SLUG` (or `_FILE`) | The app's slug, as in `github.com/apps/<slug>` |
   | `STACKURITY_GITHUB_APP_CLIENT_ID` (or `_FILE`) | Client ID |
   | `STACKURITY_GITHUB_APP_CLIENT_SECRET` (or `_FILE`) | Client secret |
   | `STACKURITY_GITHUB_APP_PRIVATE_KEY_FILE` (or `STACKURITY_GITHUB_APP_PRIVATE_KEY`) | The private key (PEM) |
   | `STACKURITY_GITHUB_APP_WEBHOOK_SECRET` (or `_FILE`) | Webhook secret |
   | `STACKURITY_GITHUB_URL` | Optional: your GitHub Enterprise Server, such as `https://github.example.com` (the API is then `<that>/api/v3`). Unset for github.com |

   All six, or none: setting only some stops the server at start with a message naming the missing ones. `STACKURITY_BASE_URL` must be set (it is the app's callback and webhook address). The start-up log prints the callback and webhook URLs GitHub must use.
5. In Stackurity, **Settings → Integrations → Git repository → Install on GitHub**, pick a test repository with a lockfile, **Install**. Back in Stackurity, the repository appears under **Active integrations** and its first scan finishes within a minute or two. On GitHub, the app's **Advanced** tab lists the webhook deliveries; push a lockfile change to the default branch to see a `push` delivery answered `scan queued`.

To rotate a credential, generate a new private key or client secret, or change the webhook secret, in the app's settings, update the variable and restart. Delete the old private key on GitHub once the server uses the new one.

### Checks

```sh
# The webhook refuses unsigned requests (401), so it is reachable and configured:
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<your server>/api/v1/integrations/github/webhook
# The app answers with its JWT (from the server's log on start: "GitHub App enabled").
```
