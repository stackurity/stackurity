# Connect GitLab

**Connect GitLab** scans every project of a GitLab group, subgroups included, in one step: an admin authorises on GitLab, picks the group, and Stackurity takes it from there. Nobody creates, pastes or renews a token. It works with GitLab.com and with a self-managed GitLab.

What happens:

1. **Integrations → Git repository → Connect GitLab** sends the admin to GitLab's consent page. Stackurity asks for the `api` scope here, because creating a group access token and a group webhook needs it.
2. Back in Stackurity, the admin picks one of the groups their GitLab account is a Reporter or above of. Stackurity checks the membership with GitLab itself; the group id the browser sends is not trusted.
3. As the group's **Owner**, Stackurity creates:
   - a **group access token** named *Stackurity*, with `read_api` and `read_repository`, the **Reporter** role and an expiry just under a year. It is stored encrypted with `STACKURITY_SECRET_KEY` and used for every listing and clone;
   - a **group webhook** for push and project events, with a random secret token. Only its SHA-256 is stored.
4. The admin's own token is revoked at GitLab before the page answers. It was kept, encrypted, only between GitLab's redirect and the group being picked (at most 10 minutes; an abandoned connect's token is revoked when it expires).
5. Every project in the group becomes an integration of kind `gitlab`, scanned within minutes (first scans are spread out), on the same asset a CI scan or Git integration of the same URL uses.

After that:

- A push to a project's **default branch** that changes a lockfile or manifest (or a file an installed stack pack reads) queues a scan. Other pushes are ignored. Without a webhook, projects are scanned on their schedule (every 6 hours).
- The group's projects are listed again daily, on any non-push event from the webhook, and on **Sync now**. A new project is added and scanned; a project that left the group (deleted, moved, or no longer visible) has its integration switched off and its asset's issues resolved as removed. The asset and its history are kept.
- The group access token's expiry is shown on the connection; 30 days before it, the connection says to connect again. Connecting the same group again keeps the connection and its projects, creates a new token and revokes the old one; an expired token stops the connection with a note until then.

## When GitLab does not allow a group access token or a webhook

Creating a group access token needs the **Owner** role in the group, and GitLab.com or an instance's settings may restrict it. Group webhooks need the Owner role and GitLab's **Premium** or **Ultimate** tier.

- **No group access token**: the connection asks the admin to **Authorise read-only access**. GitLab's consent page asks for `read_api` and `read_repository` only, and that OAuth credential is kept, encrypted, and refreshed when it nears its expiry. GitLab replaces the refresh token on every refresh; Stackurity stores the new one in the same transaction, with the connection's row locked, so two scans refreshing at once cannot lose it. If GitLab stops accepting it (revoked, or the person who gave it lost access), the connection shows **Connect again**.
- **No webhook**: the connection says *scanned on the schedule only*.

The person who authorises read-only access must be a Reporter or above of the group. The credential is theirs: what they can read is what Stackurity can read.

## Disconnecting

**Disconnect** in Stackurity offers two ways:

- **Disconnect and clean up on GitLab**: GitLab's consent page (`api`) once more; Stackurity deletes the group webhook and revokes the group access token with that token, revokes it, and removes the connection.
- **Remove from Stackurity only**: the connection, its encrypted credential and its webhook secret are deleted here. A read-only OAuth credential is revoked at GitLab; a group access token revokes itself. The webhook stays on GitLab (deleting it needs the group's Owner) and its deliveries are refused from then on; delete it under the group's **Settings → Webhooks**.

Either way the projects' integrations are switched off with a note and their assets and history are kept. Connecting the group again picks the same integrations back up.

## Security

- **One organisation per group.** A group, or a group above or below it, connected to one Stackurity organisation cannot be connected to another.
- **State.** Each authorisation has a random state, stored only as its SHA-256, bound to the organisation and the admin who started it, valid once for 10 minutes. The pick handle after it is single use and the same person's.
- **Scopes.** A token with other scopes than asked is refused and revoked. A group access token GitLab answers with more than `read_api`/`read_repository` or more than Reporter is revoked and not kept.
- **Clones.** The clone address is built from the configured GitLab address and the project's validated path (inside the connected group), never from a webhook or an API answer. The token reaches git in its environment only (never the command line or the URL) and is removed from git's error messages; the clone is the same hardened shallow clone as a Git integration.
- **Network.** Every request for an organisation goes through its private-network policy (`STACKURITY_PRIVATE_TARGETS`, `STACKURITY_PRIVATE_CIDRS`), and connections are not kept open for reuse, so a connection made for one organisation never serves another. A self-managed GitLab on a private network needs its range in `STACKURITY_PRIVATE_CIDRS`.
- **Webhooks.** `X-Gitlab-Token` is compared in constant time with the stored SHA-256 before anything is read; each `X-Gitlab-Event-UUID`, and each body, is handled once.
- **Limits.** At most 30 clones a minute per connection; GitLab's rate limits (429, `Retry-After`) postpone the work. New projects respect the organisation's asset limit and wait for room with a note.

## Setting it up (operators)

Stackurity Cloud has it set up. For your own server:

1. Register an OAuth application on your GitLab, either instance-wide (**Admin area → Applications**, self-managed) or owned by a group (**Group → Settings → Applications**, GitLab.com or self-managed):
   - **Name**: Stackurity
   - **Redirect URI**: `https://<your Stackurity address>/integrations/gitlab/callback`, the address in `STACKURITY_BASE_URL`
   - **Confidential**: yes
   - **Scopes**: `api`, `read_api`, `read_repository`. Stackurity asks for `api` only when an admin connects or cleans up, and revokes that token in the same request; it keeps `read_api read_repository` only.
2. Set on the server:

   | Variable | |
   |---|---|
   | `STACKURITY_GITLAB_CLIENT_ID` (or `_FILE`) | The application ID |
   | `STACKURITY_GITLAB_CLIENT_SECRET` (or `_FILE`) | The secret |
   | `STACKURITY_GITLAB_URL` | Your GitLab's https address; unset for `https://gitlab.com` |
   | `STACKURITY_BASE_URL` | Your Stackurity's https address (callback and webhook URLs) |
   | `STACKURITY_SECRET_KEY` | Required: the credential is stored encrypted with it |

3. Restart. The log says `Connect GitLab enabled` with the callback URL. GitLab must be able to reach `POST /api/v1/integrations/gitlab/webhook/{id}` for webhooks (GitLab's own *Allow requests to the local network* setting applies when Stackurity is on a private address).

One GitLab per server. Projects in a personal namespace cannot be connected (connect a group, scan them in CI, or add them as Git repositories with a token).
