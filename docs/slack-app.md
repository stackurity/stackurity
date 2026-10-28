# The Stackurity Slack app ("Add to Slack")

With a Slack app configured on the server, people connect Slack in two clicks: **Settings → Integrations → Slack → Add to Slack**, pick a channel on Slack's page, **Allow**, and they are back in Stackurity with a Slack integration ready. Their messages have **Assign to me** and **Snooze 1 week** buttons that act from Slack, verified with the app's signing secret. Nobody copies webhook URLs or secrets.

Stackurity Cloud has this app. On your own server it is optional: without it, Slack integrations use an incoming webhook as before (**Advanced: use a webhook** is always there), and the **Add to Slack** button is hidden.

## What the app asks for

- **Scope: `incoming-webhook` only.** Slack's consent page then shows a channel picker, and Stackurity receives that channel's webhook and a bot token. It cannot read messages, list channels or post anywhere else.
- **Interactivity** at `/api/v1/integrations/slack/actions`, for the buttons. Clicks on channels added with the app are verified with the app's signing secret, must be at most 5 minutes old, are accepted once (events too), and must come from the Slack workspace the app was installed into from that organisation (a click from any other Slack workspace is refused). The person then acts as their linked Stackurity account, exactly as described in [Acting from Slack](install.md#acting-from-slack).
- **Events** `app_uninstalled` and `tokens_revoked` at `/api/v1/integrations/slack/events`: when someone removes the app from Slack, every organisation's Slack integrations for that Slack workspace are switched off with a note ("The Stackurity app was removed from this Slack workspace. Add to Slack again to resume."), and their webhooks and tokens are deleted.

## How it works

1. **Add to Slack** (`POST /api/v1/integrations/slack/install`, admins) stores a random state, only its SHA-256, bound to the organisation and the person, valid once for 10 minutes, and sends the browser to Slack's consent page.
2. Slack sends the browser back to `/integrations/slack/oauth/callback?code=...&state=...`. That dashboard page, in the signed-in session, posts the code and state to `POST /api/v1/integrations/slack/oauth`. A state that is unknown, used, expired, another person's or another organisation's is refused before Slack is called.
3. The server exchanges the code with Slack (`oauth.v2.access`, with the client ID and secret), checks the webhook is on `hooks.slack.com`, and creates a Slack integration named after the channel and Slack workspace.
4. The webhook URL is stored as an encrypted workspace secret (`slack-app-<team>-<channel>`), and the bot token sealed the same way (AES-GCM with `STACKURITY_SECRET_KEY`, bound to the organisation) in `slack_installations`. Neither is ever returned by the API or shown in the dashboard. **Add to Slack needs `STACKURITY_SECRET_KEY`.**
5. Adding the app to a Slack channel that already has an integration refreshes it (new webhook, switched back on). Each integration's webhook is its own secret.
6. Deleting the last such integration for a Slack workspace removes the app from that Slack workspace (`apps.uninstall`) unless another organisation on the server still uses it there.

One Slack app serves every organisation on the server. A Slack workspace can be connected from several organisations; each gets its own channel webhook.

## Create the app

1. At [api.slack.com/apps](https://api.slack.com/apps), **Create New App → From an app manifest**, pick a Slack workspace to own the app (any of yours; it is only where the app is managed), and paste [`slack-app-manifest.yaml`](slack-app-manifest.yaml). On your own server, first replace `https://app.stackurity.dev` with your `STACKURITY_BASE_URL` in its three URLs. **Next**, **Create**.
   Slack may say the events Request URL did not answer its check: that is expected until step 3. The app is created anyway.
2. **Basic Information → App Credentials**: copy the **Client ID**, **Client Secret** and **Signing Secret** (not the verification token).
3. Give them to the server and restart it:

   | Variable | Value |
   |---|---|
   | `STACKURITY_SLACK_CLIENT_ID` (or `_FILE`) | Client ID |
   | `STACKURITY_SLACK_CLIENT_SECRET` (or `_FILE`, a file holding it) | Client Secret |
   | `STACKURITY_SLACK_SIGNING_SECRET` (or `_FILE`) | Signing Secret |

   All three, or none: setting only some stops the server at start with a message. `STACKURITY_BASE_URL` and `STACKURITY_SECRET_KEY` must be set. The start-up log prints the three URLs Slack must use.
4. Back in the app's settings, **Event Subscriptions**: if the Request URL shows as not verified, click **Retry** (the server now answers Slack's check). **Save Changes**.
5. **Manage Distribution**: to let other Slack workspaces add the app (needed for a service like Stackurity Cloud), tick the checklist and **Activate Public Distribution**. A server used by one company can skip this; the app can then only be added to the Slack workspace that owns it.
6. In Stackurity, **Settings → Integrations → Slack → Add to Slack**, pick a channel, **Allow**, then **Send test**.

To rotate the client secret or signing secret, **Regenerate** it in the app's settings, update the variable and restart. Clicks signed with the old signing secret are refused from then on.
