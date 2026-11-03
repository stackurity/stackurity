# The Stackurity Teams app ("Add to Teams")

With a Teams app configured on the server, people connect Microsoft Teams without a webhook: **Integrations → Microsoft Teams → Add to Teams**, add the app to a team in Teams, and send it the code Stackurity shows in the channel that should get the notifications. Stackurity then opens the new integration to choose what to send. Messages are the same Adaptive Cards as before (title, sections, **Open in Stackurity** and **Change these notifications**), posted by the Stackurity bot.

On your own server the app is optional. Without it, Teams integrations use a Workflows webhook as before, and **Add to Teams** is not shown. With it, new Teams integrations use the app; **Advanced: use a Workflows webhook** is still there, and existing webhook integrations keep working unchanged.

## How a channel is connected

Teams does not pass anything of Stackurity's through an app install, so the channel is tied to the organisation with a code, never by the Microsoft 365 tenant alone:

1. **Add to Teams** (`POST /api/v1/integrations/teams/install`, admins) makes a code such as `K7QWN-3HTRD` for that person in that organisation: single use, 15 minutes, 10 characters (about 49 bits), only its SHA-256 stored. Starting again replaces their earlier unused code. The page shows the code and an **Open Stackurity in Teams** button.
2. The admin adds the app to a team in Teams. Teams tells the bot, which posts how to connect in the team's channel.
3. In the channel that should get the notifications, the admin sends `@Stackurity K7QWN-3HTRD`. The message reaches the bot's messaging endpoint; once its token is verified (below), the code is used up and names the organisation, and that channel (tenant, team and channel ids, and the Bot Connector address Teams gave) becomes a Teams integration of that organisation. The bot answers "Connected" in the thread, and the Stackurity page, which checks every 3 seconds, opens the integration.

So nobody in a Teams tenant can connect a channel to an organisation without a code an admin of that organisation was just shown, and an admin's code connects only the channel it was typed in. A wrong, used or expired code gets an explanation in Teams and changes nothing; at most 30 codes an hour are tried per Microsoft 365 tenant. A code sent in a chat rather than a team channel is refused (and still usable). Sending the code again for a channel that already has an integration switches that integration back on.

## Every request is verified

The messaging endpoint, `POST /api/v1/integrations/teams/messages`, is public (Teams calls it), so every request must carry a Bot Framework token, checked before anything in it is used:

- a `Bearer` JWT signed with RS256 (any other algorithm, `none`, or an HMAC "signed" with the public key is refused) by a key from the Bot Framework's OpenID metadata (`https://login.botframework.com/v1/.well-known/openidconfiguration`) whose endorsements include `msteams`, for an activity from the `msteams` channel;
- issuer `https://api.botframework.com`, audience the app's Microsoft App ID, not expired and not before its start (5 minutes' leeway);
- its `serviceurl` claim equal to the activity's `serviceUrl`.

The signing keys are cached for a day; a token naming a key the cache does not have fetches them again (Microsoft rotates them), at most once a minute. Anything else is a 401 and nothing is read, stored or sent. Each activity is handled once (Microsoft retries deliveries).

Replies and notifications go only to the Bot Connector hosts Microsoft documents for Teams, over HTTPS on port 443: `smba.trafficmanager.net` (commercial), `smba.infra.gcc.teams.microsoft.com` (GCC), `smba.infra.gov.teams.microsoft.us` (GCC High) and `smba.infra.dod.teams.microsoft.us` (DoD). An activity whose `serviceUrl` is anywhere else is refused (403) even with a valid token, and a stored address is checked again before every message, so a forged `serviceUrl` never receives the app's access token. Connections to Microsoft go to public addresses only (never private networks or metadata services) and never follow redirects.

## Sending, and when the app is removed

Notifications start a new post in the channel through the Bot Connector API (`POST <serviceUrl>/v3/conversations`), with an access token for the app from Microsoft Entra (client credentials, scope `https://api.botframework.com/.default`), cached until five minutes before it expires and renewed once if the Bot Connector refuses it.

When the app is removed from the team, the team or the channel is deleted, or Teams answers that the bot is no longer in the conversation (403 or 404), the integration is switched off with the reason ("The Stackurity app was removed from this Teams channel… Use Add to Teams again to resume."), never left failing quietly. A Bot Connector error or rate limit is shown on the integration and retried as for other channels. Deleting the integration in Stackurity does not remove the app from the team; remove it in Teams if no other channel of that team uses it.

## Set up the app

You need an Azure subscription for the Azure Bot resource (the Teams channel of an Azure Bot is free) and a Teams admin, or a Teams policy that lets you upload custom apps.

1. In the [Azure portal](https://portal.azure.com), **Create a resource → Azure Bot**. Give it a handle (for example `stackurity`), and for **Type of App** choose **Multi Tenant** when the portal offers it, otherwise **Single Tenant** (Microsoft no longer creates new multi-tenant bots). **Creation type: Create new Microsoft App ID**. **Create**.
2. In the bot's **Configuration**: set **Messaging endpoint** to `https://<your server>/api/v1/integrations/teams/messages` (your `STACKURITY_BASE_URL`; on Stackurity Cloud `https://app.stackurity.dev/api/v1/integrations/teams/messages`) and **Apply**. Copy the **Microsoft App ID** (and, for a single-tenant bot, the **App Tenant ID**).
3. Next to the App ID, **Manage Password** opens the Entra app registration: **Certificates & secrets → New client secret**, and copy its value. (Or upload a certificate there and use it instead of a secret.)
4. In the bot's **Channels**, add **Microsoft Teams**, accept the terms and **Apply** (Microsoft Teams Commercial, or the government cloud you use).
5. Give the app to the server and restart it:

   | Variable | Value |
   |---|---|
   | `STACKURITY_TEAMS_APP_ID` (or `_FILE`) | The Microsoft App ID |
   | `STACKURITY_TEAMS_APP_PASSWORD` (or `_FILE`, a file holding it) | The client secret |
   | `STACKURITY_TEAMS_APP_CERTIFICATE_FILE` | Instead of a client secret: a PEM file with the certificate and its RSA private key (PKCS #8 or PKCS #1) |
   | `STACKURITY_TEAMS_APP_TENANT` | For a single-tenant bot, the App Tenant ID; empty for a multi-tenant bot |
   | `STACKURITY_TEAMS_APP_INSTALL_URL` | Optional: the link **Open Stackurity in Teams** opens (step 7); default `https://teams.microsoft.com/l/app/<app ID>` |

   The app ID and exactly one of the client secret and the certificate are required together; a mistake stops the server at start with a message. The start-up log prints the messaging endpoint. `STACKURITY_BASE_URL` should be set so links in the cards work.
6. Build the app package (the manifest in [`teams-app/manifest.json`](teams-app/manifest.json) with your app ID and host, and its two icons):

   ```sh
   make teams-app-package TEAMS_APP_ID=<Microsoft App ID> BASE_URL=https://stackurity.example.com
   ```

   This writes `stackurity-teams-app.zip` (`scripts/teams-app-package.sh`; `PRIVACY_URL`, `TERMS_URL`, `WEBSITE_URL` and `APP_VERSION` override the manifest's links and version; raise the version for each new upload).
7. Make the app available in your organisation: in the [Teams admin center](https://admin.teams.microsoft.com), **Teams apps → Manage apps → Upload new app**, and allow it in your app permission policies. Or, where custom app upload is allowed, in Teams **Apps → Manage your apps → Upload an app**. An app uploaded to your organisation's catalogue gets its own app ID there; if **Open Stackurity in Teams** does not find the app, set `STACKURITY_TEAMS_APP_INSTALL_URL` to `https://teams.microsoft.com/l/app/<that ID>`. A service used by many organisations (like Stackurity Cloud) publishes the app to the Teams Store through Partner Center instead.
8. In Stackurity, **Integrations → Microsoft Teams → Add to Teams**, follow the two steps, then **Send test**.

To rotate the client secret, add a new one in the Entra app registration, update `STACKURITY_TEAMS_APP_PASSWORD` and restart, then delete the old one. Changing the messaging endpoint needs nothing in Stackurity.

## Not supported

- Group chats and personal chats: channels of a team only.
- Buttons that act from Teams (Assign to me, Snooze): the cards' buttons open the dashboard.
- Tokens issued by Microsoft Entra rather than the Bot Framework (`iss` `https://api.botframework.com`) on the messaging endpoint, and the Azure Government Bot Framework (`login.botframework.azure.us`). Bot Connector hosts of GCC, GCC High and DoD are allowed for sending.
