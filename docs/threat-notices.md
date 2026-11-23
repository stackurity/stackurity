# Threat notices

When a new attack, attacker tool or actively exploited vulnerability appears, Stackurity checks whether it can already detect it, adds a check when it cannot, and tells every organisation once what it means for them. Nobody has to ask: notices go out on their own.

The first threat is [ARTEX](config-checks.md) (risky settings, category `attack_tool`), the AI-driven attack framework the FBI warned about on 13 November 2026 ([FLASH](https://www.ic3.gov/CSA/2026/261113.pdf)). The first exploited vulnerability (`exploited_vuln`) is Apache Roller's CVE-2026-129448, detected by its CVE on Roller deployments the agent identifies from 0.20.25 (see [Java web applications](compatibility.md#java-web-applications)).

## What an organisation is told

Each organisation gets one of four verdicts per threat:

| Verdict | Meaning | The banner's button |
|---|---|---|
| `found` | The threat's checks found it on the organisation's assets: open findings of its [risky-settings](config-checks.md) rules or of its vulnerabilities. | **See findings** |
| `covered` | It is being used against systems on the public internet; the organisation's connected assets are checked and nothing was found; there is nothing to do. The notice may name another connection that would widen the check. | none |
| `needs_connection` | Stackurity can check for it but needs something the organisation has not connected: the agent on its servers (`host_agent`), container images from the agent's `--docker` or a registry (`docker`), repositories (`repository`), a cloud account (`cloud_account`) or a Kubernetes cluster (`kubernetes`). Each missing connection comes with the Help page that sets it up. A connection whose assets were last checked by an agent or scanner older than the check counts as missing too, and the notice says to update them. | **Connect** (or **Update**) |
| `upgrade` | Self-hosted only: the server runs a release older than the threat's `min_version`, the first one with the check. Stackurity Cloud always runs the latest release and never gives this verdict; it waits until the release with the check is deployed. | **Upgrade** |

`found` wins over every other verdict, also on an older server (a known-exploited CVE is found by the normal vulnerability checks, which need no new release). Otherwise a server without the check says `upgrade`; then a missing required connection, or no connection at all, says `needs_connection`; else `covered`.

**A connection counts only once it was checked.** An asset counts for a connection when its latest complete collection came from one of Stackurity's own collectors (the agents on Linux, macOS and Windows, their Docker and software collectors, and the server's own repository, image and registry scans) whose recorded version is a release of `min_version` or later. Anything else was not checked for the threat: an older agent, a version that is not a release (`dev`, a commit), the separate scan CLI, plugins and uploads, which carry versions of their own. Such assets are counted under `outdated`. **`covered` needs every asset of a required connection checked**: one updated agent among ten old ones gives `needs_connection` with "update the agent: 9 assets were last checked by a release older than ...", and once every agent is updated the notice turns `covered` quietly (the banner shows it; nobody is emailed again). Outdated assets of a connection that is not required, beside checked ones, do not stop `covered`; the notice suggests updating them. Only a development *server* compares no versions.

**Signals.** Some rules are weaker evidence: for ARTEX, `attack-tool-artex-name` (a Go module or image only *named* like it, medium severity, from the attack-tools check). The catalogue lists them as `signal_rules`. They never make a threat `found`; the notice counts them (`signals`) and asks to look at them under Risky settings.

Notices never name assets: they give counts and links to the dashboard, so the same text is safe for every channel.

## How it is delivered

Each organisation is told **once per threat**, on every channel at the same time:

1. **A banner** in the dashboard for members with an organisation-wide security or admin role: the verdict and one button. Each person can **Dismiss** it for themselves; it stays hidden until they are told something new.
2. **One email** to the organisation's administrators and security team, in the standard notification layout, through the server's account mail (email sent by Stackurity on Stackurity Cloud; `STACKURITY_SMTP_*` on a self-hosted server). Without a mail server nothing is sent, and the notice records `no_mailer`. A failed send is tried again on each run (every 30 minutes), up to 5 times, always with what people were told then (the told verdict and its counts are kept with the notice), whatever changed quietly since; if the threat is fixed meanwhile, the retry is given up. If a server stops between sending and recording it, the email is sent again: a rare duplicate rather than a lost notice.
3. **The organisation's notification routes** that have the `threat_notices` event (Slack, Teams, email channels, webhooks), scoped like other alerts: an organisation's routes get every notice; a project's or an asset's route gets only a `found` notice with a finding on one of its assets, counting only those. Tracker channels (Jira, PagerDuty, ServiceNow) get none. Migration `0118_threat_notices` gave the event to every existing route that sends messages as they happen (urgent, new issues or problems) **except webhook routes**. Webhooks always opt in: a receiver may not expect a new kind of message (`"event": "threat_notice"`, [api.md](api.md#notification-messages)), so a webhook route gets the event only when **Threat notices** is ticked on it (events that name `threat_notices`); defaults, older modes and mode changes never add it. Other routes created since have it by default; it can be turned off per route like any other trigger.

The verdict is worked out again every 30 minutes for every organisation that is not read-only. When it **worsens to `found`** (for example `covered` → `found` after an agent reports the tool), the organisation is told again on every channel, and the banner shows again for people who had hidden it. When a found threat is **fixed**, the notice follows quietly, so if it is **found again later** that is news again: told on every channel as a new message. Every other change (a connection added or updated) updates the notice quietly and keeps a hidden banner hidden. An organisation that has no notice for a threat more than 30 days after it was added does not get one: the threat stays in `threat_check` and the catalogue.

**Rolling upgrades.** An `upgrade` notice waits until the server has known the threat for 24 hours. During a rolling upgrade to the release that has the check, a replica still on the older release would otherwise tell every organisation to upgrade minutes before the upgrade finishes.

Each notice is recorded in the activity log (`threat_notice.sent`, by the system), with the verdict and counts.

## The catalogue

The threats are a versioned JSON catalogue, [`internal/threats/catalogue.json`](../internal/threats/catalogue.json), **embedded in the binary**: an offline server knows the threats of its own release. Each threat has:

| Field | |
|---|---|
| `id`, `name`, `aliases` | The threat's names; `threat_check` matches any, ignoring case |
| `kind` | `attack_tool`, `exploited_vuln`, `disclosed_vuln` (a critical vulnerability with a fix out, not known to be exploited yet), `campaign` or `practice` |
| `severity` | `critical`, `high`, `medium` or `low` |
| `summary`, `first_seen`, `published_at`, `sources` | What it is, when it was first seen in the wild, when Stackurity added it, and https sources |
| `detects` | `config_rules` (risky-settings rule ids), `cves` (CVE or GHSA ids: exploited vulnerabilities reuse the normal findings) and `signal_rules` (weaker rules, shown but never `found`) |
| `needs` | The connections the check reads: `connection`, `required`, `checks` (what it looks for there) and `help` (a `/help/...` page or an `https://stackurity.ai` page) |
| `min_version` | The first Stackurity release with the check |
| `revision` | Grows when the entry changes |

The catalogue has a `schema` (1), a `serial` that grows with every publication, `generated_at`, and in a published feed `expires_at`. `GET /api/v1/threats` serves the catalogue the server uses, with `has_check` per threat; the MCP tool `threat_check` reads it, so an assistant knows threats added after its own release.

## The feed

Servers fetch `https://stackurity.ai/threats/feed.signed.json` every 6 hours (one replica, leased like other periodic tasks). It holds the catalogue and its signature in **one file**, so a cache can never pair a new catalogue with an old signature:

```json
{"format": "stackurity-threat-feed/1", "algorithm": "ed25519", "key_id": "8ad39b477427659c",
 "signature": "<base64 Ed25519 over the exact catalogue bytes>", "feed": "<base64 of the catalogue>"}
```

`key_id` is the first 16 hex characters of the SHA-256 of the public key. The server checks the signature against the public keys built into the release ([`internal/threats/keys`](../internal/threats/keys)), then parses the catalogue and merges it with the embedded one: per threat, the higher `revision` wins. A feed is **ignored** and shown as a problem under **Admin → Platform health** (`threats` / `threat-feed`) when it is unsigned, signed by another key, changed after signing, malformed, of a newer `schema`, has a lower `serial` than one already used or than the release's own catalogue (a replay), or has no `expires_at` or is past it; the last good feed (or the embedded catalogue) is kept. A fetch that fails for the network (offline, air-gapped) is logged and is not a problem by itself, and it clears an earlier refusal; Platform health warns once **no usable feed was read for 7 days**, and when the feed in use has expired (it is still used: it is the newest authentic list). Blocking or replaying the feed therefore cannot hide new threats silently.

The default address is fetched through the private-network guard with private, loopback and link-local addresses refused, its name looked up fully qualified (never with the resolver's search domains), and may not redirect to another host or from HTTPS to HTTP. An HTTP(S) proxy set in the environment (`HTTPS_PROXY`) may be on a private address: the server connects to the proxy, which fetches the feed. The request is an anonymous GET of a public file and sends nothing about the installation ([network.md](network.md#threat-feed)). It is off with `STACKURITY_UPDATE_CHECK=off`; `STACKURITY_THREAT_FEED_URL` points it at a mirror (copy `feed.signed.json` unchanged), which may be on your own network. **A self-hosted server never sends anything to Stackurity**: verdicts and notices are worked out and delivered on the server.

### Signing the feed

The private key stays on the signer's machine (`~/.config/stackurity/threat-feed-signing.key`, mode 0600) and is never printed or committed. The public key is `internal/threats/keys/threat-feed.pub`.

```sh
go run ./tools/threatfeed sign --key ~/.config/stackurity/threat-feed-signing.key --feed path/to/threats/feed.json --valid-for 90d
go run ./tools/threatfeed verify --signed path/to/threats/feed.signed.json
```

`sign` checks that the feed parses as a catalogue this build reads, sets its `generated_at` and `expires_at` (`--valid-for`, 90 days by default), rewrites `feed.json` (the readable copy) and writes `feed.signed.json` next to it, after checking the signature against the embedded keys. Re-sign before the expiry even when nothing changed. To publish a threat: add it to the feed with the next `serial` and a `revision`, and its check's `min_version`; add it to `catalogue.json` in the release that ships the check. A server refuses a whole feed that has a `kind` its release does not know (and keeps the last good one), so a threat of a kind new in a release (such as `disclosed_vuln`, new in 0.20.28) ships only in that release's `catalogue.json` and stays out of the feed until older servers have upgraded. To rotate the key, embed the new public key in a release (`genkey` refuses to overwrite a key file), wait until servers run it, then sign with the new key; remove the old public key in a later release.

## The operator's copy

On Stackurity Cloud, with `STACKURITY_THREAT_NOTICE_COPY_TO` set, the operator gets **one** summary email per threat once its notices went out (2 hours after the last new notice of the first pass): how many organisations got each verdict, and one example notice of the most common verdict, rendered from counts. It names no organisation and no asset. It is sent once (`threats_seen.copy_sent_at`). Self-hosted servers ignore the variable.

## Privacy

The feed fetch sends no customer data. Notices are computed from the organisation's own findings and asset counts on its own server; the operator's copy (Stackurity Cloud) carries totals and one example without names.

## Storage

Migration `0118_threat_notices`: `threats_seen` (the catalogue entries the server has known, and the operator copy's state; no organisation data), `threat_notices` (one per organisation and threat: verdict, notified verdict, counts, missing connections, and when the banner, email and routes had it) and `threat_notice_dismissals` (who hid the banner, for which verdict). Both organisation tables have row-level security, and members with access to some projects only do not see them.

## API and MCP

- [`GET /threats`](api.md#get-threats), [`GET /threat-notices`](api.md#get-threat-notices), [`POST /threat-notices/{id}/dismiss`](api.md#post-threat-noticesiddismiss).
- MCP and Ask Stackurity: `threat_check` (is the organisation affected?) and `list_threat_notices` (what it was told), both read-only ([AI assistants](ai-assistants.md)).
