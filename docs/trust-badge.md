# Trust badge

The trust badge says "Monitored by Stackurity" on a customer's README or website and links to a public trust page. It is a **Stackurity Cloud feature only** (Free and paid plans): the badges, their status decisions and everything public about them exist only on the Stackurity Cloud build with `STACKURITY_TRUST_BADGE=on`. A self-hosted server (the Community build, or the licensed self-hosted build) has no badge routes, settings or decisions, whatever the variable says.

One part runs on every installation: each evaluation records which refresh of each vulnerability source it read, in `inventory_evaluations` (see condition 4 below). That table is kept up to date on every server, with or without the badge, because it is written wherever components are evaluated; it holds nothing public and nothing about badges.

**Not launched.** The badge launches only after counsel has signed off its legal wording in writing (the trust page disclaimer, the acceptance checkbox and the terms clause) and answered the legal review brief's questions. Until then `STACKURITY_TRUST_BADGE` stays off in production. The acceptance checkbox in the dashboard is draft 2 of the brief, versioned `2026-11-draft2`; when counsel's text replaces it, the version changes and every badge needs the new terms accepted before it is turned on again.

## When a badge is active

A badge is active only when every system in its scope meets all four conditions (`internal/trustbadge`, rule version `2026-11-10.1`):

1. it reported its software inventory in the last 7 days;
2. its latest inventory was processed, complete and without collection errors (an hour's grace for processing);
3. every vulnerability source its software was matched against is within that source's own freshness window;
4. every component was evaluated against the latest refresh of each of its sources. A refresh of one source never counts for another.

Each component and source pair is in one state:

| State | Meaning | Badge |
|---|---|---|
| Evaluated | Checked against the latest refresh of its source | Can stay active |
| Unsupported | No available source covers it, or the source publishes no advisories for its release | Stays active; disclosed by broad kind of software, never package names |
| Pending | Its source refreshed, or it was just inventoried, and the check has not run yet | Stays active while the refresh it was last evaluated against is within the source's freshness window (an hour for new components, 6 hours for a source not synced yet) |
| Failed | A check that should have completed did not (the version could not be read, another reason a source could not be used, or a re-check that did not run in time) | Not active |
| Stale | Its source is past its freshness window, switched off or missing | Not active |

A badge that is turned off, or whose scope holds no systems, is not active. A badge's scope is some projects or some assets; there is no organisation-wide badge.

For condition 4 each evaluation records the source's cursor and last successful sync as it read them (`inventory_evaluations`, one row per component and source). Components evaluated before this release are compared by their evaluation time until they are next evaluated.

## Status history

Every decision is appended to `trust_badge_status` with its evidence: the covered systems with their last report and processing result, every source used with its freshness and cursor, the grouped component states, the oldest evaluation time, the result, the reason and the rule version, and the previous result. A decision can be rebuilt from its evidence. An enabled badge gets a decision every hour, and at once when it is turned on, off or changed; a badge that is turned off gets one entry saying so.

The history is append-only:

- the application's database role (`stackurity_app`) has no UPDATE, DELETE or TRUNCATE on it (taken back on every start, after the blanket grants), and a trigger rejects all three for anyone else;
- entries are deleted only by the retention purge: the `trust_badge_status_purge` function, which only the `stackurity_purge` role may run, deletes entries older than the retention period (at least 30 days) and records each purge (time, period, policy version, entries deleted) in `trust_badge_purges`;
- every read of the history made for a person is written to the audit log: `trust_badge.history.read` for the customer's timeline, `trust_badge.admin.list` and `trust_badge.admin.history.read` for Stackurity's operators.

History has no foreign key to its badge or workspace, so deleting a badge or an organisation does not delete it outside the retention policy. What happens to history when a badge ends or an organisation is deleted is for counsel to decide.

Limit: where the migrating database user may not create roles (some managed databases), the application runs as the table owner and the grants do not apply; only the trigger protects the history there. Anyone holding the database owner's credentials can always change the history.

## The badge and the trust page

**Image.** `/badge/<slug>.svg` (`?theme=dark` for dark backgrounds), about 44 px high. Active: "Monitored by Stackurity" in brand blue, with "Monitor yours, free →" below a divider. Not active, unknown or switched off: the grey "Stackurity badge not active", with no marketing line. No green, amber or red. The SVG's title and label are "Monitored by Stackurity. Not a security certification." With `?time=1`, and when the customer allowed it, the image adds the oldest evaluation time in the scope as an absolute UTC time, so a cached copy never understates how old it is.

**Trust data.** `GET /api/v1/public/trust/<slug>` is what stackurity.ai/trust/<slug> renders: the name, the website link and logo when shown, the state, the oldest evaluation time, the kinds of systems when shown, and the broad kinds of software no available source covers (for the scope statement). Never an id, a count, a finding, or a package, host, repository, image or project name. A badge is active only while its last decision is active and less than two hours old, so a stalled evaluator turns badges "not active" rather than leaving them active. `GET /api/v1/public/trust?listed=1` lists the listed, active slugs for the sitemap. See [api.md](api.md#trust-badge).

**Caching.** The image is cached for an hour when active and five minutes otherwise, the trust data for 15 minutes. Turning a badge off, changing it or deleting it changes the answer at the origin at once and, when Cloudflare credentials are set, purges the cached copies of its image, trust data and trust page.

## Settings page

**Settings → Trust badge** (organisation admins; the API also lets an admin of every project or asset a badge covers manage it):

- the scope: some projects or some assets, never the whole organisation, and only ones the person administers;
- the address (3 to 50 lower-case letters, digits and single hyphens; words such as `stackurity…`, `admin` or `verified` are reserved), the name on the trust page and the website;
- a switch for each public item: the marketing line (paid plans only), the evaluation time on the image, the kinds of systems, the website link and logo, and search engine listing;
- a live preview: the real images and trust data the public would see if the badge were on now, from the same rule and code as the public endpoints (nothing is written);
- the badge terms to accept, then **Turn on**; who accepted which version, and when, is recorded;
- copy-paste snippets (Markdown, HTML, image address) with the alt text "Monitored by Stackurity. Not a security certification.";
- the badge's status timeline (each read audited).

Every change is audited: `trust_badge.create`, `.update` (before and after), `.delete`, `.terms.accept`, `.enable`, `.disable`, `.logo.set` and `.logo.remove`.

**Plans.** Free: one badge, the marketing line always shown, no logo. Paid Cloud plans: the marketing line and the trust page's sign-up button can be switched off, one badge per project, and a logo (PNG, JPEG or WebP, at most 256 KiB, its type checked from its bytes). The limits are enforced by the server in the settings and in the public output, so a downgrade takes effect at once.

## Evidence viewer

**Admin → Trust badges** (Stackurity's operators, instance administrators only) lists every organisation's badges with their last decision and shows, for any decision, its full evidence: the systems with their last report and processing result, each source's freshness and cursor, the failed conditions, the component states, the rule version and the timeline. Every list and every history opened is audited.

## Launch gate

The badge launches only when every item is done. Each automated item names its tests; `TestLaunchGateNamesRealTests` (`internal/trustbadge`) fails if a named test disappears.

| Item | Where it is checked |
|---|---|
| All four conditions and each evaluation state | `TestActiveWhenEveryConditionHolds`, `TestNotActiveReasons`, `TestPendingWithinTheSourceWindowThenOverdue`, `TestPendingWithinGraces` |
| Per component and source evaluation, or no multi-source claim | `TestSetCoverageRecordsTheSourceRefreshEvaluated`, `TestOneSourceRefreshNeverCountsForAnother`, `TestMultiSourceComponentNeedsEverySource` |
| Unsupported never treated as failed, and failed never as unsupported | `TestUnsupportedAndFailedStayApart`, `TestUnknownClassIsNeverFine` |
| Every decision can be rebuilt from its evidence | `TestDecisionRebuildsFromEvidence`, `TestTrustBadgeHistoryAppendsAuditsAndRebuilds` |
| History rejects ordinary updates and deletes | `TestTrustBadgeHistoryIsAppendOnly` |
| Retention purge only through the restricted path, each purge audited | `TestTrustBadgeHistoryIsAppendOnly` |
| Every history read audited | `TestTrustBadgeHistoryAppendsAuditsAndRebuilds`, `TestTrustBadgeSettingsPermissionsAndAudit`, `TestTrustBadgeEvidenceViewer` |
| The trust page always shows the scope and the real oldest evaluation time | `TestTrustBadgePublicContract`; the website's trust page tests |
| Not active and turned off show within the stated cache limits | `TestTrustBadgePublicContract`, `TestTrustBadgePurgesCache` |
| No blocked claim in badge images, metadata, snippets or marketing | `TestTrustBadgeImageWording`; the website's claims check |
| Free and paid acceptance flows tested, and a self-hosted server can't serve a badge | `TestTrustBadgePlans`, `TestTrustBadgeOffServesNothing`, `TestTrustBadgeFromEnv`, `TestTrustBadgeOffRegistersNothing` |
| Counsel's written sign-off on drafts 1 to 3 and answers to all 13 questions | **Not done.** Outside the code. |

## Settings

| Variable | Meaning |
|---|---|
| `STACKURITY_TRUST_BADGE` | `on` turns the badge on: its settings page, the hourly decisions and their history, and the public image and trust data. Off by default. Read only by the Stackurity Cloud build. |
| `STACKURITY_TRUST_PAGE_BASE` | Where trust pages are published, for the snippets and cache purges. Default `https://stackurity.ai/trust`. |
| `STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE` | The Cloudflare zone in front of the server and the website. With `STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN`, a badge's cached copies are purged when it is turned off, changed or deleted (`POST api.cloudflare.com/client/v4/zones/<zone>/purge_cache`, the URLs only; see [network.md](network.md)). Unset: no purge, the cache headers apply. |
| `STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN` | A Cloudflare API token with only that zone's Cache Purge permission. Set together with the zone. |
| `STACKURITY_TRUST_BADGE_RETENTION` | How long decisions are kept, as days (`400d`) or a Go duration; at least 30 days. Unset: nothing is purged. Counsel sets the period. |
| `STACKURITY_TRUST_BADGE_RETENTION_POLICY` | The retention policy version recorded with each purge. Required with `STACKURITY_TRUST_BADGE_RETENTION`. |
