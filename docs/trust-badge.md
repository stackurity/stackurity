# Trust badge

The trust badge says "Monitored by Stackurity" on a customer's README or website and links to a public trust page. It is a **Stackurity Cloud feature only** (Free and paid plans). Self-hosted installations never run it: the community build and the licensed self-hosted build ignore the settings below.

**Not launched.** The badge launches only after counsel has signed off its legal wording in writing (the trust page disclaimer, the acceptance checkbox and the terms clause). Until then `STACKURITY_TRUST_BADGE` stays off in production.

This release has the first part only: the rule that decides whether a badge is active, and the history of its decisions. There is no badge image, trust page, public endpoint or settings page yet, so nothing is public.

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

Every decision is appended to `trust_badge_status` with its evidence: the covered systems with their last report and processing result, every source used with its freshness and cursor, the grouped component states, the oldest evaluation time, the result, the reason and the rule version, and the previous result. A decision can be rebuilt from its evidence. An enabled badge gets a decision every hour; a badge that is turned off gets one entry saying so.

The history is append-only:

- the application's database role (`stackurity_app`) has no UPDATE, DELETE or TRUNCATE on it (taken back on every start, after the blanket grants), and a trigger rejects all three for anyone else;
- entries are deleted only by the retention purge: the `trust_badge_status_purge` function, which only the `stackurity_purge` role may run, deletes entries older than the retention period (at least 30 days) and records each purge (time, period, policy version, entries deleted) in `trust_badge_purges`;
- every read of the history made for a person is written to the audit log (`trust_badge.history.read`).

History has no foreign key to its badge or workspace, so deleting a badge or an organisation does not delete it outside the retention policy. What happens to history when a badge ends or an organisation is deleted is for counsel to decide.

Limit: where the migrating database user may not create roles (some managed databases), the application runs as the table owner and the grants do not apply; only the trigger protects the history there. Anyone holding the database owner's credentials can always change the history.

## Settings

| Variable | Meaning |
|---|---|
| `STACKURITY_TRUST_BADGE` | `on` evaluates every badge hourly and writes its history. Off by default. Read only by the Stackurity Cloud build. |
| `STACKURITY_TRUST_BADGE_RETENTION` | How long decisions are kept, as days (`400d`) or a Go duration; at least 30 days. Unset: nothing is purged. Counsel sets the period. |
| `STACKURITY_TRUST_BADGE_RETENTION_POLICY` | The retention policy version recorded with each purge. Required with `STACKURITY_TRUST_BADGE_RETENTION`. |
