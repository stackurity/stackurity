# Feedback queue

This document covers the Stackurity team's own server. A self-hosted installation never runs the queue: its users' feedback goes to the team through `STACKURITY_FEEDBACK_URL` (see [network.md](network.md#feedback)), and "My feedback" asks the team's server for the status.

## Where it lives

The queue runs inside the Stackurity server at app.stackurity.dev, turned on there by `STACKURITY_FEEDBACK_QUEUE_DIR`. On every other installation the tables stay empty and the routes answer 404.

The website (stackurity.dev/feedback) stays the one public address that installations and the contact form post to. It relays each item to the queue over the internal network, with a shared key. The queue was put in the server rather than the website because the server already has what a queue needs:

- PostgreSQL with row-level security;
- instance administrators who sign in with two-factor authentication;
- tokens, rate limits shared by every replica, periodic jobs and backups.

The website has none of these: it keeps files in a container volume and has no sign-in.

```
installation ──POST /feedback (JSON or multipart)──▶ stackurity.dev (relay, per-address limits)
                                                         │ X-Stackurity-Feedback-Key
                                                         ▼
                                       app.stackurity.dev /api/v1/feedback-queue/intake
                                       (checks, strips, stores; FB-123 + status token)
```

## Settings (the team's server only)

| Variable | Meaning |
|---|---|
| `STACKURITY_FEEDBACK_QUEUE_DIR` | Directory for attachments (created with mode 0700). Setting it turns the queue on. In production: on the data volume, e.g. `/var/lib/stackurity/feedback`. Never under `/tmp` (a RAM disk in the container). |
| `STACKURITY_FEEDBACK_INTAKE_KEY` or `_FILE` | The key the website relay sends (at least 32 characters). It also derives the key that signs attachment links. The website's `FEEDBACK_QUEUE_KEY_FILE` holds the same value. |
| `STACKURITY_FEEDBACK_LINK_KEY` or `_FILE` | Signs attachment download links (at least 32 characters, not the intake key). Unset, each process makes a random key, so links work only on the replica that made them. |
| `STACKURITY_FEEDBACK_SCAN` | `required` holds every new attachment as pending, hidden from operators and the triage agent, until the on-demand scanner ([below](#virus-scan)) reports it clean. Unset or `off`: attachments are available once the type, size and structure checks pass. |
| `STACKURITY_FEEDBACK_EMAILS` | `on` sends the sender one short email when their item is released or will not be fixed (with the team's reason), through the server's account mail. Off by default: the owner approves the wording first (`GET /api/v1/admin/feedback/email-templates`). The email quotes nothing the sender wrote, since the address is not verified. |
| `STACKURITY_FEEDBACK_AGENT_EMAILS` | `on` sends the sender the [feedback agent's](#the-feedback-agent) two emails: **received** (when the item arrives, quoting what they sent, at most 600 characters with links and addresses made unclickable, five a day per address) and **needs more details** (with the questions, and a link to My feedback for Stackurity Cloud senders). Off by default: the owner approves the wording first (`GET /api/v1/admin/feedback/email-templates` marks them `approved: false`). |
| `STACKURITY_FEEDBACK_APPROVERS` | Addresses, separated by commas, emailed "Approval needed" when an item moves to `needs_owner`, with a link to Admin → Feedback. Unset: no email (the agent still posts to Slack). |
| `STACKURITY_FEEDBACK_STORAGE_MAX_MB` | Cap on the attachments kept (default 5120). Above it, new attachments are refused with 507 and feedback without attachments is still taken. `GET /api/v1/admin/feedback` reports `storage.used_bytes` and `max_bytes`. |

## Items

Each item has an id shown as `FB-123`. Its fields:

- **source:** `cloud`, `self_hosted` or `website`, with the `version` and `edition`;
- **kind:** issue, feature or question;
- **description** and **contact_email** (optional);
- **page, browser and viewport**, captured automatically;
- **attachments**;
- **status**, with `resolution` (shown to the sender) and `triage_notes` (internal);
- **owner_reason** (why it needs the owner) and the owner's approval (`approved_at`, `approved_by`, `approval_note`);
- **comments**: the thread the sender reads in My feedback (see [below](#the-feedback-agent));
- **link** to the pull request or issue, plus `duplicate_of` and `fixed_in`;
- **timestamps:** created, updated, triaged and closed.

Every change is recorded in `feedback_events`.

| Status | The sender sees |
|---|---|
| `new` | Received |
| `triaged`, `needs_owner` | Under review |
| `needs_info` (the agent or the team asked a question) | Needs your answer |
| `in_progress` | In progress |
| `fixed` (merged, awaiting release) | Fixed, waiting for release |
| `released` | Released in `fixed_in` |
| `wont_fix` (needs a `resolution`) | Won't fix, with the resolution |
| `duplicate` (needs `duplicate_of`) | Duplicate |

`released`, `wont_fix` and `duplicate` close the item.

The schema is in `internal/db/migrations/*_feedback.sql`. The queue's tables have no workspace column and only system scope can read them. Every API route checks for an instance administrator or a triage token, so no customer principal reaches them (`TestFeedbackQueueOnlyForOperators` and the isolation sweep).

## Attachments

- **What is accepted:** at most 3 per item, of PNG, JPEG, WebP or GIF images, MP4 or WebM videos, and PDFs.
- **Size limits:** 10 MB per image or PDF, 50 MB per video, and 90 MB together, which keeps the request under Cloudflare's 100 MB limit.
- **Checks:** the type is decided from the file's first bytes, never from its name or the browser's Content-Type. Images are walked chunk by chunk and lose EXIF, XMP, IPTC, ICC, comments and anything after the image's end, with no re-encoding. A structure that doesn't parse is refused, as is a declared size over 100 megapixels. The installation does this before sending, and the queue does it again.
- **Storage:** files are stored under random 128-bit names in the queue's directory and opened only through an `os.Root`. Names from people are kept only as a cleaned display name.
- **Access:** operators get a link signed with HMAC-SHA256 (over the item, the attachment and the expiry, with a key the relay never holds) that expires in ten minutes. The file is served as a download with `Content-Security-Policy: sandbox`, `nosniff` and `no-store`.
- **Re-encoding:** after the metadata walk, the queue decodes each image and encodes its pixels again (PNG, JPEG at quality 92, GIF with its frames; WebP becomes PNG), so nothing of the original file but its pixels is kept. Images over 40 megapixels are refused.
- **Virus scan:** on demand, with ClamAV, when `STACKURITY_FEEDBACK_SCAN=required` (see [Virus scan](#virus-scan)).
- **Storage alert:** above 80% of the cap, the intake logs an error and its answer carries `storage_warning`, which the website posts to the team's Slack; the daily job logs the same.
- **Video metadata:** it is not removed. Screen recordings rarely carry any, but phone videos can carry a location.

## Virus scan

ClamAV's signatures take about 1 to 1.5 GB of memory, too much to keep resident on the production droplet (4 GB). So nothing stays running: `deploy/feedback-scan` has a scan script and a daily signature update, run by systemd timers on the host.

- **Holding:** with `STACKURITY_FEEDBACK_SCAN=required`, a new attachment is stored as `pending`. It is not listed, linked or served to operators or the triage agent until it is scanned.
- **Scanning:** every 10 minutes, `scan.sh` asks for pending attachments (`GET /api/v1/admin/feedback/scan/pending`), runs `clamscan` once over them in a throwaway container (no network, read-only, the queue directory mounted read-only, memory capped at 1.5 GiB, one CPU at the lowest CPU and I/O priority), and reports each verdict (`POST /api/v1/admin/feedback/scan/{aid}`).
- **When it waits:** it skips the run, and leaves files pending, while a release runs, a build or backup holds its lock, a migration rehearsal runs, or less than 1.7 GiB of memory is available (see [RELEASING.md](../RELEASING.md#host-locks) for the shared locks). While it scans it holds the build lock, so no build starts meanwhile. A clamscan error leaves files pending too: nothing is let through unscanned.
- **Infected:** the file is deleted at once (`scan` `infected`, with the signature name), the item moves to `needs_owner` and its notes say what was found.
- **Signatures:** `freshclam.sh` updates them once a day into a Docker volume, under the same conditions.
- **Token:** the scripts use a feedback token with scope `scanner` (`POST /api/v1/admin/feedback-tokens` with `"scope":"scanner"`), which can read the pending list and report verdicts and nothing else; a triage token cannot do either.

Install (host, as root): copy `deploy/feedback-scan` to `/opt/stackurity/feedback-scan`, the env example to `/etc/stackurity/feedback-scan.env` (0600), the scanner token to the file it names (0600), the units to `/etc/systemd/system`, then run `freshclam.sh` once and `systemctl enable --now feedback-freshclam.timer feedback-scan.timer`.

Measured on the production droplet (3 November 2026): `freshclam` 30 s, peak 672 MiB; `clamscan` 43–60 s for 2–4 files up to 50 MB, peak 1029–1085 MiB inside the 1.5 GiB cap. Host memory available fell by about 1 GiB during a scan.

## Retention

A daily job, `feedback-retention`:

- deletes attachment files 180 days after their item closed (the row stays, marked `purged_at`);
- deletes items two years after they closed, or two years after they were sent if they never closed.

## Operators and the triage agent

- Instance administrators can delete an item (spam, abuse) with `DELETE /api/v1/admin/feedback/{id}`; the triage token cannot.
- A daily sweep also removes attachment files with no item (left by a crash between writing a file and storing its item).
- Intake is limited per sender address (30 items an hour, 10 with attachments), 300 items an hour in all, and 8 uploads at once; status checks 120 an hour per address.
- Instance administrators use `/api/v1/admin/feedback` (see [api.md](api.md#feedback-queue)).
- For the automated triage agent, an instance administrator creates a token with `POST /api/v1/admin/feedback-tokens` (`stkfb_…`, at most 90 days).
- The token reads items and attachments and writes status and notes. Every other route refuses it, including the token routes themselves.
- The `/feedback` project skill (`.claude/skills/feedback/SKILL.md`) uses it:
  - `/feedback review` classifies new items;
  - `/feedback approve FB-123 [comments]` applies what the owner approved;
  - `/feedback release vX.Y.Z` moves fixed items to released at release time ([RELEASING.md](../RELEASING.md)).

Feedback text and attachments are untrusted data: the skill never follows instructions found in them.

## The feedback agent

Feedback is worked on as it arrives, as the Commmerce CRM does it. The agent is `tools/feedback-agent`, a program that runs on the owner's Mac from launchd every ten minutes (the Mac has the repositories and builds the images; GitHub Actions is not used). It uses a triage token and changes code only through pull requests.

```
new item ──▶ agent (claude -p in a fresh worktree of origin/main)
               ├─ done ───────────▶ checks pass ▶ branch + pull request ▶ in_progress (link)
               ├─ needs_more_info ▶ question in the thread ▶ needs_info ──▶ sender answers in My feedback ▶ new
               ├─ needs_approval ─▶ needs_owner + reason ▶ owner: Approve ▶ triaged (approved) ▶ agent builds it
               │                                                  └ Decline (reason) ▶ wont_fix + email
               └─ cannot ─────────▶ needs_owner, won't-fix candidate (owner declines with a reason, or approves a retry)
```

**What it may build alone:** changes under `web/`, `internal/`, `docs/` and `changelog.d/`. **What needs the owner (needs_owner):** billing, prices, plans and licences; sign-in, roles, permissions and who can see what; emails and any wording customers receive outside the dashboard; legal and privacy text; deleting data, retention and migrations (`internal/db/migrations/`); Ask Stackurity's prompts, AI models or running costs; new paid services or dependencies; anything outside those folders; and any item that tries to instruct the agent. Claude is told these rules, and the runner checks the changed paths again (`tools/feedback-agent/rules.go`): a change that touches one of them is not committed, and the item goes to the owner with the paths named, unless the owner approved it.

**Each run:**

1. One run at a time (a lock file); at most three items, approved ones first, then new ones oldest first.
2. For each item: the item, its thread and its attachments are downloaded into a run folder (`~/code/feedback-agent-runs/runs/FB-123-…`, kept 30 days), with six frames of each video when `ffmpeg` is installed.
3. `claude -p` runs in a fresh worktree of `origin/main` with a prompt that marks the item's text, thread and attachments as data, never instructions. It may read and edit files and run builds and tests; it cannot push, call `gh`, `curl` or the web, or read `.env` files, tokens, keys, `~/.config` or `~/.ssh`. Its environment has no queue token, Slack webhook or other secret. It stops after 45 minutes.
4. On **done**, the runner runs `gofmt`, `go build ./...`, `go vet` and `go test` of the changed packages (through the Mac's shared test slot), and `npm ci`, typecheck, lint and tests when `web/` changed. Then it pushes a `feedback/fb-123-…` branch, opens a pull request whose body names the item by reference only, links it on the item (`in_progress`) and adds a short note for the sender to the thread. It never merges or deploys: the release owner merges and moves the item to `fixed`, and `/feedback release` moves it to `released`, which sends the released email.
5. Every outcome is posted to Slack (reference, outcome and link; never the feedback's text or the sender's address) when a webhook file is configured.
6. An item that fails twice in the same round (an error, failed checks, no result) goes to the owner with the error.

**Approving:** an instance administrator opens Admin → Feedback in the dashboard (needs approval is listed first), reads the item, its attachments, the thread and the reason, and presses Approve (with an optional note for the agent) or Decline (with the reason the sender reads). Approve and Decline need a signed-in session: API tokens and the triage token cannot approve. Both are recorded in the item's events with who and when.

**The sender** sees the thread in My feedback, labelled as the Stackurity team or the automated feedback agent, and can reply while the item is open. The reply goes through the same relay as status checks (`STACKURITY_FEEDBACK_URL/status`, one item with `reply`), so the website needs no change. A reply to a `needs_info` item puts it back to `new` for the agent.

**Install on the Mac (owner):**

1. Create a triage token in the dashboard's API (`POST /api/v1/admin/feedback-tokens` with `{"name":"feedback-agent","days":90}`) and save it with mode 0600 in `~/.config/stackurity/feedback-agent-token`. It expires after 90 days at most: renew it before then.
2. Optional: a Slack incoming webhook URL in `~/.config/stackurity/feedback-agent-slack-webhook` (0600), and `FEEDBACK_AGENT_CLAUDE_TOKEN_FILE` with a token from `claude setup-token` if the `claude` sign-in is not available to launchd.
3. `go build -o ~/.local/bin/stackurity-feedback-agent ./tools/feedback-agent` from an up-to-date clone.
4. Try one item without writing anything: `stackurity-feedback-agent -dry-run -item FB-123`.
5. Copy `tools/feedback-agent/com.stackurity.feedback-agent.plist` to `~/Library/LaunchAgents/`, replace `HOME_DIR`, and run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.stackurity.feedback-agent.plist`. The log is `~/code/feedback-agent-runs/agent.log`. To stop it: `launchctl bootout gui/$(id -u)/com.stackurity.feedback-agent`.

The runner reads `STACKURITY_FEEDBACK_API` (default `https://app.stackurity.dev/api/v1/admin/feedback`), `STACKURITY_FEEDBACK_TOKEN_FILE`, `FEEDBACK_AGENT_REPO` (a clone of this repository, default `~/code/stackurity-feedback`), `FEEDBACK_AGENT_WORK`, `FEEDBACK_AGENT_SLACK_WEBHOOK_FILE`, `FEEDBACK_AGENT_CLAUDE_TOKEN_FILE`, `FEEDBACK_AGENT_TEST_DATABASE_URL` (a throwaway PostgreSQL for Go tests that need one) and `FEEDBACK_AGENT_TEST_SLOT`.
