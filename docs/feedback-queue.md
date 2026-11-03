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
| `STACKURITY_FEEDBACK_STORAGE_MAX_MB` | Cap on the attachments kept (default 5120). Above it, new attachments are refused with 507 and feedback without attachments is still taken. `GET /api/v1/admin/feedback` reports `storage.used_bytes` and `max_bytes`. |

## Items

Each item has an id shown as `FB-123`. Its fields:

- **source:** `cloud`, `self_hosted` or `website`, with the `version` and `edition`;
- **kind:** issue, feature or question;
- **description** and **contact_email** (optional);
- **page, browser and viewport**, captured automatically;
- **attachments**;
- **status**, with `resolution` (shown to the sender) and `triage_notes` (internal);
- **link** to the pull request or issue, plus `duplicate_of` and `fixed_in`;
- **timestamps:** created, updated, triaged and closed.

Every change is recorded in `feedback_events`.

| Status | The sender sees |
|---|---|
| `new` | Received |
| `triaged`, `needs_owner` | Under review |
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
