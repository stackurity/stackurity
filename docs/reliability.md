# Reliability of background work

A Stackurity server can stop at any moment: a crash, an out-of-memory kill, a node or pod eviction, `kill -9`, a lost database connection. This page says what happens to the work it was doing, what is guaranteed after a restart (or on another replica), and how that is tested.

In short: work resumes or fails visibly, data from the last good run stays available, and nothing is duplicated except a notification in flight, which can arrive twice with the same delivery id.

## Guarantees

### Jobs (feed syncs, evaluations, integration runs, image scans)

- Jobs live in the database and are claimed one at a time. A running job renews its lock every 5 minutes.
- If the server dies, the job is claimed again 30 minutes after the last renewal (the lock timeout), by any replica. The interrupted attempt is recorded as the job's last error: `attempt 2 of 5 was interrupted: worker <id> stopped renewing its lock (crashed, killed or lost the database)`.
- A job that fails with an error is retried with exponential backoff (1 minute, then 2, 4 and so on).
- After `max_attempts` (5) the job is marked failed, whether its attempts ended in errors or in crashes: a job that kills its server every time does not run forever. Failed jobs are listed under **Settings → Platform health** with their last error, raise a "jobs failed" problem there, and are counted in `stackurity_jobs{state="failed"}`.
- Handlers are idempotent, so a job that ran (fully or partly) before the crash can safely run again.

### Intelligence feeds

- Records are stored in batches of 500, each in its own transaction, as upserts. The KEV and endoflife.date catalogues are replaced in one transaction each.
- The feed's cursor and `last_success` move only after a sync has completed and the re-evaluation it calls for has been queued. An interrupted sync leaves both where they were, so the retried sync fetches the same changes again (from the old cursor, or the full archive again) and queues the re-evaluation again. Evaluating twice is harmless; never evaluating is not possible.
- Advisories stored before the interruption remain. A full archive interrupted halfway leaves some records already updated and the rest as they were: each record is complete on its own, and the next sync brings the rest.
- Findings do not change until an evaluation runs, so an interrupted sync never removes findings.
- The interruption is visible: when the next attempt starts, the feed's last error becomes `the sync started <time> UTC was interrupted before it finished`, which shows on **Intelligence**, in Platform health, in `stackurity_feed_failing` and, if the feed goes stale, as a feed incident. A successful sync clears it.

### Inventory ingest

- A collection (from the agent, CI, an integration or an SBOM import) is stored in one transaction: the asset, the collection, every inventory row, removals of packages that are gone, coverage, relations and the queued evaluation. A crash before the commit keeps none of it; the asset keeps its previous inventory and findings, and the client gets no `201` and sends again. A crash after the commit keeps all of it.
- Between ingest and evaluation, the asset has its new inventory and its previous findings. Its evaluation is a queued job, so it survives the crash, and the collection's result (`GET /api/v1/collections/{id}/result`, which CI gates read) says `pending` until the evaluation has run, and `scoring` until its findings have been prioritised: it is never reported as evaluated or clean early, and a gate never reads unscored priorities.

### Evaluation

- A finding is unique per inventory row and issue. Re-evaluating updates findings in place (same id, same history) and resolves those that no longer apply; running an evaluation twice changes nothing the second time.

### Notifications

- Delivery is at least once. Each delivery is claimed just before it is sent, under a 5-minute lease.
  - If the server dies before the receiver took the message in, it is sent once, by any replica, when the lease ends.
  - If the server dies after the receiver took it in but before recording that, it is sent again when the lease ends: the receiver gets it twice. Webhooks carry the same `X-Stackurity-Delivery` id both times, so receivers can deduplicate. One crash causes at most one extra send of the message that was in flight.
- Nothing is lost: a delivery stays pending until it is recorded as sent (or fails after 8 attempts and is listed as failed, to retry by hand).
- Each message is queued once per channel, so planning again after a crash does not queue it again: an urgent message is keyed by its route and the set of incidents it covers, a "connected" message by the assets, a summary by its route and scheduled time, an overdue message by its route and day, and a Jira event by its incident. One narrow exception repeats content rather than a message: a crash in the middle of planning, followed by new urgent issues in the next run, can repeat the earlier issues in the next urgent message.
- Jira issues are never duplicated (see [Jira](install.md#jira)).

### Periodic tasks (alert dispatcher, digests, feed and integration scheduling, housekeeping)

- A task runs on one replica at a time under a 2-minute lease, renewed every 30 seconds. If that replica dies, another takes the task over once the lease has expired, and runs it at once because the interrupted run never finished. With one replica, the restarted server does the same.
- The interrupted run records no outcome. A task that keeps failing or never completes is flagged in Platform health once it has not succeeded within three times its interval.

### Database outages

- The server does not exit or need a restart when PostgreSQL goes away: `/readyz` answers 503 until the database answers again, then the same process resumes. Requests that need the database answer 503, which agents, CI and the dashboard treat as temporary.
- Work in flight is treated as if its server had died: leases and locks that expire during the outage hand the work over as described above, and nothing is recorded as done that was not.

## How it is tested

`internal/crashtest` runs the real server binary and kills it with `SIGKILL` at chosen moments, then restarts it and checks the database, the fake upstreams and a webhook receiver that counts what it processed. Each scenario gets a fresh database; OSV, KEV, endoflife.date and the webhook receiver are local HTTP servers. The tests need the `crash` build tag and a PostgreSQL the test may create databases in:

```sh
STACKURITY_TEST_DATABASE_URL=postgres://stackurity:secret@127.0.0.1:5432/stackurity_test?sslmode=disable \
  go test -tags crash -count=1 -v ./internal/crashtest
```

CI runs them in the `crash` job of `.github/workflows/ci.yml`, together with the operational drills of [operations.md](operations.md) (`TestUpstreamOutage`, `TestNotificationProviderOutage`, `TestAgentStopsReporting`). They take about four minutes.

So that a lease or lock timeout passes in seconds, the tests start the server with `STACKURITY_TEST_TIMINGS=job-lock=3s,task-lease=2s,tick=200ms,poll=200ms,delivery-lease=2s,alerts=1s`. The guarantees are the same; only the clocks are shorter. Never set it in production: the server logs a warning when it is set.

| Scenario | Killed | Checked after restart |
|---|---|---|
| Feed refresh | During the download of a 30,000-record OSV archive (served slowly), then again while the retried import is storing records | The 2,002 earlier advisories, the asset's findings (same ids, still open), the cursor and `last_success` are unchanged after each kill. The feed's and the job's last error report the interruption. The job is claimed again only after the lock timeout, and the third attempt completes: all records stored once, the cursor moves to the new download's start, the new advisory's finding opens, and no finding is duplicated. |
| Inventory ingest | While a 40,000-package collection is being written (during `INSERT INTO inventory`); then after it is stored, before its evaluation | First kill: no collection, inventory row or component of the batch was kept, findings unchanged; the agent's resend succeeds. Second kill: the new inventory is complete, one evaluation is queued, and the collection reads `pending`. The restarted server evaluates it: the upgraded package's finding resolves (same finding), the new one opens. |
| Notification delivery | With a webhook request in flight, before the receiver processed it | The delivery was pending after one attempt; after the restart it is received exactly once, no sooner than its lease end. |
| | After the receiver processed it, before the server recorded it | It is received exactly twice, with the same `X-Stackurity-Delivery` id, and has 2 attempts. Every other delivery is received once, every delivery ends `sent`, and no incident event is queued twice. |
| Periodic tasks | Two replicas; the one running the alert dispatcher (blocked in a webhook send) | The other replica takes the task over no earlier than the dead replica's lease end, finishes it without error, and sends everything. |
| Jobs | A feed sync whose download never finishes, killed on every attempt | Each attempt is claimed at least one lock timeout after the last renewal; after the fifth the job is failed (no sixth download), with the interruption as its last error, on the health report and in `stackurity_jobs{kind="feed.sync",state="failed"}`. |
| Database outage | Not killed: PostgreSQL is cut off (every connection closed, new ones refused) for longer than the job lock, task lease and delivery lease, during a slow OSV import, then with a webhook in flight | While it is down: the process stays up, `/healthz` answers, `/readyz` answers 503, `/metrics` reports `stackurity_database_up 0`, API requests answer 503 at once. Afterwards the same process is ready again, the alerts task runs, the import is retried with the interruption recorded and completes (earlier advisories and findings kept, none duplicated), and the webhook is sent again with the same delivery id. Every database connection terminated at once (a PostgreSQL restart): the next requests and ingests succeed. |

Four problems were found this way and fixed:

- A job killed on every attempt was claimed again after each lock timeout forever, never failed and showed no error. It now fails after `max_attempts`, and interrupted attempts are recorded.
- An interrupted feed sync showed nothing: no error on the feed until the retry finished. The next attempt now records the interruption.
- During a database outage, requests with valid API tokens or sessions were answered 401 (the failed lookup was taken for an unknown credential), so agents and CI dropped their batches instead of retrying, and the dashboard signed people out. They now get 503.
- A feed sync interrupted (or failing to queue jobs) after moving its cursor but before queueing re-evaluation lost the re-evaluation until the daily one. Re-evaluation is now queued before the cursor moves. This window is too short to hit reliably by killing the process, so it is covered by `TestChangedBeforeCursorMoves` in `internal/intel` instead.

Unit tests in the default suite cover the same rules without processes: `internal/worker` (leases, lock renewal, interrupted jobs failing), `internal/notify` (delivery claims across replicas) and `internal/intel` (the feed bookkeeping above).
