# Operations: alerts, runbooks and drills

How to watch a Stackurity installation, what each recommended alert means and what to do about it, and drills for the failures that matter most: the database going away, a full disk, a long upstream outage, a notification provider that stops accepting messages and agents that stop reporting.

What happens to background work when a server dies is in [reliability.md](reliability.md); the health endpoints and the metrics are listed in [install.md](install.md#health).

## What to watch

| Signal | Where | Use it for |
|---|---|---|
| `GET /healthz` | API port | Liveness: the process answers. Never depends on the database |
| `GET /readyz` | API port | Readiness: the database answers a ping within 2 seconds, else 503 `database_unavailable`. Container health check and Kubernetes readiness probe |
| Platform health | **Settings → Platform health** (instance admins), `GET /api/v1/admin/health` | Problems with their errors: stale or failing feeds, background tasks that do not succeed, failed jobs, job and notification backlogs, failed notifications, failing channels |
| Platform incidents | The operators' workspace (`STACKURITY_PLATFORM_WORKSPACE`) | Critical platform problems as incidents, sent through that workspace's notification routes |
| Metrics | `STACKURITY_METRICS_ADDR` (`/metrics`, no authentication, separate listener) | Everything above as Prometheus series, plus HTTP, database pool and process metrics |
| Memory profiles | `STACKURITY_METRICS_ADDR` (`/debug/pprof/heap`, `/debug/pprof/goroutine`) | What holds memory now; see [Memory](#memory) |
| Server log | stdout, JSON by default | Errors with context; each problem below names the lines to look for |

Platform incidents are raised by the alerts task itself, so they stop when that task is stuck or the database is down. Alert on the metrics from outside as well: that is what the rules below are for.

### How much notification traffic to expect

Notifications to people are grouped (see [the API reference](api.md#incidents-and-notifications)). Per route, at most:

- one `urgent` message per run of the `alerts` task (every minute), and only when that run found new urgent issues; over `max_per_hour` they are held and counted in the next summary;
- one `summary` a day (or a week), skipped when nothing changed;
- one `overdue` message a day (licensed, routes with escalation);
- one `connected` message per run for the assets whose first scan finished in it.

Resolved incidents and escalations are not sent one by one, so upgrading a server that closes thousands of findings, or thousands of incidents passing their deadline at once, produces at most one message per route. Jira channels are the exception: they keep one issue per incident, and each escalation adds a comment to its issue. If a channel still receives more than a few messages an hour, look at `SELECT route_id, event, count(*) FROM deliveries WHERE created_at > now() - interval '1 day' GROUP BY 1, 2 ORDER BY 3 DESC;`: usually two routes send to the same channel, and one of them can be deleted or narrowed.

## Recommended alerts

[`deploy/prometheus/stackurity-alerts.yml`](../deploy/prometheus/stackurity-alerts.yml) holds the rules. Load it with `rule_files` in `prometheus.yml`, or with the Helm chart set `metrics.enabled=true` and `metrics.prometheusRule.enabled=true` to get the same rules as a `PrometheusRule` (created only when the cluster serves `monitoring.coreos.com/v1`; add `metrics.prometheusRule.labels` matching your Prometheus's `ruleSelector`).

Every alert has a `severity` label to route on (`critical`: page someone; `warning`: look today; `info`: look this week), a `summary`, a `description` and a `runbook_url` pointing at its section below. Values read from the database are the same on every replica, so those alerts drop the `instance` and `pod` labels and fire once per installation.

The rules are unit tested with `promtool test rules` ([`stackurity-alerts_test.yml`](../deploy/prometheus/stackurity-alerts_test.yml), the `alerts` job in CI, using a pinned and checksummed Prometheus release). `deploy/prometheus/rules_test.go` checks that every alert has a runbook here and a test where it fires, that every metric it uses is one the server exports, and that the chart's copy (`deploy/helm/stackurity/files/stackurity-alerts.yml`) is identical. To change a threshold, edit the rules file, copy it to the chart and adjust the test.

| Alert | Severity | Fires when | For |
|---|---|---|---|
| [StackurityTargetDown](#stackuritytargetdown) | critical | A scrape target whose job name contains `stackurity` is down | 5m |
| [StackurityMetricsAbsent](#stackuritymetricsabsent) | critical | No `stackurity_build_info` series at all | 10m |
| [StackurityRestarting](#stackurityrestarting) | warning | A server started 3 or more times in 30 minutes | |
| [StackurityMixedVersions](#stackuritymixedversions) | warning | Replicas report more than one version | 30m |
| [StackurityDatabaseDown](#stackuritydatabasedown) | critical | `stackurity_database_up == 0` | 2m |
| [StackurityMetricsIncomplete](#stackuritymetricsincomplete) | warning | Database sections of the scrape fail while the database is up | 15m |
| [StackurityDatabasePoolSaturated](#stackuritydatabasepoolsaturated) | warning | Over 90% of a replica's database connections in use | 10m |
| [StackurityDatabasePoolWaits](#stackuritydatabasepoolwaits) | warning | Acquiring a connection takes over 100 ms on average | 10m |
| [StackurityHTTPErrors](#stackurityhttperrors) | warning | Over 5% of API requests answer 5xx (probes left out) | 10m |
| [StackurityIngestErrors](#stackurityingesterrors) | warning | `/api/v1/ingest` or `/api/v1/sbom/import` answers 5xx | 15m |
| [StackurityHealthCritical](#stackurityhealthcritical) | critical | Platform health reports a critical problem | 15m |
| [StackurityVulnerabilityFeedStale](#stackurityvulnerabilityfeedstale) | critical | A vulnerability feed is past its freshness limit | 10m |
| [StackurityFeedStale](#stackurityfeedstale) | warning | An EPSS, release or lifecycle feed is past its freshness limit | 30m |
| [StackurityFeedFailing](#stackurityfeedfailing) | warning | A feed's syncs fail but its data is still fresh | 2h |
| [StackurityTaskNotSucceeding](#stackuritytasknotsucceeding) | critical | A periodic task's last success is older than 3 intervals (at least 10 minutes) | 5m |
| [StackurityTaskNeverSucceeded](#stackuritytaskneversucceeded) | warning | A registered periodic task has never succeeded | 1h |
| [StackurityTaskFailing](#stackuritytaskfailing) | warning | A periodic task failed 3 runs in a row | 5m |
| [StackurityJobsFailed](#stackurityjobsfailed) | warning | Jobs ran out of attempts in the last 24 hours | 5m |
| [StackurityJobQueueBacklog](#stackurityjobqueuebacklog) | warning | The oldest due job has waited over 30 minutes | 5m |
| [StackurityJobQueueStalled](#stackurityjobqueuestalled) | critical | The oldest due job has waited over 2 hours | 10m |
| [StackurityNotificationsFailed](#stackuritynotificationsfailed) | warning | Notifications ran out of attempts in the last 24 hours | 5m |
| [StackurityNotificationChannelFailing](#stackuritynotificationchannelfailing) | warning | An enabled channel's last send failed | 30m |
| [StackurityNotificationsBacklog](#stackuritynotificationsbacklog) | critical | A due notification has waited over 15 minutes | 5m |
| [StackurityAssetsStoppedReporting](#stackurityassetsstoppedreporting) | warning | 5 or more assets went stale within an hour | |
| [StackurityAssetsStale](#stackurityassetsstale) | info | Any asset has been stale for a day | 24h |

The thresholds follow the server's own limits: feeds are stale after their `stale_after` (6 hours for OSV ecosystems and distributions, 12 hours for CISA KEV, 48 hours for Amazon Linux, 72 hours for FIRST EPSS and the package registries, 7 days for endoflife.date); periodic tasks are flagged after three intervals, as Platform health does; the job backlog warning matches Platform health's 30 minutes.

## Runbooks

Useful everywhere: Platform health shows the error behind most problems. For the database, connect with `psql` as the login role (the owner); it sees every workspace. The server's own role (`stackurity_app`) only sees rows of the scope it sets.

### StackurityTargetDown

Prometheus cannot scrape a server's metrics listener.

1. Is the process running? `docker compose ps`, `kubectl get pods -l app.kubernetes.io/name=stackurity`. Look at its last log lines and exit code; `137` with an `OOMKilled` reason means the memory limit is too low for the largest feed import or ingest.
2. If it runs, check that `STACKURITY_METRICS_ADDR` is set and reachable from Prometheus (network policy: `metrics.from` in the chart).
3. If several replicas run and only one is down, the others carry on: background work moves to them within a lease (2 minutes for tasks, 30 minutes for a running job).

If your scrape job's name does not contain `stackurity`, change the selector in the rule.

### StackurityMetricsAbsent

No server reports metrics: every replica is down, or Prometheus stopped scraping them (a renamed job, a ServiceMonitor that no longer matches). Check as for [StackurityTargetDown](#stackuritytargetdown), then the scrape configuration.

### StackurityRestarting

A server keeps restarting. The common causes, from its last log lines before each start:

- `connect to database` at start: the database is unreachable or refuses the login ([database interruption](#database-interruption)).
- Killed without a log line: out of memory. Look for `heap growing during background work` just before it: it names the job or task ([Memory](#memory)). The kernel log (`journalctl -k | grep -i oom`) confirms the kill.
- `no space left on device`: [disk exhaustion](#disk-exhaustion).
- A migration error after an upgrade: stop every replica and follow [Rolling back](install.md#rolling-back).

### StackurityMixedVersions

Two versions run against the same database. That happens during a rolling update, which Stackurity does not support: a new schema is not guaranteed to work with the previous version's code. Stop every replica of the old version (the chart's `Recreate` strategy and Compose do this). If an upgrade is half done, finish it or roll it back as in [Upgrading](install.md#upgrading).

### StackurityDatabaseDown

The server cannot reach PostgreSQL. While it lasts:

- `/readyz` answers 503, so a load balancer or Kubernetes stops sending traffic; `/healthz` still answers 200 and the process keeps running.
- API requests answer 5xx (credentials cannot be checked: `503 unavailable`); agents and CI retry their submissions.
- Background work pauses. Leases and locks expire if the outage outlasts them, and the work is picked up again afterwards: an interrupted job is retried with the interruption as its error, a notification in flight may be sent twice with the same `X-Stackurity-Delivery` id.
- The log shows `claim periodic tasks` and `claim job` errors.

What to do: restore the database (see [database interruption](#database-interruption) for what to check). The server reconnects by itself; do not restart it unless it stays unready after the database answers again. Afterwards, check Platform health for failed jobs and failed notifications.

### StackurityMetricsIncomplete

Some database sections of the scrape fail although the database answers, so the alerts built on them cannot fire. The server log says which section (`metrics: read failed`, `section=`). Typical causes: a statement timeout set on the role, a missing grant after a manual restore (start the server once so it restores the grants), or a disk problem on the database (see [disk exhaustion](#disk-exhaustion)).

### StackurityDatabasePoolSaturated

A replica uses nearly all of its 20 database connections. Requests and jobs then wait for a connection (see [StackurityDatabasePoolWaits](#stackuritydatabasepoolwaits)).

1. Look for slow queries on the database: `SELECT pid, now() - query_start AS running, state, left(query, 120) FROM pg_stat_activity WHERE datname = 'stackurity' ORDER BY running DESC;`
2. Look for locks: `SELECT * FROM pg_locks WHERE NOT granted;`
3. If the load is legitimate (many agents reporting at once), add replicas. Make sure PostgreSQL's `max_connections` allows 20 per replica plus your own connections.

### StackurityDatabasePoolWaits

Getting a connection takes long on average. Same causes and steps as [StackurityDatabasePoolSaturated](#stackuritydatabasepoolsaturated); also check the database's CPU and I/O.

### StackurityHTTPErrors

Over 5% of API requests fail with a server error.

1. `stackurity_http_requests_total{code="5xx"}` by `route` shows which endpoints.
2. The log has a `request failed` line with the error and `request_id` for each 500; 503s with `could not check credentials` mean the database did not answer.
3. If the database is down, follow [StackurityDatabaseDown](#stackuritydatabasedown) instead.

### StackurityIngestErrors

Inventory submissions fail with server errors. Agents keep their batch and retry (four attempts with backoff), and CI scans fail or retry depending on the pipeline, but the inventory is not updated. Look at the log lines for `/api/v1/ingest` (`request failed`). A full database disk shows here first ([disk exhaustion](#disk-exhaustion)).

### StackurityHealthCritical

Platform health has a critical problem: a vulnerability feed is stale, no vulnerability intelligence was ever synced, or a background task has not succeeded within three intervals. Open **Settings → Platform health**: each problem has its error. The more specific alerts usually fire as well; follow their runbooks.

### StackurityVulnerabilityFeedStale

A vulnerability feed has not synced within its freshness limit. New advisories for that ecosystem are not matched. Nothing is cleared: findings already open stay open, every workspace gets a P2 feed incident, the All issues page says intelligence is stale, and each affected asset's coverage says its components were checked against stale intelligence.

1. **Intelligence** (or `GET /api/v1/feeds`) shows the feed's last error.
2. HTTP 5xx, timeouts or DNS errors: the upstream or the way to it is down. Check outbound access from the server (`curl -sI https://osv-vulnerabilities.storage.googleapis.com/` from the container), proxies and firewalls; see [network.md](network.md). If it is the upstream itself, wait: see [prolonged upstream outage](#prolonged-upstream-outage).
3. HTTP 404 or a parse error: the source changed; check for a newer Stackurity release.
4. No error and no recent attempt: the scheduler is not running; see [StackurityTaskNotSucceeding](#stackuritytasknotsucceeding) for `enqueue-due-feeds` and [StackurityJobQueueBacklog](#stackurityjobqueuebacklog).

Once fixed, **Refresh** on the Intelligence page (`POST /api/v1/feeds/{name}/refresh`) queues a sync at once; the feed incident resolves after it succeeds.

The operators' workspace (`STACKURITY_PLATFORM_WORKSPACE`) is told both ways, once each: its routes with the `problems` event get the stale feed right away, and the same routes get a `resolved` message ("Intelligence feed kev:cisa has recovered") when it syncs again. Both reach only routes whose minimum priority is P2 or lower for a vulnerability feed (feed incident P2), or P3 or lower for the others (P3); a route with a P1 minimum, the default, gets neither. A stall that ends before it was announced (between two dispatcher cycles) gets no recovery message. The server logs `intelligence feed is stale` at warn level and `intelligence feed recovered` at info level, once each, with the feed's name.

### StackurityFeedStale

As [StackurityVulnerabilityFeedStale](#stackurityvulnerabilityfeedstale), for FIRST EPSS (exploit prediction, feed kind `prediction`), the package registries (latest releases) or endoflife.date (lifecycle). CISA KEV is a `vulnerability` feed and alerts as one. Priorities that depend on predicted exploitation, upgrade recommendations or end-of-life dates are older than promised; a stale EPSS feed keeps its last scores, opens a P3 feed incident and is a warning on Platform health.

### StackurityFeedFailing

A feed's recent syncs fail, but its last success is still within its freshness limit, so nothing is stale yet. Usually a short upstream problem that solves itself; if it lasts, check the error as for a stale feed before it turns into one.

### StackurityTaskNotSucceeding

A periodic task (`alerts`, `alert-digest`, `enqueue-due-feeds`, `ensure-feeds`, `enqueue-due-integrations`, `mark-stale-assets`, `housekeeping`, `daily-evaluation`, `prune-affected-values`, `platform-fallback`, `update-check`) has not succeeded for three of its intervals. Either every run fails, or one replica holds its lease and never finishes (a stuck lease). For `alerts` this means no notifications at all are sent; for `alert-digest`, held messages of deleted routes wait (summaries are also planned by `alerts`).

1. Platform health's **Background tasks** table shows its last error, last start and whether it runs now. Or: `SELECT name, locked_by, locked_until, last_started_at, last_success_at, consecutive_failures, last_error FROM periodic_tasks ORDER BY name;`
2. A last error: fix its cause (it often names the workspace and the integration or channel involved).
3. No error, `locked_by` set and `last_started_at` long ago: the run hangs on that replica (`locked_by` names the host and process). Leases last 2 minutes and are renewed every 30 seconds while the run is alive, so a dead replica's lease expires by itself; a live one that hangs keeps renewing. Restart that replica: another takes the task over when the lease ends and runs it at once.
4. Nothing ever starts: no server is running its worker; check that a server runs and is connected to this database.

### StackurityTaskNeverSucceeded

A task has been registered for an hour without one successful run. Tasks run at once when they are first registered, so this means every run failed: follow [StackurityTaskNotSucceeding](#stackuritytasknotsucceeding). `update-check` fails on installations that cannot reach GitHub; set `STACKURITY_UPDATE_CHECK=off` or `STACKURITY_UPDATE_URL` there.

### StackurityTaskFailing

A task failed its last three runs but has succeeded recently enough not to be overdue. Platform health shows the error. Fix it before the task becomes overdue.

### StackurityJobsFailed

Jobs ran out of their 5 attempts (retries after 1, 2, 4 and 8 minutes, or after each interrupted attempt). Platform health lists the latest failures with their workspace and error; `SELECT id, kind, workspace_id, attempts, last_error, failed_at FROM jobs WHERE failed_at > now() - interval '1 day' ORDER BY failed_at DESC;` lists them all.

- `feed.sync`: an upstream problem, see [StackurityVulnerabilityFeedStale](#stackurityvulnerabilityfeedstale). The next scheduled refresh queues a new sync.
- `integration.run`, `image.scan`: the integration's credentials, target or network; the integration shows the error, and its next scheduled run tries again (**Run now** to try at once).
- `evaluate`: a bug or a database problem; the daily evaluation runs everything again. Report it with the error.
- An error saying an attempt `was interrupted`: the server running it died or lost the database every time, often an out-of-memory kill on a very large job ([reliability.md](reliability.md)).

The alert clears 24 hours after the last failure.

### StackurityJobQueueBacklog

The oldest due job has waited over 30 minutes for a worker. Workers are busy with long jobs (a first OSV import, a large image scan), stuck, or not running. `SELECT kind, count(*), min(run_at) FROM jobs WHERE done_at IS NULL AND failed_at IS NULL AND run_at <= now() GROUP BY 1;` shows what waits; `SELECT id, kind, locked_by, locked_at FROM jobs WHERE locked_at IS NOT NULL AND done_at IS NULL AND failed_at IS NULL;` what runs. A burst after an outage drains by itself. Persistent backlog: add replicas.

### StackurityJobQueueStalled

The backlog has lasted over two hours: evaluations, feed syncs and integration runs are not happening. Check that at least one server is running and ready, then follow [StackurityJobQueueBacklog](#stackurityjobqueuebacklog).

### StackurityNotificationsFailed

Notifications ran out of their 8 attempts (retried after 30 seconds, then 1, 2, 4, 8, 16 and 32 minutes; at once when the receiver rejects credentials) and were not delivered. Each workspace's delivery log (**Settings → Integrations**, **Delivery log**, `GET /api/v1/deliveries?status=failed`) shows each one with its error, and **Retry** (`POST /api/v1/deliveries/{id}/retry`) sends it again once the cause is fixed. Common causes: an expired webhook secret or bot token, a removed Slack or Teams channel, a Jira project or permission change, a mail relay refusing the sender. The people the incidents were for may not know about them: tell them, or retry.

### StackurityNotificationChannelFailing

An enabled channel's last send failed and has stayed failed for 30 minutes. Messages to it are being retried; they fail after 8 attempts (about an hour) and then fire [StackurityNotificationsFailed](#stackuritynotificationsfailed). The channel shows its last error under **Settings → Integrations**; the **Send test** button sends a test message once it is fixed.

### StackurityNotificationsBacklog

A due notification has not been picked up for over 15 minutes, so people are not told about incidents. Deliveries deferred by quiet hours or held for the next summary are not counted. The `alerts` task is stuck or failing: follow [StackurityTaskNotSucceeding](#stackuritytasknotsucceeding) for it. Platform incidents cannot report this, because they are sent by the same task.

### StackurityAssetsStoppedReporting

At least five more assets went stale within an hour (an asset is stale when nothing reported it for `STACKURITY_STALE_AFTER`, 48 hours by default). Many at once usually has one cause:

- Agents cannot reach the server: a DNS, firewall, proxy or certificate change. Run `stackurity diagnostics --server URL` on one of the hosts.
- Their tokens were revoked, or their workspace was disabled (the agent logs `HTTP 401`).
- Ingest fails on the server ([StackurityIngestErrors](#stackurityingesterrors)).
- An integration (repositories, images, AWS, Kubernetes) fails: its last error is on the integration.

### StackurityAssetsStale

Some assets have not reported for over a day after being marked stale. Their inventory and findings are out of date, their coverage says so, and each workspace has a collection incident for them. Decommissioned hosts belong deleted (or merged), so they stop counting; others need their agent or integration fixed.

### Sign-in refused: too many login attempts

Failed sign-ins back off per account and client address (five are free, then 30 seconds doubling to 15 minutes), and an account takes at most 100 failures every 15 minutes from all addresses together ([limits](install.md#running-several-replicas)). The answer carries `Retry-After`.

- Look at the audit log for `auth.login_failed`, `auth.login_backoff` and `auth.login_locked` on the account. A backoff only holds up the address that failed: the owner can sign in from another network, through single sign-on, or after the wait. The account cap does not apply to addresses the account signed in from in the last 30 days. A successful sign-in clears its address's count.
- If every event shows the same private address (your proxy, a tunnel connector, or the Docker bridge gateway), the server is not seeing client addresses, and everyone shares one count. Check `STACKURITY_TRUST_PROXY=true`, that `STACKURITY_TRUSTED_PROXY_HEADER` is the header your proxy sets, and that the proxy's address is in `STACKURITY_TRUSTED_PROXIES`; the server logs a warning naming an untrusted peer that sent the header ([Client addresses behind a proxy](install.md#client-addresses-behind-a-proxy)).
- To lift every sign-in backoff and account cap at once (for example after fixing the above), connect with `psql` and run `DELETE FROM rate_limits WHERE key LIKE 'login-fail:%' OR key LIKE 'login-account-fail:%';`. Keys are hashed, so one account cannot be picked out.

## Memory

The server's memory is mostly the Go heap. Background work is built to hold a bounded amount whatever the data: a vulnerability feed sync stores OSV records in batches of at most 500 records and 16 MiB of JSON (Ubuntu kernel records run to megabytes each), and an evaluation reads a package's advisories for the release it evaluates only, and keeps them only while it evaluates that package's rows.

**Which work used the memory.** While a job or periodic task runs, the worker reads the heap every second. When the heap has grown more than 256 MiB since the work started, it logs one warning while the work is still running, so the name is in the log even if the process is then killed:

```
level=WARN msg="heap growing during background work" work="job feed.sync" job=657 heap_start_mib=60 heap_now_mib=420 grew_mib=360 threshold_mib=256 running="[job feed.sync task alerts]"
```

and, when it ends, `background work made the heap grow` with the peak. `running` lists everything that was running at the time: the growth belongs to one of them. Set `STACKURITY_HEAP_WARN_MIB` to change the threshold (in MiB), or to `off`.

**Profiles.** With `STACKURITY_METRICS_ADDR` set, the same private listener as `/metrics` also serves Go's heap and goroutine profiles. They are never served on the API port, and nothing else from `net/http/pprof` (no CPU profile or trace) is served at all. The listener has no authentication: keep it on a private network, as for `/metrics`.

```sh
# from the host (Docker: publish the metrics port to 127.0.0.1 only, or docker exec)
go tool pprof -top http://127.0.0.1:9090/debug/pprof/heap      # what holds memory
curl -s 'http://127.0.0.1:9090/debug/pprof/heap?gc=1&debug=1' | head   # text, after a GC
curl -s 'http://127.0.0.1:9090/debug/pprof/goroutine?debug=2' > goroutines.txt  # every goroutine's stack
```

Take a heap profile while the warning above is current: it shows which function holds the memory.

**GOMEMLIMIT.** Set it to about 70% of the container's memory limit (`GOMEMLIMIT=1100MiB` for a 1.5 GiB limit). The rest covers what the Go heap does not count: goroutine stacks, the runtime, the WebAssembly runtime for stack packs, and buffers. It is a soft limit: the garbage collector works harder as the heap nears it, which smooths peaks of garbage, but it cannot free memory that is still in use. Work that needs more than the container has is still killed, so treat a kill with `GOMEMLIMIT` set as a bug and report it with the warning line and a heap profile.

## Maintenance

### Reclaiming advisory space after upgrading

Before migration `0036`, every feed sync deleted and re-inserted the package rows of every advisory it read, and the stored entries carried fields nothing reads. On a large installation `advisory_packages` grew to several gigabytes, a large part of it dead rows. Since `0036`, syncs write only what changed and an entry is stored once, so the table stops growing, but PostgreSQL does not give the old space back on its own: the table file keeps its size until it is rewritten. Physical backups, snapshots and copies of the database carry that space.

1. **Wait for one sync of every OSV feed after the upgrade.** The migration makes the next sync of each OSV feed read its full archive once and rewrite its rows in the new form. On **Intelligence**, every `osv:` feed's last success must be later than the upgrade. Ubuntu takes longest.
2. **Check what there is to reclaim** (optional):

   ```sql
   SELECT pg_size_pretty(pg_total_relation_size('advisory_packages')) AS now,
          count(*) AS rows,
          count(*) FILTER (WHERE affected_hash IS NULL) AS old_rows
   FROM advisory_packages;
   ```

   `old_rows` should be 0 or close to it (rows of advisories that are no longer in any archive keep the old form; they are read as before). Expect roughly 190 bytes per row, including indexes and `affected_values`, after the rewrite.
3. **Rewrite the tables in a quiet moment:**

   ```sql
   SET lock_timeout = '10s';  -- give up rather than queue behind a long query
   VACUUM FULL advisory_packages;
   VACUUM FULL advisories;
   VACUUM FULL affected_values;
   ```

   Each command holds an exclusive lock on its table while it copies the live rows into a new file and rebuilds its indexes. While `advisory_packages` or `advisories` is locked, evaluations, feed syncs, the finding page and the second check wait for it; they continue when it finishes, and nothing fails unless it waits longer than a job's timeout (minutes, not seconds). Ingest, sign-in and lists that do not read advisories are not affected. The time is about one read of the old file plus one write of the new, much smaller one: 16 seconds for a 1.1 GB table of 670,000 rows on a laptop, a few minutes for 3.5 million rows on a server with an SSD. It needs free disk space for the new copy (a fraction of the old size) until it finishes.

   `pg_repack` avoids the long lock (it locks each table only briefly at the start and the end), but it needs a primary key or a unique index on NOT NULL columns, and `advisory_packages` has neither. Once `old_rows` is 0, one can be added without a long lock and removed afterwards: add `CHECK (affected_hash IS NOT NULL) NOT VALID`, `VALIDATE` it, `ALTER COLUMN affected_hash SET NOT NULL` (instant with the validated check), drop the check, `CREATE UNIQUE INDEX CONCURRENTLY` on `(advisory_id, ecosystem, name, affected_hash)`, run `pg_repack -t advisory_packages -t advisories -t affected_values` without `--order-by` (the matcher reads a package's rows in stored order), then drop the index and the NOT NULL. On the test data the whole sequence took 36 seconds, the repack itself 21. A plain `VACUUM` (no lock) does not shrink the file, but it makes the dead space reusable; the table then stays at its current size.

### Verifying the audit log

The audit log is append-only and each workspace's events form a hash chain (migration `0052`; [security-audit.md, Audit log](security-audit.md#audit-log)). Check it with

```sh
stackurity admin verify-audit                 # every workspace, and the platform's own events
stackurity admin verify-audit --workspace 3   # one workspace; --workspace 0 is the platform's events
```

It reads one consistent snapshot, so it can run while the server works, and prints one line per chain:

```text
platform: ok, 41 events verified (ids 9120 to 9311)
workspace 1: ok, 1532 events verified (ids 9118 to 9310); 210544 earlier events not chained
workspace 3: BROKEN at event 9204 (chain position 17): hash does not match the event's content: the event was changed; 16 events before it verified (ids 9150 to 9198)
```

"Earlier events not chained" are those recorded before the upgrade to the release with migration `0052`: they are kept as they were. The command exits with status 1 when any chain is broken. A break means someone with database owner or superuser rights changed or removed events: treat it as an incident (keep a `pg_dump` and the database logs, then follow [Tenant-isolation incidents](security-audit.md#6-tenant-isolation-incidents) for the triage). Running it daily from cron and keeping its output somewhere else (a log system, a ticket) also keeps a record of each chain's newest hash outside the database.

Removing audit events on purpose (a retention policy of your own) is described under [Who may remove audit events](security-audit.md#audit-log).

## Drills

Run these on a staging installation, or in production during a quiet window with people watching. Each lists the steps, what you should see and how it is checked automatically. The commands assume the Compose install in `deploy/`; with Kubernetes, use the matching `kubectl` commands.

### Database interruption

PostgreSQL stops for a few minutes, as in a failover, a crash or maintenance.

1. Note the time and start a feed refresh so there is work in flight (**Intelligence → Refresh** on an OSV feed).
2. Stop the database: `docker compose stop postgres` (Kubernetes: scale the database down, or block it with a network policy).
3. Wait at least 5 minutes, longer than the 2-minute task lease and the 5-minute delivery lease.
4. Start it again: `docker compose start postgres`.

Expected while it is down:

- `curl -s -o /dev/null -w '%{http_code}' localhost:8080/readyz` answers `503`; `/healthz` answers `200`. The process keeps running: Compose marks the container unhealthy (its health check uses `/readyz`) without restarting it, and in Kubernetes the readiness probe takes the pod out of the Service while the liveness probe (`/healthz`) leaves it running.
- `stackurity_database_up` is 0 and [StackurityDatabaseDown](#stackuritydatabasedown) fires after 2 minutes; the scrape itself still succeeds.
- API requests and the dashboard answer 503; nobody is signed out and agents keep their batches to retry.
- The log has one `claim periodic tasks` error per tick and `claim job` errors; nothing else is written.

Expected afterwards, without restarting Stackurity:

- `/readyz` answers 200 within seconds of the database accepting connections, and the alert resolves.
- The `alerts` task succeeds again within a minute (Platform health, Background tasks).
- A job that was running is retried once its 30-minute lock expires, with `attempt 1 of 5 was interrupted: worker ... stopped renewing its lock` as its last error, and then completes. An interrupted feed sync shows `the sync started ... was interrupted before it finished` until the retry succeeds. Findings and earlier advisories are unchanged meanwhile.
- A notification that was being sent is sent again after its lease ends; a receiver can get it twice, with the same `X-Stackurity-Delivery` id. No notification is lost.

If `/readyz` stays at 503 after the database is back, check that the server can connect (`docker compose logs stackurity`), then restart it.

Automated: `TestDatabaseOutageDuringFeedSync` and `TestDatabaseOutageDuringDelivery` in `internal/crashtest` cut the server off from PostgreSQL (through a proxy, closing every connection and refusing new ones) for longer than the job lock, task lease and delivery lease, in the middle of an OSV import and with a webhook in flight, and check all of the above with shortened timings. The first also terminates every database connection at once, as a PostgreSQL restart does, and checks that the next requests and ingests succeed. Writing it found that requests with valid credentials were answered 401 during an outage, so agents dropped their batches and people were signed out; they now get 503.

### Disk exhaustion

**The database disk fills up.** PostgreSQL then refuses writes (`could not extend file ...: No space left on device`), and may shut down if it cannot write its WAL.

1. On staging, give PostgreSQL a small volume (for example a 1 GiB volume or `tmpfs` with `size=1g` for its data directory) and fill it: `docker compose exec postgres sh -c 'dd if=/dev/zero of=/var/lib/postgresql/data/filler bs=1M count=10000'` until it fails.
2. Submit an inventory (`stackurity scan . --server ...`) and trigger a feed refresh.

Expected: reads keep working and `/readyz` keeps answering 200 while PostgreSQL still runs, because a ping writes nothing. Writes fail: ingest answers 500 ([StackurityIngestErrors](#stackurityingesterrors), [StackurityHTTPErrors](#stackurityhttperrors)), jobs fail and retry ([StackurityJobsFailed](#stackurityjobsfailed)), and periodic tasks stop succeeding ([StackurityTaskNotSucceeding](#stackuritytasknotsucceeding)). If PostgreSQL shuts down, it is a [database interruption](#database-interruption). Nothing already stored is lost; a failed ingest keeps none of its batch, and the agent sends it again.

Recover: free space (`rm` the filler, grow the volume), then check that `/readyz` answers 200, Platform health clears, and the failed jobs ran again or will on their next schedule. Find out what grew: `SELECT relname, pg_size_pretty(pg_total_relation_size(oid)) FROM pg_class WHERE relkind = 'r' ORDER BY pg_total_relation_size(oid) DESC LIMIT 10;`. Alert on the database volume's free space with your usual node or cloud metrics (Stackurity does not export it): warn below 20% free.

**The server's data directory fills up.** `STACKURITY_DATA_DIR` only holds temporary clones and scratch files for repository scans, image scans and feed downloads. When it is full those jobs fail with `no space left on device` ([StackurityJobsFailed](#stackurityjobsfailed)); the API, ingest and notifications are unaffected. Free space (the files there are temporary and can be deleted while the server is stopped) or give the volume more room; the jobs run again on their next schedule.

### Prolonged upstream outage

OSV, a package registry or endoflife.date is unreachable for hours.

1. On staging, block the server's outbound access to the source (a firewall rule, or point `STACKURITY_OSV_URL` at an address that answers 503) and refresh an OSV feed.
2. Wait past the feed's freshness limit (6 hours for OSV), or watch the error in the meantime.

Expected:

- Each sync attempt tries a failed request 4 times (2, 4 and 8 seconds apart), then the job is retried with backoff and fails after 5 attempts. The feed shows the upstream's error (`GET ...: HTTP 503`) on **Intelligence** and in `stackurity_feed_failing`; [StackurityFeedFailing](#stackurityfeedfailing) fires after 2 hours, [StackurityJobsFailed](#stackurityjobsfailed) once a sync job gives up.
- Once the last success is older than the freshness limit: `stackurity_feed_stale` is 1, [StackurityVulnerabilityFeedStale](#stackurityvulnerabilityfeedstale) and [StackurityHealthCritical](#stackurityhealthcritical) fire, Platform health shows a critical stale-feed problem, every workspace gets a P2 feed incident, the All issues page warns that intelligence is stale, and affected assets' coverage says their components were checked against stale intelligence.
- Nothing is cleared: advisories already stored stay, open findings stay open, and no finding is resolved because data is missing.

Recover: restore access and refresh the feed. The sync catches up from its cursor, the feed incident resolves, the alerts clear. For long planned outages or air-gapped sites, mirror the sources ([network.md](network.md)).

Automated: `TestUpstreamOutage` in `internal/crashtest`.

### Notification provider failure

Slack, Teams, the mail relay or a webhook receiver rejects or cannot take messages.

1. On staging, point a webhook channel at a receiver that answers 500 (or revoke a Slack app's token) and trigger an urgent issue or connect a new asset (or **Test** the channel).

Expected:

- The delivery log shows the attempts with the provider's error (`HTTP 500: ...`); `stackurity_notification_deliveries{state="retrying"}` counts them, `stackurity_notification_channels_failing` counts the channel, Platform health warns that a channel failed its last send, and [StackurityNotificationChannelFailing](#stackuritynotificationchannelfailing) fires after 30 minutes.
- After 8 attempts (about an hour) each delivery is `failed`: [StackurityNotificationsFailed](#stackuritynotificationsfailed) fires and Platform health reports the failed notifications. Rejected credentials fail at once.
- Other channels keep working; nothing is dropped silently.

Recover: fix the channel, **Test** it, then **Retry** the failed deliveries in the delivery log. Each is sent once more.

Automated: `TestNotificationProviderOutage` in `internal/crashtest`.

### Agent unreachable

A host's agent stops reporting (host down, agent removed, network change).

1. On staging, stop the agent on one host (`sudo systemctl stop stackurity-agent`) or block its route to the server.
2. Wait past `STACKURITY_STALE_AFTER` (48 hours; set it lower on staging, for example `STACKURITY_STALE_AFTER=30m`). The `mark-stale-assets` task checks every 10 minutes.

Expected: the asset is marked stale and counted in `stackurity_assets_stale`; its coverage says no collection since its last report and that the inventory may be out of date; its workspace gets a P3 collection incident ("Asset ... has stopped reporting"); its findings stay as they were. Many at once fire [StackurityAssetsStoppedReporting](#stackurityassetsstoppedreporting).

Recover: start the agent. Its next report makes the asset current and resolves the incident.

Automated: `TestAgentStopsReporting` in `internal/crashtest`.

## After any incident

- Platform health shows no problem, and the alerts above have resolved.
- Failed jobs and failed notifications from the incident window were retried or are understood.
- The audit log (`GET /api/v1/audit`) shows no unexpected changes made during it, and `stackurity admin verify-audit` reports no break.
- If anything was not as described here, report it: the drills are part of the test suite, and a difference is a bug.
