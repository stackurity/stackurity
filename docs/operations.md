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
| Server log | stdout, JSON by default | Errors with context; each problem below names the lines to look for |

Platform incidents are raised by the alerts task itself, so they stop when that task is stuck or the database is down. Alert on the metrics from outside as well: that is what the rules below are for.

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
| [StackurityFeedStale](#stackurityfeedstale) | warning | A KEV, release or lifecycle feed is past its freshness limit | 30m |
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

The thresholds follow the server's own limits: feeds are stale after their `stale_after` (6 hours for OSV ecosystems and distributions, 48 hours for Amazon Linux, 72 hours for CISA KEV and the package registries, 7 days for endoflife.date); periodic tasks are flagged after three intervals, as Platform health does; the job backlog warning matches Platform health's 30 minutes.

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
- Killed without a log line: out of memory. Raise the memory limit; the first OSV download of a large ecosystem and very large ingests use the most.
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

### StackurityFeedStale

As [StackurityVulnerabilityFeedStale](#stackurityvulnerabilityfeedstale), for CISA KEV (known exploitation), the package registries (latest releases) or endoflife.date (lifecycle). Priorities that depend on known exploitation, upgrade recommendations or end-of-life dates are older than promised.

### StackurityFeedFailing

A feed's recent syncs fail, but its last success is still within its freshness limit, so nothing is stale yet. Usually a short upstream problem that solves itself; if it lasts, check the error as for a stale feed before it turns into one.

### StackurityTaskNotSucceeding

A periodic task (`alerts`, `alert-digest`, `enqueue-due-feeds`, `ensure-feeds`, `enqueue-due-integrations`, `mark-stale-assets`, `housekeeping`, `daily-evaluation`, `platform-fallback`, `update-check`) has not succeeded for three of its intervals. Either every run fails, or one replica holds its lease and never finishes (a stuck lease). For `alerts` this means no notifications at all are sent.

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

Notifications ran out of their 8 attempts (retried after 30 seconds, then 1, 2, 4, 8, 16 and 32 minutes; at once when the receiver rejects credentials) and were not delivered. Each workspace's delivery log (**Settings → Notifications**, `GET /api/v1/deliveries?status=failed`) shows each one with its error, and **Retry** (`POST /api/v1/deliveries/{id}/retry`) sends it again once the cause is fixed. Common causes: an expired webhook secret or bot token, a removed Slack or Teams channel, a Jira project or permission change, a mail relay refusing the sender. The people the incidents were for may not know about them: tell them, or retry.

### StackurityNotificationChannelFailing

An enabled channel's last send failed and has stayed failed for 30 minutes. Messages to it are being retried; they fail after 8 attempts (about an hour) and then fire [StackurityNotificationsFailed](#stackuritynotificationsfailed). The channel shows its last error under **Settings → Notifications**; the **Test** button sends a test message once it is fixed.

### StackurityNotificationsBacklog

A due notification has not been picked up for over 15 minutes, so people are not told about incidents. Deliveries deferred by quiet hours or held for a digest are not counted. The `alerts` task is stuck or failing: follow [StackurityTaskNotSucceeding](#stackuritytasknotsucceeding) for it. Platform incidents cannot report this, because they are sent by the same task.

### StackurityAssetsStoppedReporting

At least five more assets went stale within an hour (an asset is stale when nothing reported it for `STACKURITY_STALE_AFTER`, 48 hours by default). Many at once usually has one cause:

- Agents cannot reach the server: a DNS, firewall, proxy or certificate change. Run `stackurity diagnostics --server URL` on one of the hosts.
- Their tokens were revoked, or their workspace was disabled (the agent logs `HTTP 401`).
- Ingest fails on the server ([StackurityIngestErrors](#stackurityingesterrors)).
- An integration (repositories, images, AWS, Kubernetes) fails: its last error is on the integration.

### StackurityAssetsStale

Some assets have not reported for over a day after being marked stale. Their inventory and findings are out of date, their coverage says so, and each workspace has a collection incident for them. Decommissioned hosts belong deleted (or merged), so they stop counting; others need their agent or integration fixed.

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

1. On staging, point a webhook channel at a receiver that answers 500 (or revoke a Slack app's token) and trigger an incident (or **Test** the channel).

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
- The audit log (`GET /api/v1/audit`) shows no unexpected changes made during it.
- If anything was not as described here, report it: the drills are part of the test suite, and a difference is a bug.
