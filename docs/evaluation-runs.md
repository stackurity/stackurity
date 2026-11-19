# Evaluation runs

Stackurity records each time an organisation's software is checked against vulnerability data, and each sync of a vulnerability, release or lifecycle source. The compliance evidence pack uses these records to show, for a period, how many hours had a completed check ([api.md](api.md#audit-evidence-pack)). Before migration `0116_evaluation_runs`, only each component's latest evaluation was kept, so this could not be shown after the fact.

## What is recorded

`evaluation_runs` has one row per run of an organisation (row-level security, like other organisation tables):

| Trigger | When |
|---|---|
| `feed_sync` | A source changed. The components it affects were evaluated again, about 30 seconds after the sync. `feeds` names that source. |
| `ingest` | An asset reported, and its inventory was evaluated. |
| `daily` | The daily full evaluation. End-of-life dates pass without any source changing. |
| `scheduled` | The check every 30 minutes, so every clock hour has one. It is OK when each vulnerability source the organisation's installed software is checked against was read successfully within its refresh interval plus one hour, and no re-evaluation has been waiting longer than 15 minutes. Otherwise `error_class` says why: `feed_failed` (overdue after a failed sync), `feed_stale` (overdue) or `evaluation_backlog`. |

Each row has:

- when it started and finished;
- the sources it used, each with its last successful sync;
- the assets evaluated (for `scheduled`: the assets with installed software it covered);
- the findings opened or updated, and the findings closed;
- `ok`, and an `error_class` (`timeout`, `canceled`, `error` or one of the above). The error text is never stored.

A failed job is recorded on each attempt.

Most vulnerability sources are read every hour: the OSV ecosystems and the distributions' OSV data. A few are read every 6 hours because their publishers update less often: Amazon Linux, Oracle Linux, vendor builds, Microsoft's Security Update Guide and Windows programs. A source that changed hands only the components it affects to re-evaluation. Every other evaluation is carried forward to the new data, since evaluating it again would give the same result.

`feed_sync_runs` has one row per source sync: started, finished, ok, records changed, whether it handed components to re-evaluation, and an error class. It is public intelligence like `feeds`, with no organisation data.

## Retention

Both tables are kept 400 days (an audit year and a margin). The hourly housekeeping task deletes older rows (`store.PruneEvaluationRuns`). A run is a few hundred bytes. An organisation with 50 servers reporting every 6 hours writes about 250 rows a day, plus the scheduled checks (48 a day) and one row for each source change.

## Reading them

`store.EvaluationCoverage(ctx, from, to)` counts the whole clock hours (UTC) from the later of `from` and the organisation's first recorded run to the earlier of `to` and now, and how many of them had a successful run. It also gives the longest gap and the failures by class. Hours before the first run are not counted: nothing is known about them either way. `store.EvaluationRuns` lists the runs of a period.
