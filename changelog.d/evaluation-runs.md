### Added

- **A record of every vulnerability check.** Each evaluation run of an organisation is kept for 400 days: after a source changed, after a report, the daily run, and a scheduled check every 30 minutes that confirms every source was read on schedule and nothing is waiting for re-evaluation. Each feed sync is kept too. The licensed evidence pack uses these records to show how many hours of a period had a completed check, counting only from when recording started. See [Evaluation runs](docs/evaluation-runs.md).

### Upgrading

- Migration `0116_evaluation_runs` adds the tables `evaluation_runs` (row-level security) and `feed_sync_runs`. Additive. Recording starts when the new version runs; earlier hours are reported as not recorded.
