### Fixed

- **An evaluation job could fail with `null value in column "workspace_id" of relation "findings"`.** A per-asset evaluation job could be queued without its organisation and then run in the worker's platform scope, where saving findings fails. Each such job now takes the organisation from its asset, and an evaluation job that has none runs in its asset's organisation or fails with a clear message. ([#539](https://github.com/stackurity/stackurity/issues/539))
- **Settings, Jobs no longer shows an old error on a job that succeeded.** A job that failed an attempt and then succeeded on a retry kept the earlier error next to "done"; it is now cleared when the job completes.
