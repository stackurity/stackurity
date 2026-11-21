### Fixed

- **An upgrade no longer stops when a migration deadlocks with a server still running the previous version.** During a rolling upgrade, an older replica's queries could lock tables in a different order from a migration, and Postgres cancelled the migration with "deadlock detected" (or a lock timeout), so the new server did not start. Each migration runs in one transaction that Postgres rolls back in full, so it is now tried up to five times, with a short pause, before the upgrade gives up.
