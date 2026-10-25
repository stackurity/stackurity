-- Several server replicas can share one database. Periodic tasks are claimed
-- here, so each runs at most once per interval across replicas and never
-- twice at the same time. A claim is a lease: a replica renews it while the
-- task runs, and when a replica dies its lease expires and another replica
-- takes the task over. The row also keeps the last outcome for health checks.
CREATE TABLE periodic_tasks (
    name                  text PRIMARY KEY,
    every                 interval NOT NULL,
    seen_at               timestamptz NOT NULL DEFAULT now(),  -- last registered by a running server
    last_started_at       timestamptz,
    last_finished_at      timestamptz,
    last_success_at       timestamptz,
    last_error            text NOT NULL DEFAULT '',
    last_duration         interval,
    consecutive_failures  int NOT NULL DEFAULT 0,
    locked_by             text,
    locked_until          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now()
);

-- Values every replica must agree on, such as the one-time setup token.
CREATE TABLE instance_state (
    key         text PRIMARY KEY,
    value       text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Platform tables: task errors can name a workspace and the setup token is a
-- secret, so only system scope (the worker, instance-admin views) sees them.
ALTER TABLE periodic_tasks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON periodic_tasks USING (stackurity_system()) WITH CHECK (stackurity_system());
ALTER TABLE instance_state ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON instance_state USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Recently failed jobs are counted for health checks and metrics.
CREATE INDEX jobs_failed_at ON jobs (failed_at) WHERE failed_at IS NOT NULL;
