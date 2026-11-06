-- The plan's inactive pause (docs/asset-limits.md, "Plan limits"): when
-- nobody in an organisation has signed in for inactive_pause_days, it is
-- warned twice (15 and 5 days before) and then paused: nothing new is
-- collected and no notifications are sent, everything is kept, and the
-- next sign-in by any member resumes it at once. Unset plan limits never
-- set these.

SET LOCAL lock_timeout = '10s';

ALTER TABLE workspaces
    ADD COLUMN inactive_warned_first_at timestamptz,
    ADD COLUMN inactive_warned_last_at  timestamptz,
    ADD COLUMN inactive_paused_at       timestamptz;
