-- Idle timeout for browser sessions (docs/install.md, "Sessions"): a
-- session unused for STACKURITY_SESSION_IDLE_TIMEOUT (30 minutes by
-- default) ends, on top of the 12-hour limit from sign-in. last_seen_at
-- is updated at most once a minute. Sessions from before this migration
-- count as seen now.
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX sessions_last_seen ON sessions (last_seen_at);
