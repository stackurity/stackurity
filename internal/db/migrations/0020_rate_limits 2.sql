-- Rate limits for sign-in, setup, enrollment and single sign-on, shared by
-- every replica so a client behind a load balancer gets the limit once, not
-- once per replica. Each row counts the hits of one key in one fixed window;
-- windows are aligned to the database clock, so replicas agree on them.
-- Keys never hold an email or address in clear (see store.RateLimitHit).
CREATE TABLE rate_limits (
    key           text NOT NULL,
    window_start  timestamptz NOT NULL,
    hits          int NOT NULL DEFAULT 0,
    expires_at    timestamptz NOT NULL,
    PRIMARY KEY (key, window_start)
);
CREATE INDEX rate_limits_expires ON rate_limits (expires_at);

-- A platform table: hashed keys still say who tried to sign in when, so only
-- system scope sees it.
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON rate_limits USING (stackurity_system()) WITH CHECK (stackurity_system());
