-- Usage counts (owner decision 2026-11-16): how often each organisation sees
-- a locked paid-plan notice or clicks a link in it, is refused something by
-- its plan, or exports a report, SBOM or VEX document. The operator reads
-- them as totals to learn which features people want and use.
--
-- Metadata only: the organisation, the event, a fixed key (a feature, a
-- limit or an export kind from a list in internal/store/usage.go), the UTC
-- day and how many times. No user, no request content, no names. Rows are
-- deleted after UsageCountRetention (400 days).
SET LOCAL lock_timeout = '10s';

CREATE TABLE usage_counts (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    day          date NOT NULL,
    event        text NOT NULL CHECK (event IN ('teaser_view', 'teaser_click', 'limit_refused', 'export')),
    key          text NOT NULL CHECK (key ~ '^[a-z0-9_]{1,40}$'),
    n            bigint NOT NULL DEFAULT 1 CHECK (n >= 1),
    PRIMARY KEY (workspace_id, day, event, key)
);
CREATE INDEX usage_counts_day ON usage_counts (day);
ALTER TABLE usage_counts ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON usage_counts USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON usage_counts USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON usage_counts TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
