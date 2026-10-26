-- Release 0.7, "the loop": check again, regressed issues, snooze until a fix
-- ships, ignore with reason, scope and expiry, and the approval inbox.
--
-- Every change here is additive. New columns on findings are nullable or
-- have constant defaults, so adding them does not rewrite the table (about
-- 130,000 rows in the largest workspace); the two new indexes on findings
-- take a few seconds there and lock writes to findings meanwhile.

-- Regressed: an issue that was fixed and came back on the same asset (same
-- component and advisory). regressed_at is when it last came back;
-- regressed_notified_at is when an urgent message last told people.
ALTER TABLE findings
    ADD COLUMN regressed_at           timestamptz,
    ADD COLUMN regressed_notified_at  timestamptz,
    -- Snoozed or ignored until a free fixed version exists (state
    -- suppressed or risk_accepted); suppressed_until stays set to the
    -- workspace's exception limit as a backstop.
    ADD COLUMN until_fix              boolean NOT NULL DEFAULT false,
    -- Why an accepted issue is ignored: accepted_risk, false_positive,
    -- mitigated or no_fix ('' for acceptances made before 0.7).
    ADD COLUMN ignore_reason          text NOT NULL DEFAULT '',
    -- The ignore rule (finding_exceptions) that set or last set the state.
    -- Kept after the issue is reopened, so that rule never applies to it again.
    ADD COLUMN exception_id           bigint,
    -- The matcher's verification while a person has marked the finding a
    -- false positive (verification 'rejected'); restored when it is reopened.
    ADD COLUMN verification_before    text NOT NULL DEFAULT '';

-- One issue (component and advisory) on one asset across inventory rows:
-- regressed detection, ignore rules and check outcomes look it up.
CREATE INDEX findings_identity ON findings (asset_id, component_id, key, kind);
-- Open regressed issues, for Home and the urgent messages.
CREATE INDEX findings_open_regressed ON findings (asset_id) INCLUDE (workspace_id, state)
    WHERE status = 'open' AND regressed_at IS NOT NULL;

-- Ignore rules: one decision to ignore an issue (component and advisory) on
-- one asset or on every asset of the workspace, including assets and
-- findings found later. Findings it covers get state risk_accepted and its
-- reason; a false positive also sets verification 'rejected'.
CREATE TABLE finding_exceptions (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    kind             text NOT NULL,
    key              text NOT NULL,
    component_id     bigint NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    asset_id         bigint REFERENCES assets(id) ON DELETE CASCADE,   -- NULL: every asset
    reason           text NOT NULL CHECK (reason IN ('accepted_risk', 'false_positive', 'mitigated', 'no_fix')),
    note             text NOT NULL DEFAULT '',
    mitigation       text NOT NULL DEFAULT '',
    expires_at       timestamptz,                                       -- NULL: never (or until a fix ships)
    until_fix        boolean NOT NULL DEFAULT false,
    created_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    request_id       bigint,                                            -- the approved ignore request, if any
    created_at       timestamptz NOT NULL DEFAULT now(),
    ended_at         timestamptz,
    ended_by_name    text NOT NULL DEFAULT '',
    ended_reason     text NOT NULL DEFAULT ''
);
CREATE INDEX finding_exceptions_workspace ON finding_exceptions (workspace_id);
CREATE INDEX finding_exceptions_active ON finding_exceptions (component_id, key) WHERE ended_at IS NULL;
ALTER TABLE finding_exceptions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON finding_exceptions USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON finding_exceptions USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Requests to ignore issues from people whose role may not ignore
-- (engineers, viewers), decided by security or admin users.
CREATE TABLE ignore_requests (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    finding_ids        bigint[] NOT NULL,
    title              text NOT NULL DEFAULT '',     -- what the request is about, for the inbox
    fix_group          text NOT NULL DEFAULT '',
    asset_id           bigint REFERENCES assets(id) ON DELETE CASCADE,
    reason             text NOT NULL CHECK (reason IN ('accepted_risk', 'false_positive', 'mitigated', 'no_fix')),
    note               text NOT NULL,
    mitigation         text NOT NULL DEFAULT '',
    scope              text NOT NULL CHECK (scope IN ('asset', 'everywhere')),
    expiry             text NOT NULL CHECK (expiry IN ('date', 'until_fix', 'never')),
    expires_at         timestamptz,
    status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined')),
    requested_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    requested_by_name  text NOT NULL DEFAULT '',
    requested_at       timestamptz NOT NULL DEFAULT now(),
    decided_by         bigint REFERENCES users(id) ON DELETE SET NULL,
    decided_by_name    text NOT NULL DEFAULT '',
    decided_at         timestamptz,
    decision_note      text NOT NULL DEFAULT '',
    applied            int NOT NULL DEFAULT 0
);
CREATE INDEX ignore_requests_workspace ON ignore_requests (workspace_id);
CREATE INDEX ignore_requests_pending ON ignore_requests (requested_at) WHERE status = 'pending';
ALTER TABLE ignore_requests ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ignore_requests USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ignore_requests USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Check again: a request for fresh evidence about an asset, or about one fix
-- on it. It completes when a complete collection received after the request
-- has been evaluated, with an outcome:
--   passed        every issue it was about is gone
--   partly_fixed  some are gone, some are left
--   still_open    none is gone
--   expired       no report arrived within 7 days
-- method says who has to report: the agent on the host (agent), a
-- server-side scan (integration), or the next upload (report).
CREATE TABLE checks (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    fix_group          text NOT NULL DEFAULT '',        -- '' for the whole asset
    fix_title          text NOT NULL DEFAULT '',
    finding_ids        bigint[] NOT NULL DEFAULT '{}',  -- a fix's open issues when it was requested
    open_before        int NOT NULL DEFAULT 0,
    reason             text NOT NULL DEFAULT 'check' CHECK (reason IN ('check', 'applied')),
    method             text NOT NULL CHECK (method IN ('agent', 'integration', 'report')),
    integration_id     bigint REFERENCES integrations(id) ON DELETE SET NULL,
    requested_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    requested_by_name  text NOT NULL DEFAULT '',
    requested_at       timestamptz NOT NULL DEFAULT now(),
    picked_up_at       timestamptz,                     -- the agent asked for it
    collection_id      bigint,                          -- the report that answered it
    completed_at       timestamptz,
    outcome            text NOT NULL DEFAULT '' CHECK (outcome IN ('', 'passed', 'partly_fixed', 'still_open', 'expired')),
    fixed              int NOT NULL DEFAULT 0,
    remaining          int NOT NULL DEFAULT 0,
    new_issues         int NOT NULL DEFAULT 0
);
CREATE INDEX checks_workspace ON checks (workspace_id);
CREATE INDEX checks_asset ON checks (asset_id, requested_at DESC);
CREATE INDEX checks_open ON checks (asset_id) WHERE completed_at IS NULL;
ALTER TABLE checks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON checks USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON checks USING (stackurity_system()) WITH CHECK (stackurity_system());

-- When an agent last asked whether to report now (0.7 agents, about once a
-- minute; written at most every 5 minutes). NULL: an older agent, or none.
ALTER TABLE assets ADD COLUMN agent_polled_at timestamptz;
