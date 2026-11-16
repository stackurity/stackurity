-- Compliance evidence connectors (paid): send vulnerability-management
-- evidence to Vanta and Drata on a schedule. Vanta is connected with OAuth
-- 2.0 (the operator registers one Vanta app, STACKURITY_VANTA_CLIENT_ID and
-- _SECRET); Drata with an API key an administrator pastes. See
-- docs/evidence-connectors.md.
--
-- Additive: three new tables, nothing is rewritten.

SET LOCAL lock_timeout = '10s';

-- One connection per vendor per organisation. Tokens and the Drata API key
-- are sealed with STACKURITY_SECRET_KEY like stored secrets, bound to the
-- organisation and the connection, and are never returned by the API. A
-- Vanta token refresh holds this row's lock and stores the new tokens in
-- one update (token_version counts them). status is reconnect_needed once
-- the vendor refused the refresh token or the key; syncs then stop with
-- that reason until an administrator reconnects. config holds the vendor's
-- ids (Vanta document; Drata workspace, custom connection, resources,
-- evidence item).
CREATE TABLE evidence_connections (
    id                bigserial PRIMARY KEY,
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    vendor            text NOT NULL CHECK (vendor IN ('vanta', 'drata')),
    region            text NOT NULL DEFAULT 'us' CHECK (region IN ('us', 'eu', 'aus', 'apac')),
    config            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object'),
    access_token      bytea,
    refresh_token     bytea,
    api_key           bytea,
    expires_at        timestamptz,
    token_version     bigint NOT NULL DEFAULT 0,
    status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reconnect_needed', 'paused')),
    status_reason     text NOT NULL DEFAULT '' CHECK (length(status_reason) <= 500),
    interval_hours    integer NOT NULL DEFAULT 24 CHECK (interval_hours IN (6, 12, 24, 168)),
    next_sync_at      timestamptz NOT NULL DEFAULT now(),
    last_sync_at      timestamptz,
    last_sync_status  text CHECK (last_sync_status IN ('ok', 'failed', 'partial')),
    last_sync_summary jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(last_sync_summary) = 'object'),
    connected_by      bigint REFERENCES users(id) ON DELETE SET NULL,
    connected_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, vendor)
);
CREATE INDEX evidence_connections_due ON evidence_connections (next_sync_at) WHERE status = 'active';
CREATE TRIGGER evidence_connections_connected_by_same_ws BEFORE INSERT OR UPDATE OF connected_by ON evidence_connections
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'connected_by');
ALTER TABLE evidence_connections ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON evidence_connections USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON evidence_connections USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The OAuth state of a Connect Vanta in progress: single use, 10 minutes,
-- bound to the organisation and the person who started it. Only the
-- SHA-256 of the state is kept.
CREATE TABLE evidence_oauth_states (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    vendor         text NOT NULL CHECK (vendor IN ('vanta')),
    region         text NOT NULL DEFAULT 'us' CHECK (region IN ('us', 'eu', 'aus')),
    state_hash     bytea NOT NULL UNIQUE,
    user_id        bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);
CREATE INDEX evidence_oauth_states_expiry ON evidence_oauth_states (expires_at);
CREATE TRIGGER evidence_oauth_states_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON evidence_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE evidence_oauth_states ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON evidence_oauth_states USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON evidence_oauth_states USING (stackurity_system()) WITH CHECK (stackurity_system());

-- One row per sync of a connection; the newest 50 per connection are kept.
-- counts: {"assets": n, "vulnerabilities": n, "evidence_uploaded": bool}.
CREATE TABLE evidence_sync_runs (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    connection_id  bigint NOT NULL REFERENCES evidence_connections(id) ON DELETE CASCADE,
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    status         text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed', 'partial')),
    counts         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object'),
    error          text NOT NULL DEFAULT '' CHECK (length(error) <= 1000)
);
CREATE INDEX evidence_sync_runs_connection ON evidence_sync_runs (connection_id, started_at DESC);
CREATE TRIGGER evidence_sync_runs_connection_same_ws BEFORE INSERT OR UPDATE OF connection_id ON evidence_sync_runs
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('evidence_connections', 'connection_id');
ALTER TABLE evidence_sync_runs ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON evidence_sync_runs USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON evidence_sync_runs USING (stackurity_system()) WITH CHECK (stackurity_system());
