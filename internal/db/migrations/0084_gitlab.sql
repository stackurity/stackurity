-- Connect GitLab: a GitLab group's projects scanned in one step. Additive:
-- four tables, each with row-level security. See docs/gitlab.md.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

-- An authorisation at GitLab in progress: single use, 10 minutes, bound to
-- the organisation and the person who started it. Only the SHA-256 of the
-- state is stored.
--   purpose     setup (connect a group), readonly (the read-only OAuth
--               credential when a group access token is not allowed) or
--               cleanup (delete the webhook and token on GitLab, then
--               disconnect)
--   pick_hash   after setup's code exchange: the SHA-256 of the handle the
--               dashboard sends back with the group it picked
--   user_token  the person's OAuth access token from setup's exchange,
--               sealed, kept only until the group is picked (at most 10
--               minutes, then revoked at GitLab and deleted)
CREATE TABLE gitlab_oauth_states (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    state_hash     bytea NOT NULL UNIQUE,
    user_id        bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose        text NOT NULL CHECK (purpose IN ('setup', 'readonly', 'cleanup')),
    connection_id  bigint,
    return_to      text NOT NULL DEFAULT '' CHECK (length(return_to) <= 300),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    pick_hash      bytea UNIQUE,
    user_token     bytea
);
CREATE INDEX gitlab_oauth_states_expiry ON gitlab_oauth_states (expires_at);
CREATE TRIGGER gitlab_oauth_states_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON gitlab_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE gitlab_oauth_states ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gitlab_oauth_states USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gitlab_oauth_states USING (stackurity_system()) WITH CHECK (stackurity_system());

-- A GitLab group connected to one organisation. group_id is unique across
-- all organisations (one GitLab instance per server).
--   credential_kind  group_token (a group access token Stackurity created:
--                    read_api + read_repository, Reporter, at most a year),
--                    oauth (an OAuth access and refresh token with read_api
--                    + read_repository, refreshed and rotated) or none (not
--                    yet: the read-only authorisation is awaited)
--   credential       the credential, sealed with STACKURITY_SECRET_KEY
--                    (bound to the workspace and the group); nothing else
--                    here is secret
--   hook_secret_hash SHA-256 of the group webhook's secret token
--   webhook          active, not_permitted (GitLab refused: needs the
--                    group's Owner role and a tier with group webhooks) or
--                    none
--   status           active, needs_credential, or expired (the credential
--                    stopped working: connect again)
CREATE TABLE gitlab_connections (
    id                  bigserial PRIMARY KEY,
    workspace_id        bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    group_id            bigint NOT NULL UNIQUE CHECK (group_id > 0),
    group_path          text NOT NULL CHECK (length(group_path) BETWEEN 1 AND 255),
    group_name          text NOT NULL DEFAULT '' CHECK (length(group_name) <= 255),
    credential_kind     text NOT NULL DEFAULT 'none' CHECK (credential_kind IN ('group_token', 'oauth', 'none')),
    credential          bytea,
    credential_expires  timestamptz,
    token_id            bigint,
    hook_id             bigint,
    hook_secret_hash    bytea,
    webhook             text NOT NULL DEFAULT 'none' CHECK (webhook IN ('active', 'not_permitted', 'none')),
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'needs_credential', 'expired')),
    note                text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    connected_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    connected_at        timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    last_sync           timestamptz
);
CREATE INDEX gitlab_connections_ws ON gitlab_connections (workspace_id);
CREATE TRIGGER gitlab_connections_connected_by_same_ws BEFORE INSERT OR UPDATE OF connected_by ON gitlab_connections
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'connected_by');
ALTER TABLE gitlab_connections ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gitlab_connections USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gitlab_connections USING (stackurity_system()) WITH CHECK (stackurity_system());

-- A connected group's projects (subgroups included), each scanned by its
-- own integration (kind gitlab). removed_at: no longer in the group (its
-- asset's issues resolve as removed; the asset and its history stay).
-- integration_id is NULL when someone deleted the integration: that project
-- is then left out.
CREATE TABLE gitlab_projects (
    id                   bigserial PRIMARY KEY,
    workspace_id         bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    connection_id        bigint NOT NULL REFERENCES gitlab_connections(id) ON DELETE CASCADE,
    project_id           bigint NOT NULL CHECK (project_id > 0),
    path_with_namespace  text NOT NULL CHECK (length(path_with_namespace) BETWEEN 3 AND 255),
    default_branch       text NOT NULL DEFAULT '' CHECK (length(default_branch) <= 255),
    integration_id       bigint REFERENCES integrations(id) ON DELETE SET NULL,
    added_at             timestamptz NOT NULL DEFAULT now(),
    removed_at           timestamptz,
    UNIQUE (connection_id, project_id)
);
CREATE INDEX gitlab_projects_ws ON gitlab_projects (workspace_id);
CREATE INDEX gitlab_projects_integration ON gitlab_projects (integration_id);
CREATE INDEX gitlab_projects_project ON gitlab_projects (project_id);
CREATE TRIGGER gitlab_projects_integration_same_ws BEFORE INSERT OR UPDATE OF integration_id ON gitlab_projects
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('integrations', 'integration_id');
ALTER TABLE gitlab_projects ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gitlab_projects USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gitlab_projects USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Webhook deliveries already handled (X-Gitlab-Event-UUID), and their
-- bodies, so a redelivery or a replay is acknowledged and ignored. Kept 30
-- days. System only.
CREATE TABLE gitlab_deliveries (
    delivery_id  text PRIMARY KEY CHECK (length(delivery_id) BETWEEN 1 AND 100),
    body_hash    bytea NOT NULL UNIQUE,
    event        text NOT NULL DEFAULT '' CHECK (length(event) <= 60),
    received_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX gitlab_deliveries_received ON gitlab_deliveries (received_at);
ALTER TABLE gitlab_deliveries ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON gitlab_deliveries USING (stackurity_system()) WITH CHECK (stackurity_system());
