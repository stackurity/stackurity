-- The Stackurity GitHub App ("Install on GitHub"). Additive: four tables,
-- each with row-level security. See docs/github-app.md.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

-- An "Install on GitHub" in progress: single use, 10 minutes, bound to the
-- organisation and the person who started it. Only the SHA-256 of the state
-- is stored.
CREATE TABLE github_app_states (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    state_hash    bytea NOT NULL UNIQUE,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    return_to     text NOT NULL DEFAULT '' CHECK (length(return_to) <= 300),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz
);
CREATE INDEX github_app_states_expiry ON github_app_states (expires_at);
CREATE TRIGGER github_app_states_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON github_app_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE github_app_states ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON github_app_states USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON github_app_states USING (stackurity_system()) WITH CHECK (stackurity_system());

-- A GitHub App installation (a GitHub account or organisation that installed
-- the app) and the one organisation it belongs to here. An installation is
-- bound once: installation_id is unique across all organisations. No token
-- is stored: installation tokens are minted for each scan and dropped.
--   status  active, suspended (on GitHub) or deleted (uninstalled on GitHub;
--           kept for its history, never active again)
CREATE TABLE github_installations (
    id                    bigserial PRIMARY KEY,
    workspace_id          bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    installation_id       bigint NOT NULL UNIQUE CHECK (installation_id > 0),
    account_login         text NOT NULL DEFAULT '' CHECK (length(account_login) <= 100),
    account_type          text NOT NULL DEFAULT '' CHECK (length(account_type) <= 40),
    repository_selection  text NOT NULL DEFAULT '' CHECK (length(repository_selection) <= 20),
    status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    note                  text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    installed_by          bigint REFERENCES users(id) ON DELETE SET NULL,
    installed_at          timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    last_sync             timestamptz
);
CREATE INDEX github_installations_ws ON github_installations (workspace_id);
CREATE TRIGGER github_installations_installed_by_same_ws BEFORE INSERT OR UPDATE OF installed_by ON github_installations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'installed_by');
ALTER TABLE github_installations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON github_installations USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON github_installations USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The repositories an installation grants, each scanned by its own
-- integration (kind github_app). removed_at: no longer granted (its asset's
-- issues resolve as removed; the asset and its history stay). paused: the
-- integration was switched off by Stackurity because the installation was
-- suspended or removed, so it is switched on again only by Stackurity.
-- integration_id is NULL when someone deleted the integration: that
-- repository is then left out until it is granted again.
CREATE TABLE github_app_repositories (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    installation_id  bigint NOT NULL REFERENCES github_installations(installation_id) ON DELETE CASCADE,
    repository_id    bigint NOT NULL CHECK (repository_id > 0),
    full_name        text NOT NULL CHECK (length(full_name) BETWEEN 3 AND 200),
    default_branch   text NOT NULL DEFAULT '' CHECK (length(default_branch) <= 255),
    integration_id   bigint REFERENCES integrations(id) ON DELETE SET NULL,
    paused           boolean NOT NULL DEFAULT false,
    added_at         timestamptz NOT NULL DEFAULT now(),
    removed_at       timestamptz,
    UNIQUE (installation_id, repository_id)
);
CREATE INDEX github_app_repositories_ws ON github_app_repositories (workspace_id);
CREATE INDEX github_app_repositories_integration ON github_app_repositories (integration_id);
CREATE TRIGGER github_app_repositories_integration_same_ws BEFORE INSERT OR UPDATE OF integration_id ON github_app_repositories
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('integrations', 'integration_id');
ALTER TABLE github_app_repositories ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON github_app_repositories USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON github_app_repositories USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Webhook deliveries already handled, so a redelivery (same
-- X-GitHub-Delivery) or a replay of the same signed body is acknowledged and
-- ignored. Kept 30 days. System only.
CREATE TABLE github_deliveries (
    delivery_id  text PRIMARY KEY CHECK (length(delivery_id) BETWEEN 1 AND 100),
    body_hash    bytea NOT NULL UNIQUE,
    event        text NOT NULL DEFAULT '' CHECK (length(event) <= 60),
    received_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX github_deliveries_received ON github_deliveries (received_at);
ALTER TABLE github_deliveries ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON github_deliveries USING (stackurity_system()) WITH CHECK (stackurity_system());
