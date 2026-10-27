-- Acting from Slack: Assign to me and Snooze buttons on Slack channels set up
-- with a Slack app's signing secret. Every change is additive: three new
-- tables, each with row-level security per workspace.

-- Read and update rows of every workspace below (row-level security is
-- forced for the table owner where the application role cannot be created).
SELECT set_config('stackurity.scope', 'system', true);

-- --- linked Slack accounts

-- A Slack user (in a Slack workspace, "team") linked to a Stackurity user of
-- this workspace. Their clicks on interactive buttons act as that user, with
-- that user's role and project access. A Slack user is linked to at most one
-- account per workspace; linking again needs the link removed first.
CREATE TABLE slack_links (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    team_id         text NOT NULL CHECK (team_id ~ '^[A-Z0-9]{1,32}$'),
    team_name       text NOT NULL DEFAULT '' CHECK (length(team_name) <= 200),
    slack_user_id   text NOT NULL CHECK (slack_user_id ~ '^[A-Z0-9]{1,32}$'),
    slack_user_name text NOT NULL DEFAULT '' CHECK (length(slack_user_name) <= 200),
    user_id         bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    UNIQUE (workspace_id, team_id, slack_user_id)
);
CREATE INDEX slack_links_user ON slack_links (workspace_id, user_id);
-- The linked user must be a member of the workspace.
CREATE TRIGGER slack_links_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON slack_links
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');

ALTER TABLE slack_links ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- A member with project access only sees and removes their own links; the
-- organisation's people see the workspace's (the API still lists only the
-- caller's own).
CREATE POLICY ws ON slack_links
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_member()) IS NULL OR user_id = (SELECT stackurity_member())))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_member()) IS NULL OR user_id = (SELECT stackurity_member())));
CREATE POLICY sys ON slack_links USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- one-time links to confirm a Slack account

-- Sent ephemerally to a Slack user who clicked a button before linking. The
-- signed-in Stackurity user who opens it confirms "link Slack user X in team
-- T to my account". Single use, 15 minutes, only the SHA-256 is stored, and
-- only in the workspace of the channel the click came from.
CREATE TABLE slack_link_requests (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    channel_id      bigint REFERENCES channels(id) ON DELETE CASCADE,
    team_id         text NOT NULL CHECK (team_id ~ '^[A-Z0-9]{1,32}$'),
    team_name       text NOT NULL DEFAULT '' CHECK (length(team_name) <= 200),
    slack_user_id   text NOT NULL CHECK (slack_user_id ~ '^[A-Z0-9]{1,32}$'),
    slack_user_name text NOT NULL DEFAULT '' CHECK (length(slack_user_name) <= 200),
    token_hash      bytea NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    used_by         bigint REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX slack_link_requests_user ON slack_link_requests (workspace_id, team_id, slack_user_id);
CREATE INDEX slack_link_requests_expiry ON slack_link_requests (expires_at);
CREATE TRIGGER slack_link_requests_channel_id_same_ws BEFORE INSERT OR UPDATE OF channel_id ON slack_link_requests
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('channels', 'channel_id');

ALTER TABLE slack_link_requests ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON slack_link_requests USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON slack_link_requests USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- replay protection

-- Slack request signatures seen in the last few minutes, per workspace: a
-- signed request is accepted once. Rows older than 10 minutes are removed
-- as new ones arrive (a request older than 5 minutes is refused anyway).
CREATE TABLE slack_seen_requests (
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    signature_hash bytea NOT NULL,
    seen_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, signature_hash)
);
CREATE INDEX slack_seen_requests_seen ON slack_seen_requests (workspace_id, seen_at);

ALTER TABLE slack_seen_requests ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON slack_seen_requests USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON slack_seen_requests USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON slack_links, slack_link_requests, slack_seen_requests TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE slack_links_id_seq, slack_link_requests_id_seq TO stackurity_app;
    END IF;
END $$;
