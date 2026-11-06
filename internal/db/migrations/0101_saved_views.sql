-- Saved views: a person's own named filters on a dashboard page (the
-- Fixes page's "Views" menu). Each is the page's query string, as the page
-- puts it in its address, so opening a view is opening that address.
-- A view belongs to the person who saved it, in one organisation; nobody
-- else lists or deletes it (store/saved_views.go always filters by user).
-- Additive: one new table.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE saved_views (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    page         text NOT NULL CHECK (page ~ '^[a-z][a-z0-9_-]{0,39}$'),
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    query        text NOT NULL DEFAULT '' CHECK (length(query) <= 2000),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, user_id, page, name)
);
CREATE INDEX saved_views_user ON saved_views (user_id);

-- Not narrowed to projects: a view is the person's own filter, not asset
-- data (what it shows is narrowed when the page loads it).
ALTER TABLE saved_views ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON saved_views USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON saved_views USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON saved_views TO stackurity_app';
        EXECUTE 'GRANT USAGE, SELECT, UPDATE ON SEQUENCE saved_views_id_seq TO stackurity_app';
    END IF;
END $$;
