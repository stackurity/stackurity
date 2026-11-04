-- Suggested links (the Stack tab's "Suggested links"): an application with
-- no built_from relation is offered the repositories it was probably built
-- from (store.LinkSuggestions). "Not this one" records the pair here so it
-- is not suggested again; "Link" adds the relation and removes the row.

SET LOCAL lock_timeout = '10s';

CREATE TABLE link_suggestion_dismissals (
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    app_id        bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    repo_id       bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dismissed_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    dismissed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, app_id, repo_id)
);
CREATE INDEX link_suggestion_dismissals_repo ON link_suggestion_dismissals (repo_id);

-- Like asset_relations: a connection narrowed to projects sees, and may
-- write, a dismissal only when it sees both assets.
ALTER TABLE link_suggestion_dismissals ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON link_suggestion_dismissals
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR (app_id IN (SELECT unnest(stackurity_visible_assets())) AND repo_id IN (SELECT unnest(stackurity_visible_assets())))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR (app_id IN (SELECT unnest(stackurity_visible_assets())) AND repo_id IN (SELECT unnest(stackurity_visible_assets())))));
CREATE POLICY sys ON link_suggestion_dismissals USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The assets and the user must be of the same workspace (migration 0025).
CREATE TRIGGER link_suggestion_dismissals_app_id_same_ws BEFORE INSERT OR UPDATE OF app_id ON link_suggestion_dismissals
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'app_id');
CREATE TRIGGER link_suggestion_dismissals_repo_id_same_ws BEFORE INSERT OR UPDATE OF repo_id ON link_suggestion_dismissals
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'repo_id');
CREATE TRIGGER link_suggestion_dismissals_dismissed_by_same_ws BEFORE INSERT OR UPDATE OF dismissed_by ON link_suggestion_dismissals
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'dismissed_by');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON link_suggestion_dismissals TO stackurity_app;
    END IF;
END $$;
