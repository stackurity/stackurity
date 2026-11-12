-- Connect GitLab files a group's projects into a Stackurity project
-- (docs/gitlab.md). Before this, the assets a connected group's projects
-- created were in no project: people with project access never saw them,
-- and their findings showed only under "All projects".
--
--   project_id  the Stackurity project the connection's assets are added
--               to (when first scanned, or when it is chosen later); NULL
--               leaves them in no project, as before
--
-- Additive: one nullable column.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE gitlab_connections ADD COLUMN project_id bigint REFERENCES projects(id) ON DELETE SET NULL;
CREATE INDEX gitlab_connections_project ON gitlab_connections (project_id) WHERE project_id IS NOT NULL;
CREATE TRIGGER gitlab_connections_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON gitlab_connections
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
