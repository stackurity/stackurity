-- A session started by a workspace's own single sign-on (Stackurity Cloud)
-- is pinned to that workspace: it never works in, or switches to, another
-- workspace, so one organisation's identity provider can never act in
-- another organisation, even for a person who belongs to both.
ALTER TABLE sessions ADD COLUMN sso_workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
