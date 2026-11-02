-- Fleet enrollment codes, and a record of every use of an enrollment code.
--
-- A fleet code is an enrollment code made to add many servers in one rollout
-- (cloud-init, Ansible, Terraform, an SSH loop): up to 1,000 servers and up
-- to 90 days, both chosen explicitly when it is made. It is stored like any
-- other code (only its hash) and exchanged for one collector token per host.
--
--   fleet      made as a fleet code (Add server > For many servers)
--   max_uses   how many servers the code could enroll when it was made;
--              NULL for codes made before this release (only uses_left
--              was kept)
--
-- enrollment_uses lists which host used a code, when, and from which
-- address, for every code, so an administrator can see what a fleet code
-- enrolled and spot a use they did not expect.
--
-- Additive: two columns with defaults (no rewrite on PostgreSQL 11+) and one
-- new table.

SET LOCAL lock_timeout = '10s';

ALTER TABLE enrollments ADD COLUMN fleet boolean NOT NULL DEFAULT false;
ALTER TABLE enrollments ADD COLUMN max_uses int CHECK (max_uses IS NULL OR max_uses >= 1);

CREATE TABLE enrollment_uses (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    enrollment_id  bigint NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
    hostname       text NOT NULL DEFAULT '',
    remote_addr    text NOT NULL DEFAULT '',
    token_id       bigint REFERENCES api_tokens(id) ON DELETE SET NULL,
    used_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_uses_enrollment ON enrollment_uses (enrollment_id, used_at DESC);
CREATE INDEX enrollment_uses_workspace ON enrollment_uses (workspace_id);
ALTER TABLE enrollment_uses ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON enrollment_uses USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON enrollment_uses USING (stackurity_system()) WITH CHECK (stackurity_system());
CREATE TRIGGER enrollment_uses_enrollment_id_same_ws BEFORE INSERT OR UPDATE OF enrollment_id ON enrollment_uses
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('enrollments', 'enrollment_id');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_uses TO stackurity_app';
        EXECUTE 'GRANT USAGE, SELECT, UPDATE ON SEQUENCE enrollment_uses_id_seq TO stackurity_app';
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
