-- Connect AWS with a CloudFormation stack (docs/install.md, "AWS managed
-- services"). Additive: two new tables, nothing is rewritten.
--
-- An AWS connection is one customer account Stackurity reads through a role
-- the customer's stack creates. Stackurity generates the external ID, so no
-- workspace can name the role of another workspace's account (the confused
-- deputy problem). The role is assumed with Stackurity's own AWS principal
-- (STACKURITY_AWS_PRINCIPAL_ARN) and the integration it feeds runs the
-- aws-managed plugin with short-lived credentials from that role.

SELECT set_config('stackurity.scope', 'system', true);

-- status: pending (waiting for the role ARN, from the stack's callback or
-- pasted), active (the role was assumed with the external ID and the
-- integration exists) or failed (last_error says why; verifying again is
-- allowed). The callback token is signed with the installation's
-- "aws-callback" key and carries a nonce; only the nonce's SHA-256 is kept,
-- and callback_used_at makes the token single use.
CREATE TABLE aws_connections (
    id                  bigserial PRIMARY KEY,
    workspace_id        bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    external_id         text NOT NULL UNIQUE CHECK (external_id ~ '^stk-[0-9a-f]{32}$'),
    regions             text[] NOT NULL CHECK (cardinality(regions) BETWEEN 1 AND 40),
    agent_install       boolean NOT NULL DEFAULT false,
    status              text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'failed')),
    role_arn            text NOT NULL DEFAULT '' CHECK (length(role_arn) <= 2048),
    account_id          text NOT NULL DEFAULT '' CHECK (account_id = '' OR account_id ~ '^[0-9]{12}$'),
    last_error          text NOT NULL DEFAULT '' CHECK (length(last_error) <= 2000),
    integration_id      bigint UNIQUE REFERENCES integrations(id) ON DELETE SET NULL,
    callback_nonce_hash bytea,
    callback_expires_at timestamptz,
    callback_used_at    timestamptz,
    created_by          bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    verified_at         timestamptz
);
CREATE INDEX aws_connections_workspace ON aws_connections (workspace_id);
CREATE TRIGGER aws_connections_integration_id_same_ws BEFORE INSERT OR UPDATE OF integration_id ON aws_connections
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('integrations', 'integration_id');
ALTER TABLE aws_connections ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON aws_connections USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON aws_connections USING (stackurity_system()) WITH CHECK (stackurity_system());

-- One agent install on one EC2 instance through SSM Run Command, with a
-- single-use enrollment code made for it (never stored here). status:
-- pending/running while SSM runs the command, then success, failed or
-- timed_out; detail holds the end of the command's output or the error.
CREATE TABLE aws_agent_installs (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    connection_id  bigint NOT NULL REFERENCES aws_connections(id) ON DELETE CASCADE,
    region         text NOT NULL CHECK (region ~ '^[a-z]{2}(-gov)?-[a-z]+-[0-9]$'),
    instance_id    text NOT NULL CHECK (instance_id ~ '^(i|mi)-[0-9a-f]{8,32}$'),
    computer_name  text NOT NULL DEFAULT '' CHECK (length(computer_name) <= 255),
    enrollment_id  bigint REFERENCES enrollments(id) ON DELETE SET NULL,
    command_id     text NOT NULL DEFAULT '' CHECK (length(command_id) <= 64),
    status         text NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'timed_out')),
    detail         text NOT NULL DEFAULT '' CHECK (length(detail) <= 4000),
    created_by     bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    checked_at     timestamptz
);
CREATE INDEX aws_agent_installs_connection ON aws_agent_installs (connection_id, created_at DESC);
CREATE INDEX aws_agent_installs_workspace ON aws_agent_installs (workspace_id);
CREATE TRIGGER aws_agent_installs_connection_id_same_ws BEFORE INSERT OR UPDATE OF connection_id ON aws_agent_installs
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('aws_connections', 'connection_id');
CREATE TRIGGER aws_agent_installs_enrollment_id_same_ws BEFORE INSERT OR UPDATE OF enrollment_id ON aws_agent_installs
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('enrollments', 'enrollment_id');
ALTER TABLE aws_agent_installs ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON aws_agent_installs USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON aws_agent_installs USING (stackurity_system()) WITH CHECK (stackurity_system());
