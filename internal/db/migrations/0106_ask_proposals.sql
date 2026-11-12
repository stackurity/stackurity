-- Ask Stackurity may propose changes (owner decision 2026-11-12): the model
-- can only propose; the person applies a proposal with a click in the
-- panel, through the same API and role checks as the dashboard
-- (internal/api/ask_proposals.go).
--
-- ask_propose: the organisation admin's switch "Ask may propose changes".
-- Off for the organisations that exist now (they agreed to a read-only
-- assistant), on for organisations created from now on: the column is
-- added with false, which fills every existing row, and its default is
-- then changed to true, as 0086 did for ask_enabled.
SET LOCAL lock_timeout = '10s';

ALTER TABLE workspaces ADD COLUMN ask_propose boolean NOT NULL DEFAULT false;
ALTER TABLE workspaces ALTER COLUMN ask_propose SET DEFAULT true;

SELECT set_config('stackurity.scope', 'system', true);

-- One proposed change, tied to the conversation and the question it
-- answered (question_seq: the person's message). The confirm code is the
-- one the write tool's preview gave (internal/mcp/write.go confirmCode); it
-- never goes to the model. A proposal is applied at most once: status moves
-- from proposed to applying (one request wins) to applied or failed. A
-- proposal still proposed after expires_at is shown as expired. It is
-- deleted with its conversation.
CREATE TABLE ask_proposals (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    conversation_id bigint NOT NULL REFERENCES ask_conversations(id) ON DELETE CASCADE,
    user_id         bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    question_seq    integer NOT NULL CHECK (question_seq >= 1),
    tool            text NOT NULL CHECK (tool IN ('assign', 'snooze', 'ignore', 'check_again', 'add_assets_to_project', 'rename_project')),
    args            jsonb NOT NULL,
    summary         text NOT NULL CHECK (length(summary) <= 2000),
    details         jsonb NOT NULL DEFAULT '{}',
    notes           jsonb NOT NULL DEFAULT '[]',
    code            text NOT NULL CHECK (length(code) BETWEEN 1 AND 64),
    unrequested     boolean NOT NULL DEFAULT false,
    status          text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'applying', 'applied', 'dismissed', 'failed', 'undoing', 'undone')),
    -- changed: the preview was made again at Apply because what the change
    -- covers had changed; the person sees the new one and applies again.
    changed         boolean NOT NULL DEFAULT false,
    result          jsonb,
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    link            text NOT NULL DEFAULT '' CHECK (length(link) <= 300),
    undo            jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    decided_at      timestamptz,
    undone_at       timestamptz
);
CREATE INDEX ask_proposals_conversation ON ask_proposals (conversation_id, question_seq);
ALTER TABLE ask_proposals ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_proposals USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_proposals USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ask_proposals TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE ask_proposals_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
