-- Ask Stackurity, the in-app assistant (internal/ask). Additive: five
-- workspace columns with constant defaults and six new tables; nothing is
-- rewritten.
--
-- Conversations belong to the person who asked. The API reads them only
-- for that person: an organisation admin can delete every conversation in
-- the organisation but never read one (store/ask.go has no query that
-- returns another person's messages). Row-level security keeps them in
-- their workspace; it is not narrowed to projects, because a conversation
-- is the person's own, not asset data (the tools it ran were narrowed when
-- they ran).

SET LOCAL lock_timeout = '10s';

-- ask_enabled: the organisation admin's switch (Settings → AI assistants).
-- The assistant sends data to a model provider, so it is opt-in for the
-- organisations that exist now: they get false, and an admin turns it on.
-- Organisations created from now on get true (each person still accepts
-- the data notice before their first question).
-- ask_question_limit: questions per ask_question_period (NULL: no limit;
-- 0: not included in the plan); the period is a calendar month, or 'total'
-- for an allowance that never renews (a trial). ask_spend_cap_micros:
-- model spend a month in millionths of a US dollar (NULL: no cap).
-- ask_model: the model for this organisation ('' : the server's default).
-- The limits and the model are set by the edition (Stackurity Cloud: from
-- the plan) or by an instance admin.
ALTER TABLE workspaces
    ADD COLUMN ask_enabled          boolean NOT NULL DEFAULT false,
    ADD COLUMN ask_question_limit   integer CHECK (ask_question_limit IS NULL OR ask_question_limit >= 0),
    ADD COLUMN ask_question_period  text NOT NULL DEFAULT 'month' CHECK (ask_question_period IN ('month', 'total')),
    ADD COLUMN ask_spend_cap_micros bigint CHECK (ask_spend_cap_micros IS NULL OR ask_spend_cap_micros >= 0),
    ADD COLUMN ask_model            text NOT NULL DEFAULT '' CHECK (ask_model ~ '^[A-Za-z0-9._:@/-]{0,100}$');
ALTER TABLE workspaces ALTER COLUMN ask_enabled SET DEFAULT true;

SELECT set_config('stackurity.scope', 'system', true);

-- One conversation. Deleted 30 days after it was created (housekeeping),
-- with its messages. context_tokens is the prompt size of its latest model
-- call, to stop a conversation before it gets too long.
CREATE TABLE ask_conversations (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id        bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id     bigint REFERENCES projects(id) ON DELETE SET NULL,
    model          text NOT NULL CHECK (length(model) BETWEEN 1 AND 100),
    title          text NOT NULL DEFAULT '' CHECK (length(title) <= 200),
    context_tokens bigint NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ask_conversations_user ON ask_conversations (workspace_id, user_id, updated_at DESC);
CREATE INDEX ask_conversations_created ON ask_conversations (created_at);
CREATE TRIGGER ask_conversations_project BEFORE INSERT OR UPDATE OF project_id ON ask_conversations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
ALTER TABLE ask_conversations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_conversations USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_conversations USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The messages of a conversation, in order, append-only: content is the
-- message exactly as sent to or received from the model (content blocks,
-- thinking blocks included), replayed unchanged on the next question. It is
-- json, not jsonb, so its text is kept byte for byte (jsonb would reorder
-- the keys of tool inputs).
-- visible_text is what the person sees. A user message may carry tool
-- results instead of a question (visible_text empty). Usage and cost are
-- set on assistant messages.
CREATE TABLE ask_messages (
    id                 bigserial PRIMARY KEY,
    conversation_id    bigint NOT NULL REFERENCES ask_conversations(id) ON DELETE CASCADE,
    workspace_id       bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    seq                integer NOT NULL CHECK (seq >= 1),
    role               text NOT NULL CHECK (role IN ('user', 'assistant')),
    content            json NOT NULL,
    visible_text       text NOT NULL DEFAULT '',
    page               jsonb,
    model              text NOT NULL DEFAULT '',
    stop_reason        text NOT NULL DEFAULT '',
    input_tokens       bigint NOT NULL DEFAULT 0,
    cache_write_tokens bigint NOT NULL DEFAULT 0,
    cache_read_tokens  bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    cost_micros        bigint NOT NULL DEFAULT 0,
    request_id         text NOT NULL DEFAULT '' CHECK (length(request_id) <= 200),
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (conversation_id, seq)
);
ALTER TABLE ask_messages ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_messages USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_messages USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Questions and model spend per organisation and calendar month (UTC).
-- Counts and money only, no content. alerted_80 and alerted_100: when the
-- organisation's admins were told it reached that share of its cap.
CREATE TABLE ask_usage (
    workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    month        date NOT NULL CHECK (extract(day FROM month) = 1),
    questions    integer NOT NULL DEFAULT 0 CHECK (questions >= 0),
    cost_micros  bigint NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
    alerted_80   timestamptz,
    alerted_100  timestamptz,
    PRIMARY KEY (workspace_id, month)
);
CREATE INDEX ask_usage_month ON ask_usage (month);
ALTER TABLE ask_usage ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_usage USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_usage USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Spend held for model calls in flight, so calls made at once cannot pass
-- a cap together. A call settles its hold when it ends; a hold older than
-- ten minutes (the process died) no longer counts and is removed by
-- housekeeping. Platform work only: the store takes holds in system scope.
CREATE TABLE ask_holds (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    micros       bigint NOT NULL CHECK (micros >= 0),
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ask_holds_created ON ask_holds (created_at);
ALTER TABLE ask_holds ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON ask_holds USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Alerts about the installation's monthly spend cap, sent once per month
-- and level. Platform work only.
CREATE TABLE ask_global_alerts (
    month   date NOT NULL,
    level   integer NOT NULL CHECK (level IN (80, 100)),
    sent_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (month, level)
);
ALTER TABLE ask_global_alerts ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON ask_global_alerts USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The data notice a person accepted before their first question, per
-- organisation and notice version.
CREATE TABLE ask_notice_acceptances (
    workspace_id bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    version      text NOT NULL CHECK (length(version) BETWEEN 1 AND 40),
    accepted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id, version)
);
ALTER TABLE ask_notice_acceptances ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_notice_acceptances USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_notice_acceptances USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ask_conversations, ask_messages, ask_usage, ask_holds, ask_global_alerts, ask_notice_acceptances TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE ask_conversations_id_seq, ask_messages_id_seq, ask_holds_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
