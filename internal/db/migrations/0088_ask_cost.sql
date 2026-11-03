-- Ask Stackurity: keeping long conversations cheap, and a record of every
-- model call (internal/ask). Additive: new columns with constant defaults
-- and two new tables; nothing is rewritten.

SET LOCAL lock_timeout = '10s';

-- The system prompt's version (ask.PromptVersion) on each answer, so a
-- change to the prompt can be compared with what came before.
ALTER TABLE ask_messages
    ADD COLUMN prompt_version text NOT NULL DEFAULT '' CHECK (length(prompt_version) <= 40);

-- A conversation that outgrew its history budget keeps a short summary of
-- its earlier turns (written by a small model) instead of resending them:
-- summary covers every message up to seq summary_through; later messages
-- are sent as they are.
ALTER TABLE ask_conversations
    ADD COLUMN summary         text NOT NULL DEFAULT '' CHECK (length(summary) <= 16000),
    ADD COLUMN summary_through integer NOT NULL DEFAULT 0 CHECK (summary_through >= 0);

-- One row per model call (an answer's round or a summary): metadata only.
-- Never the question, the answer, tool results or the summary. Detailed
-- rows are kept 90 days, then folded into ask_api_calls_daily (kept two
-- years) by housekeeping. conversation_id and user_id go NULL when those
-- are deleted, so the counts and costs stay.
CREATE TABLE ask_api_calls (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id            bigint REFERENCES users(id) ON DELETE SET NULL,
    conversation_id    bigint REFERENCES ask_conversations(id) ON DELETE SET NULL,
    kind               text NOT NULL CHECK (kind IN ('answer', 'summary')),
    model              text NOT NULL DEFAULT '' CHECK (length(model) <= 100),
    prompt_version     text NOT NULL DEFAULT '' CHECK (length(prompt_version) <= 40),
    input_tokens       bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens      bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cache_read_tokens  bigint NOT NULL DEFAULT 0 CHECK (cache_read_tokens >= 0),
    cache_write_tokens bigint NOT NULL DEFAULT 0 CHECK (cache_write_tokens >= 0),
    cost_micros        bigint NOT NULL DEFAULT 0 CHECK (cost_micros >= 0),
    latency_ms         integer NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
    tool_calls         integer NOT NULL DEFAULT 0 CHECK (tool_calls >= 0),
    tool_names         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tool_names) <= 64),
    history_turns_sent integer NOT NULL DEFAULT 0 CHECK (history_turns_sent >= 0),
    summary_used       boolean NOT NULL DEFAULT false,
    stop_reason        text NOT NULL DEFAULT '' CHECK (length(stop_reason) <= 40),
    error_code         text NOT NULL DEFAULT '' CHECK (length(error_code) <= 40),
    request_id         text NOT NULL DEFAULT '' CHECK (length(request_id) <= 200),
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ask_api_calls_ws ON ask_api_calls (workspace_id, created_at DESC);
CREATE INDEX ask_api_calls_created ON ask_api_calls (created_at);
CREATE INDEX ask_api_calls_conversation ON ask_api_calls (conversation_id) WHERE conversation_id IS NOT NULL;
ALTER TABLE ask_api_calls ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_api_calls USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_api_calls USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Totals per organisation, day (UTC), model and kind, kept two years.
CREATE TABLE ask_api_calls_daily (
    workspace_id       bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    day                date NOT NULL,
    model              text NOT NULL,
    kind               text NOT NULL,
    calls              integer NOT NULL DEFAULT 0,
    errors             integer NOT NULL DEFAULT 0,
    input_tokens       bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    cache_read_tokens  bigint NOT NULL DEFAULT 0,
    cache_write_tokens bigint NOT NULL DEFAULT 0,
    cost_micros        bigint NOT NULL DEFAULT 0,
    latency_ms         bigint NOT NULL DEFAULT 0,
    tool_calls         bigint NOT NULL DEFAULT 0,
    summaries_used     integer NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, day, model, kind)
);
CREATE INDEX ask_api_calls_daily_day ON ask_api_calls_daily (day);
ALTER TABLE ask_api_calls_daily ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_api_calls_daily USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_api_calls_daily USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ask_api_calls, ask_api_calls_daily TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE ask_api_calls_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
