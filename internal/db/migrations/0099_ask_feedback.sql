-- Ask Stackurity feedback: what people say about answers (explicit) and
-- signals the server notices itself (implicit), for the Stackurity team to
-- review across installations' organisations (operator only). Additive.
--
-- An explicit row: a thumbs up or down on an answer, or "Send feedback"
-- from the panel's header. With a thumbs down or "Send feedback" the person
-- picks what was wrong (category), what it was about (scope) and may write
-- what they expected (text). With consent (the box under the form, ticked
-- by default) the row keeps a snapshot of the messages it is about, their
-- visible text only, with credentials and colleagues' email addresses
-- removed, so it survives the person deleting the conversation. Without
-- consent there is no snapshot.
--
-- An implicit row: metadata only (category, the conversation and message
-- it is about), never text and never a snapshot.
--
-- Retention (store.PurgeAskFeedback, hourly): snapshots are removed 90 days
-- after the row was made, rows after one year.
--
-- Row-level security keeps rows in their organisation. No organisation
-- endpoint lists them: only the installation's operators (and their
-- feedback review tokens) read them, in system scope.

SET LOCAL lock_timeout = '10s';

CREATE TABLE ask_feedback (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id          bigint REFERENCES users(id) ON DELETE SET NULL,
    conversation_id  bigint REFERENCES ask_conversations(id) ON DELETE SET NULL,
    message_id       bigint REFERENCES ask_messages(id) ON DELETE SET NULL,
    kind             text NOT NULL CHECK (kind IN ('explicit', 'implicit')),
    rating           text CHECK (rating IN ('up', 'down')),
    category         text NOT NULL DEFAULT '' CHECK (length(category) <= 40),
    scope            text NOT NULL DEFAULT 'answer' CHECK (scope IN ('answer', 'chat', 'ui')),
    text             text NOT NULL DEFAULT '' CHECK (length(text) <= 2000),
    consent          boolean NOT NULL DEFAULT false,
    snapshot         jsonb CHECK (snapshot IS NULL OR consent),
    prompt_version   text NOT NULL DEFAULT '' CHECK (length(prompt_version) <= 40),
    model            text NOT NULL DEFAULT '' CHECK (length(model) <= 100),
    usage_call_id    bigint,
    page_path        text NOT NULL DEFAULT '' CHECK (length(page_path) <= 300),
    viewport         text NOT NULL DEFAULT '' CHECK (length(viewport) <= 20),
    status           text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'fixed', 'wontfix')),
    resolution_notes text NOT NULL DEFAULT '' CHECK (length(resolution_notes) <= 4000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (kind = 'explicit' OR (text = '' AND snapshot IS NULL AND rating IS NULL))
);
CREATE INDEX ask_feedback_review ON ask_feedback (status, created_at DESC);
CREATE INDEX ask_feedback_created ON ask_feedback (created_at);
CREATE INDEX ask_feedback_conversation ON ask_feedback (conversation_id);
-- An implicit signal is recorded once per conversation, message and kind of
-- signal.
CREATE UNIQUE INDEX ask_feedback_implicit_once ON ask_feedback (conversation_id, COALESCE(message_id, 0), category)
    WHERE kind = 'implicit';
ALTER TABLE ask_feedback ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ask_feedback USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON ask_feedback USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Read-only tokens for reviewing feedback (an operator's automated
-- reviewer): they work only on /api/v1/admin/ask/feedback (list, read, set
-- status and notes), never anywhere else. Not tied to an organisation.
-- Only a SHA-256 hash of the secret is kept. Platform work only.
CREATE TABLE ask_feedback_review_tokens (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text NOT NULL CHECK (length(prefix) <= 40),
    token_hash   bytea NOT NULL UNIQUE,
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
ALTER TABLE ask_feedback_review_tokens ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON ask_feedback_review_tokens USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ask_feedback, ask_feedback_review_tokens TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE ask_feedback_id_seq, ask_feedback_review_tokens_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
