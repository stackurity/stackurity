-- Feedback agent: the loop that works on feedback as it arrives
-- (tools/feedback-agent). Adds:
--   - status needs_info: the agent or the team asked the sender questions;
--     the sender's answer (from My feedback) puts the item back to new;
--   - the owner's approval of a needs_owner item (approved_at/by/note), and
--     owner_reason, why the item needs the owner (internal);
--   - feedback_comments, a thread under each item the sender can read and
--     answer: questions and updates from the agent or the team, and the
--     sender's replies;
--   - event actions commented, approved, declined;
--   - feedback_sent.thread and status needs_info, so My feedback on the
--     sender's installation shows the thread.
-- Additive: new columns with defaults, a new table, replaced CHECK
-- constraints.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE feedback_items DROP CONSTRAINT feedback_items_status_check;
ALTER TABLE feedback_items ADD CONSTRAINT feedback_items_status_check
    CHECK (status IN ('new', 'triaged', 'in_progress', 'needs_owner', 'needs_info',
                      'fixed', 'released', 'wont_fix', 'duplicate'));
ALTER TABLE feedback_items
    ADD COLUMN owner_reason  text NOT NULL DEFAULT '' CHECK (length(owner_reason) <= 2000),
    ADD COLUMN approved_at   timestamptz,
    ADD COLUMN approved_by   text NOT NULL DEFAULT '' CHECK (length(approved_by) <= 200),
    ADD COLUMN approval_note text NOT NULL DEFAULT '' CHECK (length(approval_note) <= 2000);

ALTER TABLE feedback_events DROP CONSTRAINT feedback_events_action_check;
ALTER TABLE feedback_events ADD CONSTRAINT feedback_events_action_check
    CHECK (action IN ('created', 'updated', 'emailed', 'attachments_purged', 'scanned',
                      'commented', 'approved', 'declined'));

-- The thread the sender sees. author_kind says who wrote it: the agent (a
-- triage token), the team (an instance administrator) or the sender (with
-- the item's status token). author is the token name or the administrator's
-- address; it is never shown to the sender.
CREATE TABLE feedback_comments (
    id          bigserial PRIMARY KEY,
    item_id     bigint NOT NULL REFERENCES feedback_items(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    author_kind text NOT NULL CHECK (author_kind IN ('agent', 'team', 'sender')),
    author      text NOT NULL DEFAULT '' CHECK (length(author) <= 200),
    -- question: asks the sender for details (the item is needs_info).
    kind        text NOT NULL DEFAULT 'comment' CHECK (kind IN ('comment', 'question', 'reply')),
    body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 5000)
);
CREATE INDEX feedback_comments_item ON feedback_comments (item_id, id);
ALTER TABLE feedback_comments ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON feedback_comments USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE feedback_sent DROP CONSTRAINT feedback_sent_status_check;
ALTER TABLE feedback_sent ADD CONSTRAINT feedback_sent_status_check
    CHECK (status IN ('received', 'reviewing', 'needs_info', 'in_progress', 'fixed',
                      'released', 'wont_fix', 'duplicate', 'unknown'));
ALTER TABLE feedback_sent
    ADD COLUMN thread jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(thread) = 'array' AND octet_length(thread::text) <= 65536);
