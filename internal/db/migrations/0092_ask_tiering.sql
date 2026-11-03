-- Ask Stackurity: the cheapest model first, a stronger one when the person
-- is struggling (owner decision 2026-11-03; internal/ask/tier.go). Each
-- call records the reason it was stepped up and the model it stepped up
-- from, so the step-up rate and the ratings per model can be read from the
-- call log; the daily totals count step-ups too. "triage" is the small
-- Haiku call that asks whether a short follow-up says the last answer was
-- wrong.
SET LOCAL lock_timeout = '10s';

ALTER TABLE ask_api_calls DROP CONSTRAINT IF EXISTS ask_api_calls_kind_check;
ALTER TABLE ask_api_calls
    ADD CONSTRAINT ask_api_calls_kind_check CHECK (kind IN ('answer', 'summary', 'triage')),
    ADD COLUMN step_up_reason text NOT NULL DEFAULT '',
    ADD COLUMN stepped_from    text NOT NULL DEFAULT '';

ALTER TABLE ask_api_calls_daily ADD COLUMN step_ups integer NOT NULL DEFAULT 0;

-- A step up made between questions (a thumbs-down, a stopped answer) is
-- recorded on the conversation until its next answer's call carries it.
ALTER TABLE ask_conversations
    ADD COLUMN pending_step_up      text NOT NULL DEFAULT '',
    ADD COLUMN pending_stepped_from text NOT NULL DEFAULT '';
