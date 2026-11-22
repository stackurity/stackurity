-- Ask Stackurity: answers that were refused or left incomplete, and notes
-- about a project for Ask (internal/ask).
--
-- 1. ask_api_calls.incomplete_reason: why an answer call ended without a
--    full answer: refusal (the model declined), cannot_answer (the answer
--    says it could not find or answer something), tool_error (a lookup
--    failed and the answer was given without it), max_tokens (cut short),
--    tool_budget (the question used up its lookups), too_long (the
--    conversation outgrew its budget). refusal_category is the provider's
--    category for a refusal. Metadata only, like the rest of the table:
--    never the question or the answer. The daily totals count refusals and
--    incomplete answers.
-- 2. projects.ask_notes: a short text a project's admins write about it
--    ("this is our payments API; host X is a staging box"), which Ask
--    reads as background, never as instructions. At most 2,000 characters.
--
-- Additive: new columns with constant defaults; nothing is rewritten.
--
-- Release owner: renumber this file only if another migration takes the
-- same file name (duplicate numbers are fine).

SET LOCAL lock_timeout = '10s';

ALTER TABLE ask_api_calls
    ADD COLUMN incomplete_reason text NOT NULL DEFAULT ''
        CHECK (incomplete_reason IN ('', 'refusal', 'cannot_answer', 'tool_error', 'max_tokens', 'tool_budget', 'too_long')),
    ADD COLUMN refusal_category text NOT NULL DEFAULT '' CHECK (length(refusal_category) <= 40);

ALTER TABLE ask_api_calls_daily
    ADD COLUMN refusals   integer NOT NULL DEFAULT 0,
    ADD COLUMN incomplete integer NOT NULL DEFAULT 0;

ALTER TABLE projects
    ADD COLUMN ask_notes            text NOT NULL DEFAULT '' CHECK (char_length(ask_notes) <= 2000),
    ADD COLUMN ask_notes_updated_at timestamptz;
