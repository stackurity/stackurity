-- Feedback attachments scanned on demand (deploy/feedback-scan). With
-- STACKURITY_FEEDBACK_SCAN=required, a new attachment is 'pending' and hidden
-- from operators and the triage agent until the scanner reports it 'clean';
-- an 'infected' one is deleted at once (purged_at) and its item flagged.
-- Without scanning, attachments are 'checked' (type, size, structure) as
-- before. The scanner has its own token scope, which can read the list of
-- pending files and report results and nothing else; triage tokens cannot.
-- Additive: new columns with defaults; replaced CHECK constraints.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE feedback_attachments DROP CONSTRAINT feedback_attachments_scan_check;
UPDATE feedback_attachments SET scan = 'checked' WHERE scan = 'checked_clamav';
ALTER TABLE feedback_attachments
    ADD CONSTRAINT feedback_attachments_scan_check CHECK (scan IN ('checked', 'pending', 'clean', 'infected')),
    ADD COLUMN scan_signature text NOT NULL DEFAULT '' CHECK (length(scan_signature) <= 200),
    ADD COLUMN scanned_at timestamptz;
CREATE INDEX feedback_attachments_pending ON feedback_attachments (id) WHERE scan = 'pending' AND purged_at IS NULL;

ALTER TABLE feedback_events DROP CONSTRAINT feedback_events_action_check;
ALTER TABLE feedback_events ADD CONSTRAINT feedback_events_action_check
    CHECK (action IN ('created', 'updated', 'emailed', 'attachments_purged', 'scanned'));

ALTER TABLE feedback_agent_tokens
    ADD COLUMN scope text NOT NULL DEFAULT 'triage' CHECK (scope IN ('triage', 'scanner'));
