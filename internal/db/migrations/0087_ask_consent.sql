-- Ask Stackurity: an administrator's consent before it is turned on (owner
-- decision 2026-11-03). Every organisation, new ones included, now starts
-- with the assistant off; it is turned on only with the consent dialog
-- (Integrations → AI assistants), which records the wording's version, who
-- agreed and when (also in the audit log as ask.consent). A later change to
-- the wording needs a new consent: the API treats an organisation whose
-- ask_consent_version is not the current one as off.
SET LOCAL lock_timeout = '10s';

ALTER TABLE workspaces
    ALTER COLUMN ask_enabled SET DEFAULT false,
    ADD COLUMN ask_consent_version text NOT NULL DEFAULT '',
    ADD COLUMN ask_consented_by    bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN ask_consented_at    timestamptz;

-- Nobody has consented yet: whatever was switched on before goes off.
UPDATE workspaces SET ask_enabled = false WHERE ask_enabled;
