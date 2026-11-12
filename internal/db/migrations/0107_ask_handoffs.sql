-- Ask Stackurity hand-offs (owner decision 2026-11-12): when the person
-- asks Ask to connect something, Ask stores a hand-off with tool 'connect'
-- (internal/ask/handoff.go). Its card starts the service's own flow, links
-- to the setup page, or, for a server, creates an install code when the
-- person clicks Apply (internal/api/ask_proposals.go).
--
-- status 'started': the person clicked the card's button or link; the
-- connection is finished on the service's page, not here.
-- args->>'kind' of a hand-off is one of the kinds Ask can hand off
-- (ask.ConnectKinds): never a disconnect, a token, SSO, users or billing.
SET LOCAL lock_timeout = '10s';

SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE ask_proposals DROP CONSTRAINT ask_proposals_tool_check;
ALTER TABLE ask_proposals ADD CONSTRAINT ask_proposals_tool_check
    CHECK (tool IN ('assign', 'snooze', 'ignore', 'check_again', 'add_assets_to_project', 'rename_project', 'connect'));

ALTER TABLE ask_proposals DROP CONSTRAINT ask_proposals_status_check;
ALTER TABLE ask_proposals ADD CONSTRAINT ask_proposals_status_check
    CHECK (status IN ('proposed', 'applying', 'applied', 'dismissed', 'failed', 'undoing', 'undone', 'started'));

ALTER TABLE ask_proposals ADD CONSTRAINT ask_proposals_connect_kind
    CHECK (tool <> 'connect' OR args->>'kind' IN ('github', 'gitlab', 'jira', 'pagerduty', 'slack', 'teams', 'email', 'webhook', 'server', 'digitalocean'));
