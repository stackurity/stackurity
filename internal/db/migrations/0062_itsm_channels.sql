-- PagerDuty and ServiceNow channels (docs/install.md, "PagerDuty" and
-- "ServiceNow"). Like Jira, they keep one record per incident in
-- incident_issues: a PagerDuty alert (issue_key is its dedup key) or a
-- ServiceNow incident (issue_key is its number, remote_id its sys_id).
--
-- Every change is additive (constant defaults or nullable columns):
-- nothing is rewritten.

SET LOCAL lock_timeout = '10s';

ALTER TABLE channels DROP CONSTRAINT channels_kind_check;
ALTER TABLE channels ADD CONSTRAINT channels_kind_check
    CHECK (kind IN ('email', 'stackurity_email', 'slack', 'teams', 'webhook', 'jira', 'pagerduty', 'servicenow'));

-- synced_acked: whether the record was told the incident is acknowledged
-- (no new findings left), so PagerDuty acknowledges the alert once.
-- remote_id: the tracker's own id when it differs from the key shown
-- (ServiceNow sys_id).
-- remote_state: the record's state read back from the tracker when it was
-- closed there (resolved, closed, canceled); empty while it is open there
-- or not read back. remote_checked_at: when it was last read.
ALTER TABLE incident_issues
    ADD COLUMN synced_acked      boolean NOT NULL DEFAULT false,
    ADD COLUMN remote_id         text NOT NULL DEFAULT '',
    ADD COLUMN remote_state      text NOT NULL DEFAULT '',
    ADD COLUMN remote_checked_at timestamptz;
