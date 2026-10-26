-- Grouped notifications. A route no longer sends one message per incident
-- and event: it sends at most one urgent alert per evaluation cycle, a daily
-- or weekly summary at a time of day in its own time zone, and at most one
-- overdue alert a day.
--
-- mode: urgent_summary (urgent alerts right away and a daily summary),
--       daily (daily summary only) or weekly (weekly summary only).
-- summary_time: "HH:MM" in the route's timezone.
-- summary_day: the weekday of the weekly summary.
-- last_summary_at: the end of the period the last summary covered; the next
--       one covers what happened since.
--
-- Existing routes keep their filters, quiet hours, time zone and hourly
-- limit, and become "urgent right away + daily summary" at 09:00; their
-- minimum priority is the urgent threshold. Routes marked escalation used
-- to receive escalations only: they become urgent + summary routes with
-- the overdue section and the daily overdue alert (escalation keeps that
-- meaning), and send_resolved now decides whether summaries list fixed
-- issues.
ALTER TABLE routes
    ADD COLUMN mode text NOT NULL DEFAULT 'urgent_summary' CHECK (mode IN ('urgent_summary', 'daily', 'weekly')),
    ADD COLUMN summary_time text NOT NULL DEFAULT '09:00',
    ADD COLUMN summary_day text NOT NULL DEFAULT 'monday'
        CHECK (summary_day IN ('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')),
    ADD COLUMN last_summary_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE routes ALTER COLUMN min_priority SET DEFAULT 'P1';

-- When notifications first described the asset. Until its first complete
-- collection has been evaluated, the backlog it reports raises no urgent
-- alerts; then one "connected" message describes it. Every asset that
-- exists now counts as announced.
ALTER TABLE assets ADD COLUMN announced_at timestamptz;
UPDATE assets SET announced_at = now();

-- The fix (action plan group) a finding belonged to when it was resolved,
-- kept for summaries ("1,240 closed after Install security updates").
-- Filled when the action plan is rebuilt after the finding resolved.
ALTER TABLE findings
    ADD COLUMN resolved_fix_group text NOT NULL DEFAULT '',
    ADD COLUMN resolved_fix_title text NOT NULL DEFAULT '';
CREATE INDEX findings_resolved_in_group ON findings (fix_group) WHERE status = 'resolved' AND fix_group <> '';

-- Per-incident messages still queued for people (not Jira issues) are not
-- sent one by one any more: they are held and counted in the route's next
-- summary.
UPDATE deliveries d SET status = 'held', last_error = 'replaced by grouped notifications; counted in the next summary'
FROM channels c
WHERE c.id = d.channel_id AND c.kind <> 'jira' AND d.status = 'pending' AND d.route_id IS NOT NULL
  AND d.event IN ('opened', 'priority_raised', 'escalated', 'resolved', 'digest');
