-- Upgrade recommendations pick the newest stable release in a major line,
-- so release data keeps every stable, non-withdrawn version a registry lists
-- (version_dates only covers versions the registry dates).
ALTER TABLE package_releases ADD COLUMN stable_versions text[] NOT NULL DEFAULT '{}';

-- The matcher now records when it resolves or reopens a finding
-- (finding_events actions 'resolved' and 'reopened'), so the outcomes report
-- can count reopened findings and time each open episode.
CREATE INDEX finding_events_detection ON finding_events (action, at) WHERE action IN ('resolved', 'reopened');
CREATE INDEX findings_resolved_at ON findings (resolved_at) WHERE status = 'resolved';
