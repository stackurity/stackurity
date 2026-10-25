-- Upgrade recommendations pick the newest stable release in a major line,
-- so release data keeps every stable, non-withdrawn version a registry lists
-- (version_dates only covers versions the registry dates).
ALTER TABLE package_releases ADD COLUMN stable_versions text[] NOT NULL DEFAULT '{}';
