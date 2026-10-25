-- Versions a registry has withdrawn (yanked, retracted or unlisted), as
-- version -> reason ('' when the registry gives none).
ALTER TABLE package_releases ADD COLUMN yanked jsonb NOT NULL DEFAULT '{}';
