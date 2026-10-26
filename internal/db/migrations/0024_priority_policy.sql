-- The risk policy version (risk.Policy.Version) that produced each finding's
-- priority, score, factors and SOS flag, so a stored priority can be traced to
-- the exact policy behind it. Empty until the finding is next prioritised.
ALTER TABLE findings ADD COLUMN priority_policy text NOT NULL DEFAULT '';
