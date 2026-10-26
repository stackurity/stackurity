-- What the matcher concluded about upstream end of life for a distribution
-- package, when it raised no finding for it: nginx 1.18 is end of life
-- upstream, but this is Ubuntu 22.04's own package and Ubuntu 22.04 still
-- provides security updates. Shown on the component and asset pages and
-- used by the action plan to list a release's packages under its upgrade.
-- NULL when there is nothing to say. Written by each evaluation.
ALTER TABLE inventory ADD COLUMN lifecycle_note jsonb;
