-- FIRST's Exploit Prediction Scoring System (EPSS): the probability that a
-- CVE is exploited in the wild in the next 30 days, and its percentile among
-- all scored CVEs. Public intelligence shared by every workspace, like
-- known_exploited; the feed epss:first replaces it whole once a day.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE epss_scores (
    cve            text PRIMARY KEY,
    score          real NOT NULL CHECK (score >= 0 AND score <= 1),
    percentile     real NOT NULL CHECK (percentile >= 0 AND percentile <= 1),
    -- The model that produced the score (v2026.06.15) and the day it was
    -- scored; the same for every row of one file.
    model_version  text NOT NULL,
    score_date     date NOT NULL
);

-- A feed kind for predictions: a stale EPSS feed makes priorities older than
-- promised, but nothing goes unmatched, so it is a warning and a P3 feed
-- incident rather than a vulnerability feed's critical problem.
ALTER TABLE feeds DROP CONSTRAINT IF EXISTS feeds_kind_check;
ALTER TABLE feeds ADD CONSTRAINT feeds_kind_check CHECK (kind IN ('vulnerability', 'release', 'lifecycle', 'prediction'));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON epss_scores TO stackurity_app;
    END IF;
END $$;
