-- Config findings: a fourth category, attack_tool, for known attack tools
-- found on an asset (internal/collect/confcheck/attacktools.go): a Go
-- binary built from ARTEX, an image of it (including the builds reported to
-- carry a backdoor) or a copy of its source. Findings, alerts and
-- dismissal work as for the other categories.
--
-- Additive: the category check is widened. The table is small (risky
-- settings per asset), so the check is validated in place.
--
-- Release owner: renumber this file only if another migration takes the
-- same file name (duplicate numbers are fine).

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE config_findings DROP CONSTRAINT config_findings_category_check;
ALTER TABLE config_findings ADD CONSTRAINT config_findings_category_check
    CHECK (category IN ('agent_hook', 'ssh', 'ci', 'attack_tool'));
