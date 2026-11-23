-- Config findings: a fifth category, kernel, for kernel modules that let
-- code already running on a server become root
-- (internal/collect/confcheck/kernel.go). The first is SCTP, the root step
-- of nginx2root (Nov 2026). Findings, alerts and dismissal work as for the
-- other categories.
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
    CHECK (category IN ('agent_hook', 'ssh', 'ci', 'attack_tool', 'kernel'));
