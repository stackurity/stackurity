-- The second check of leaked keys and risky settings (internal/secondcheck,
-- docs/verification.md "Second check"). Each open or resolved leak and
-- config finding gets a verdict: confirmed, likely_false_positive, fixed or
-- could_not_check, with a one-line reason and the version of the rules that
-- gave it.
--
-- leaks.value_checker and value_signals are what the collector's value
-- check (internal/secondcheck/valuecheck) read in the value while it had
-- it: a placeholder, a provider's test-mode key, a published sample, a
-- token whose built-in checksum does not match. Signals come from a fixed
-- list, enforced here, so the column cannot hold the value or part of it.
--
-- The latest verdict is kept on the row (recheck_*), for lists, filters and
-- alerts; every verdict ever given is kept in second_check_verdicts, which
-- is append-only (an update is refused; rows go only with their leak,
-- finding, asset or workspace), so the evidence pack can show how a
-- conclusion was reached.
--
-- Additive: new columns with constant defaults, one new table. The leaks
-- and config_findings tables are small (at most 1,000 per asset and
-- collector), so the checks are validated in place.
--
-- Release owner: renumber this file if another migration takes 0120 first.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE leaks
    ADD COLUMN value_checker   text NOT NULL DEFAULT '' CHECK (value_checker ~ '^([a-z]+/[0-9]{1,4})?$'),
    ADD COLUMN value_signals   text[] NOT NULL DEFAULT '{}' CHECK (value_signals <@ ARRAY['placeholder', 'low_entropy',
        'test_mode_key', 'known_sample', 'checksum_valid', 'checksum_invalid']::text[]),
    ADD COLUMN recheck_verdict text NOT NULL DEFAULT '' CHECK (recheck_verdict IN ('', 'confirmed', 'likely_false_positive',
        'fixed', 'could_not_check')),
    ADD COLUMN recheck_reason  text NOT NULL DEFAULT '' CHECK (length(recheck_reason) <= 1000),
    ADD COLUMN recheck_checker text NOT NULL DEFAULT '' CHECK (length(recheck_checker) <= 64),
    ADD COLUMN recheck_at      timestamptz;

ALTER TABLE config_findings
    ADD COLUMN recheck_verdict text NOT NULL DEFAULT '' CHECK (recheck_verdict IN ('', 'confirmed', 'likely_false_positive',
        'fixed', 'could_not_check')),
    ADD COLUMN recheck_reason  text NOT NULL DEFAULT '' CHECK (length(recheck_reason) <= 1000),
    ADD COLUMN recheck_checker text NOT NULL DEFAULT '' CHECK (length(recheck_checker) <= 64),
    ADD COLUMN recheck_at      timestamptz;

CREATE TABLE second_check_verdicts (
    id                bigserial PRIMARY KEY,
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id          bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    leak_id           bigint REFERENCES leaks(id) ON DELETE CASCADE,
    config_finding_id bigint REFERENCES config_findings(id) ON DELETE CASCADE,
    verdict           text NOT NULL CHECK (verdict IN ('confirmed', 'likely_false_positive', 'fixed', 'could_not_check')),
    reason            text NOT NULL CHECK (length(reason) <= 1000),
    checker           text NOT NULL CHECK (length(checker) <= 64),
    -- What the check read (rule, file, signals, scan state); never a value.
    inputs            jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(inputs) <= 8192),
    checked_at        timestamptz NOT NULL DEFAULT now(),
    CHECK ((leak_id IS NULL) <> (config_finding_id IS NULL))
);
CREATE INDEX second_check_verdicts_leak ON second_check_verdicts (leak_id, id) WHERE leak_id IS NOT NULL;
CREATE INDEX second_check_verdicts_config ON second_check_verdicts (config_finding_id, id) WHERE config_finding_id IS NOT NULL;
CREATE INDEX second_check_verdicts_asset ON second_check_verdicts (asset_id);
CREATE INDEX second_check_verdicts_workspace ON second_check_verdicts (workspace_id, checked_at);
CREATE TRIGGER second_check_verdicts_asset_id_same_ws BEFORE INSERT ON second_check_verdicts
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');

CREATE FUNCTION second_check_verdicts_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'second_check_verdicts is append-only: a verdict is never changed, a new one is added'
        USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER second_check_verdicts_append_only BEFORE UPDATE ON second_check_verdicts
    FOR EACH ROW EXECUTE FUNCTION second_check_verdicts_guard();

ALTER TABLE second_check_verdicts ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON second_check_verdicts
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON second_check_verdicts USING (stackurity_system()) WITH CHECK (stackurity_system());
