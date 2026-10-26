-- Release 1.0, "proof": an independent second check of high-impact
-- findings, recorded apart from detection.
--
-- Everything here is additive. findings gets no new column; the why-it-
-- matched explanation lives in findings.evidence ("match", written by the
-- matcher). The one new index on findings is partial and small (open
-- high-impact findings only); building it reads the open findings once.

-- The latest second check of one finding. basis is a hash of the match it
-- checked (see store.matchBasis); when the matcher changes the match the row
-- is deleted and the finding is checked again.
--   agreed           the independent check reached the same verdict
--   disagreed        it did not; differences says what differs. A person
--                    should review it; verification, priority and SOS are
--                    left as they are, so a defect here never hides an issue.
--   could_not_check  it could not decide; reason says why
CREATE TABLE second_checks (
    finding_id    bigint PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    basis         text NOT NULL,
    result        text NOT NULL CHECK (result IN ('agreed', 'disagreed', 'could_not_check')),
    reason        text NOT NULL DEFAULT '',
    differences   jsonb NOT NULL DEFAULT '[]',
    independent   jsonb NOT NULL DEFAULT '{}',   -- what the second check derived
    checked_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX second_checks_workspace ON second_checks (workspace_id, result);
ALTER TABLE second_checks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Seen through its finding, so a project-narrowed connection (0032) sees the
-- checks of the assets it can see.
CREATE POLICY ws ON second_checks
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR EXISTS (SELECT 1 FROM findings f WHERE f.id = second_checks.finding_id)))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR EXISTS (SELECT 1 FROM findings f WHERE f.id = second_checks.finding_id)));
CREATE POLICY sys ON second_checks USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Every disagreement, kept after the finding changes or closes, with the raw
-- inputs both sides read: the material for new matching corpus cases.
CREATE TABLE second_check_disagreements (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    finding_id    bigint REFERENCES findings(id) ON DELETE SET NULL,
    asset_id      bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    key           text NOT NULL,
    purl          text NOT NULL,
    version       text NOT NULL,
    differences   jsonb NOT NULL,
    inputs        jsonb NOT NULL,                -- the finding's claim and the records read
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX second_check_disagreements_workspace ON second_check_disagreements (workspace_id, created_at DESC);
ALTER TABLE second_check_disagreements ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Follows its asset, like inventory and findings under projects (0032).
CREATE POLICY ws ON second_check_disagreements
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON second_check_disagreements USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Every reference names a row of the same workspace (see 0025).
CREATE TRIGGER second_checks_finding_id_same_ws BEFORE INSERT OR UPDATE OF finding_id ON second_checks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('findings', 'finding_id');
CREATE TRIGGER second_check_disagreements_finding_id_same_ws BEFORE INSERT OR UPDATE OF finding_id ON second_check_disagreements
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('findings', 'finding_id');
CREATE TRIGGER second_check_disagreements_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON second_check_disagreements
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');

-- Open findings the second check covers: P1, SOS, known exploited,
-- regressed, unconfirmed versions and matches the matcher marked ambiguous.
-- Keep this predicate in step with store.secondCheckWanted.
CREATE INDEX findings_second_check ON findings (workspace_id, id)
    WHERE status = 'open' AND kind IN ('vulnerability', 'end_of_life') AND (
        priority = 'P1' OR sos OR regressed_at IS NOT NULL OR verification = 'needs_validation'
        OR (evidence->>'known_exploited') = 'true' OR evidence->'match' ? 'ambiguous');
