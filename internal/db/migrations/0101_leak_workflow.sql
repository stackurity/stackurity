-- Leaked keys as tracked work (store/leaks.go): an owner (a person and/or a
-- team, like findings' assignee columns), a deadline set from the leak's
-- severity when it is first seen, and "I've rotated it": who said so, when
-- and a note. Marking a leak rotated does not resolve it; a complete scan
-- that no longer sees the key does (resolution 'gone', as before). A scan
-- that still sees it after rotated_at shows it as still found.
--
-- Additive: new nullable or defaulted columns, their same-workspace
-- triggers, one CHECK and one partial index. Open leaks get their deadline
-- from the default durations (critical 1 day, high 7, medium 30; low none).

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE leaks
    ADD COLUMN assignee_user_id bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN assignee_team_id bigint REFERENCES teams(id) ON DELETE SET NULL,
    ADD COLUMN due_at           timestamptz,
    ADD COLUMN rotated_at       timestamptz,
    ADD COLUMN rotated_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN rotation_note    text NOT NULL DEFAULT '' CHECK (length(rotation_note) <= 1000),
    ADD CONSTRAINT leaks_rotation_has_time CHECK (rotated_at IS NOT NULL OR (rotated_by IS NULL AND rotation_note = ''));

CREATE TRIGGER leaks_assignee_user_id_same_ws BEFORE INSERT OR UPDATE OF assignee_user_id ON leaks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'assignee_user_id');
CREATE TRIGGER leaks_assignee_team_id_same_ws BEFORE INSERT OR UPDATE OF assignee_team_id ON leaks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('teams', 'assignee_team_id');
CREATE TRIGGER leaks_rotated_by_same_ws BEFORE INSERT OR UPDATE OF rotated_by ON leaks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'rotated_by');

CREATE INDEX leaks_assignee_user ON leaks (assignee_user_id) WHERE assignee_user_id IS NOT NULL;
CREATE INDEX leaks_assignee_team ON leaks (assignee_team_id) WHERE assignee_team_id IS NOT NULL;

UPDATE leaks SET due_at = first_seen + make_interval(days => CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 7 ELSE 30 END)
    WHERE status = 'open' AND severity <> 'low';
