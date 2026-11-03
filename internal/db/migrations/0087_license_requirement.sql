-- A self-hosted server now needs a key: the free Community key from a
-- sign-up, or a paid licence (internal/license/requirement.go). This row
-- says from when. A new install needs one from the start (it is asked for
-- right after the first administrator is created). A server that already
-- has users or data gets 30 days from its first start on this version, so
-- an upgrade never locks anyone out. The row is written once, here, so
-- restarts and replicas agree.
--
-- observed_seconds counts the time servers were seen running since then
-- (each replica adds the time since the last tick, at most 20 minutes, by
-- the database's clock; never a negative step). An upgraded server is held
-- back only after 30 days of that, or after its grace date has passed and
-- it has run at least 7 days: a clock that jumps forward cannot lock it out
-- early, and one set back cannot keep the grace period going for ever.
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE license_requirement (
    id                int PRIMARY KEY CHECK (id = 1),
    required_from     timestamptz NOT NULL,
    upgraded          boolean NOT NULL,
    observed_seconds  bigint NOT NULL DEFAULT 0 CHECK (observed_seconds >= 0),
    last_tick         timestamptz NOT NULL DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now()
);

INSERT INTO license_requirement (id, required_from, upgraded)
SELECT 1, CASE WHEN existing THEN now() + interval '30 days' ELSE now() END, existing
FROM (SELECT EXISTS (SELECT 1 FROM users) OR EXISTS (SELECT 1 FROM assets) AS existing) e;
