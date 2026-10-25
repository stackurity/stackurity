-- A deduplicated job that is already running cannot absorb a new request:
-- the work it is doing may predate the data that triggered the request.
-- requeue marks such a job to run once more after it finishes.
ALTER TABLE jobs ADD COLUMN requeue boolean NOT NULL DEFAULT false;

-- When the asset was last fully evaluated, taken as the start of that run, so
-- a CI gate can tell whether a submitted collection has been evaluated yet.
ALTER TABLE assets ADD COLUMN evaluated_at timestamptz;

-- What reduces the risk while a finding is suppressed or accepted (a WAF
-- rule, a disabled feature, a restricted network path).
ALTER TABLE findings ADD COLUMN mitigation text NOT NULL DEFAULT '';
