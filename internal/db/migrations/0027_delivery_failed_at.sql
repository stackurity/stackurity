-- When a notification delivery ran out of attempts, so that metrics and the
-- health check can count deliveries that failed recently (as they do for
-- jobs) instead of every failure ever kept. Retrying a delivery by hand
-- clears it. Deliveries that failed before this migration count from the
-- time they were queued.
ALTER TABLE deliveries ADD COLUMN failed_at timestamptz;
UPDATE deliveries SET failed_at = created_at WHERE status = 'failed';
CREATE INDEX deliveries_failed ON deliveries (failed_at) WHERE status = 'failed';
