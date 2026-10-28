package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Rate limits shared by every replica (migration 0020). Each key counts hits
// in fixed windows aligned to the database clock, so replicas with skewed
// clocks still agree on where a window starts. The table is a platform table:
// these methods run in system scope themselves, because the callers are
// unauthenticated requests (sign-in, setup, enrollment) with no scope at all.

// rateLimitKey names a counter without keeping the subject (an address, an
// email) in clear.
func rateLimitKey(bucket, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return bucket + ":" + hex.EncodeToString(sum[:16])
}

// RateLimitHit counts one hit for subject in bucket in the current window and
// returns the window's hits, this one included. The increment is a single
// upsert, so concurrent hits on any replica are each counted once.
func (s *Store) RateLimitHit(ctx context.Context, bucket, subject string, window time.Duration) (int, error) {
	if window < time.Second {
		return 0, fmt.Errorf("rate limit window %s is shorter than a second: %w", window, ErrInvalid)
	}
	var hits int
	err := s.Pool.QueryRow(tenant.System(ctx), `INSERT INTO rate_limits AS r (key, window_start, hits, expires_at)
		SELECT $1, w.start, 1, w.start + make_interval(secs => $2)
		FROM (SELECT to_timestamp(floor(extract(epoch FROM now()) / $2) * $2) AS start) w
		ON CONFLICT (key, window_start) DO UPDATE SET hits = r.hits + 1
		RETURNING hits`, rateLimitKey(bucket, subject), window.Seconds()).Scan(&hits)
	return hits, err
}

// PurgeRateLimits deletes windows that have ended and returns how many.
func (s *Store) PurgeRateLimits(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM rate_limits WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Failure counters (login backoff). A counter is one rate_limits row whose
// window_start is the epoch, so it never meets a fixed-window row: hits is
// the number of failures in a row, and expires_at is the last failure plus
// the memory passed in, after which the failures are forgotten (and the
// hourly housekeeping deletes the row). Times come from the database clock,
// so replicas agree.

// failureEpoch is the window_start that marks a failure counter.
const failureEpoch = "epoch"

// RecordFailure counts one failure for subject in bucket and returns the
// failures in a row, this one included, and the database time of this one.
func (s *Store) RecordFailure(ctx context.Context, bucket, subject string, memory time.Duration) (int, time.Time, error) {
	if memory < time.Second {
		return 0, time.Time{}, fmt.Errorf("failure memory %s is shorter than a second: %w", memory, ErrInvalid)
	}
	var n int
	var at time.Time
	err := s.Pool.QueryRow(tenant.System(ctx), `INSERT INTO rate_limits AS r (key, window_start, hits, expires_at)
		VALUES ($1, $3::timestamptz, 1, now() + make_interval(secs => $2))
		ON CONFLICT (key, window_start) DO UPDATE
		SET hits = CASE WHEN r.expires_at < now() THEN 1 ELSE r.hits + 1 END, expires_at = EXCLUDED.expires_at
		RETURNING hits, now()`, rateLimitKey(bucket, subject), memory.Seconds(), failureEpoch).Scan(&n, &at)
	return n, at, err
}

// Failures returns subject's failures in a row in bucket, the database time
// of the last one and the database's current time; no failures is 0.
func (s *Store) Failures(ctx context.Context, bucket, subject string, memory time.Duration) (n int, last, now time.Time, err error) {
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT COALESCE(max(hits), 0),
			COALESCE(max(expires_at) - make_interval(secs => $2), now()), now()
		FROM rate_limits WHERE key = $1 AND window_start = $3::timestamptz AND expires_at >= now()`,
		rateLimitKey(bucket, subject), memory.Seconds(), failureEpoch).Scan(&n, &last, &now)
	return n, last, now, err
}

// ClearFailures forgets subject's failures in bucket.
func (s *Store) ClearFailures(ctx context.Context, bucket, subject string) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM rate_limits WHERE key = $1 AND window_start = $2::timestamptz`,
		rateLimitKey(bucket, subject), failureEpoch)
	return err
}

// RateLimitCount returns subject's hits in bucket in the current window of
// length window, without counting one.
func (s *Store) RateLimitCount(ctx context.Context, bucket, subject string, window time.Duration) (int, error) {
	if window < time.Second {
		return 0, fmt.Errorf("rate limit window %s is shorter than a second: %w", window, ErrInvalid)
	}
	var hits int
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT COALESCE(max(hits), 0) FROM rate_limits
		WHERE key = $1 AND window_start = to_timestamp(floor(extract(epoch FROM now()) / $2) * $2)`,
		rateLimitKey(bucket, subject), window.Seconds()).Scan(&hits)
	return hits, err
}
