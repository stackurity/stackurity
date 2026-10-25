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
