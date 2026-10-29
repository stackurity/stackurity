package store

import (
	"context"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Addresses an account recently signed in from (docs/install.md,
// "Sessions"): kept in rate_limits as a marker row under bucket, like the
// failure counters, so no table is needed and housekeeping removes them
// when they expire.

// RememberAddress marks subject (an account and client address) as having
// signed in successfully, for memory from now.
func (s *Store) RememberAddress(ctx context.Context, bucket, subject string, memory time.Duration) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO rate_limits (key, window_start, hits, expires_at)
		VALUES ($1, $3::timestamptz, 1, now() + make_interval(secs => $2))
		ON CONFLICT (key, window_start) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		rateLimitKey(bucket, subject), memory.Seconds(), failureEpoch)
	return err
}

// AddressKnown reports whether subject signed in successfully within its
// memory.
func (s *Store) AddressKnown(ctx context.Context, bucket, subject string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT EXISTS (SELECT 1 FROM rate_limits
		WHERE key = $1 AND window_start = $2::timestamptz AND expires_at >= now())`, rateLimitKey(bucket, subject), failureEpoch).Scan(&ok)
	return ok, err
}
