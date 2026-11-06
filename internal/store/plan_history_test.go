package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestInactivePause: an organisation nobody signed in to is warned 15 and
// 5 days before its pause, then paused (read-only, not collecting); the
// next sign-in resumes it at once and the sweep starts again. One already
// idle past the days when the limit is set still gets both warnings
// first. Without the limit nothing happens.
func TestInactivePause(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	sys := tenant.System(context.Background())
	u, err := s.CreateUser(ctx, "admin@x.io", "Admin", auth.RoleAdmin, "Correct horse battery staple 9!")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	day := 24 * time.Hour
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.Pool.Exec(sys, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE workspaces SET created_at = $1 WHERE id = 1`, now.Add(-400*day))
	exec(`UPDATE users SET last_login_at = $1 WHERE id = $2`, now.Add(-50*day), u.ID)
	sweep := func(at time.Time) []store.InactiveNotice {
		t.Helper()
		n, err := s.SweepInactive(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := sweep(now); len(n) != 0 {
		t.Fatalf("without the limit: %+v", n)
	}
	if err := s.SetPlanLimits(ctx, 1, store.PlanLimits{InactivePauseDays: 60}); err != nil {
		t.Fatal(err)
	}
	n := sweep(now)
	if len(n) != 1 || n[0].Last || len(n[0].Admins) != 1 || n[0].Admins[0] != "admin@x.io" || n[0].PauseOn.Before(now.Add(10*day-time.Minute)) {
		t.Fatalf("first warning: %+v", n)
	}
	if n := sweep(now.Add(time.Hour)); len(n) != 0 {
		t.Errorf("warned twice in an hour: %+v", n)
	}
	if n := sweep(now.Add(10 * day)); len(n) != 1 || !n[0].Last {
		t.Fatalf("last warning: %+v", n)
	}
	if err := s.CheckWritable(ctx); err != nil {
		t.Errorf("read-only before the pause: %v", err)
	}
	pausedAt := now.Add(15 * day)
	sweep(pausedAt)
	var ro *store.ReadOnlyError
	if err := s.CheckWritable(ctx); !errors.As(err, &ro) || ro.Reason != store.PausedReason {
		t.Fatalf("paused: %v", err)
	}
	ids, _ := s.CollectingWorkspaceIDs(sys)
	for _, id := range ids {
		if id == 1 {
			t.Error("a paused organisation is still collecting")
		}
	}
	st, _ := s.GetWorkspaceState(ctx, 1)
	if st.ReadOnly == nil || st.ReadOnly.Reason != store.PausedReason {
		t.Errorf("state: %+v", st)
	}
	// A sign-in resumes it at once; the sweep then forgets the warnings.
	exec(`UPDATE users SET last_login_at = $1 WHERE id = $2`, pausedAt.Add(time.Minute), u.ID)
	if err := s.CheckWritable(ctx); err != nil {
		t.Errorf("after a sign-in: %v", err)
	}
	if n := sweep(pausedAt.Add(time.Hour)); len(n) != 0 {
		t.Errorf("after a sign-in: %+v", n)
	}
	var first *time.Time
	if err := s.Pool.QueryRow(sys, `SELECT inactive_warned_first_at FROM workspaces WHERE id = 1`).Scan(&first); err != nil || first != nil {
		t.Errorf("warnings kept after a sign-in: %v %v", first, err)
	}
	// Idle long past the days when the limit is set: still warned first,
	// with the pause at least 15 days away.
	exec(`UPDATE users SET last_login_at = $1 WHERE id = $2`, now.Add(-200*day), u.ID)
	if n := sweep(now); len(n) != 1 || n[0].PauseOn.Before(now.Add(15*day-time.Minute)) {
		t.Errorf("idle 200 days: %+v", n)
	}
	if n := sweep(now.Add(2 * day)); len(n) != 0 {
		t.Errorf("second warning too soon: %+v", n)
	}
	if err := s.CheckWritable(ctx); err != nil {
		t.Errorf("paused without both warnings: %v", err)
	}
}
