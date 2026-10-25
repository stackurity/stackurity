package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Replicas starting together agree on one setup token, and platform state is
// invisible outside system scope.
func TestSharedSetupTokenAndPlatformIsolation(t *testing.T) {
	st := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	a, err := st.SharedSetupToken(sys, "first")
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.SharedSetupToken(sys, "second")
	if err != nil || a != "first" || b != "first" {
		t.Fatalf("tokens %q %q %v; want both replicas to use the first", a, b, err)
	}
	if err := st.RegisterPeriodic(sys, "secret-task", time.Minute); err != nil {
		t.Fatal(err)
	}

	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := st.SharedSetupToken(ws, "workspace"); err == nil {
		t.Error("a workspace wrote instance state")
	}
	var n int
	if err := st.Pool.QueryRow(ws, `SELECT (SELECT count(*) FROM instance_state) + (SELECT count(*) FROM periodic_tasks)`).Scan(&n); err != nil || n != 0 {
		t.Errorf("workspace scope sees %d platform rows (%v)", n, err)
	}
	if list, err := st.ListPeriodicTasks(ws); err != nil || len(list) != 0 {
		t.Errorf("workspace scope lists tasks: %+v %v", list, err)
	}

	if err := st.ClearSetupToken(sys); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.SharedSetupToken(sys, "third"); c != "third" {
		t.Errorf("after clearing: %q", c)
	}
}
