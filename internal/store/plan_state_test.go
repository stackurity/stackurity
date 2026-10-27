package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestProjectLimitStore: unset by default; at the limit new projects (and
// projects taken out of the archive) are refused; existing projects are
// never archived or deleted by a lower limit; archiving makes room.
func TestProjectLimitStore(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var ids []int64
	for i := 0; i < 3; i++ {
		p, err := s.CreateProject(ctx, fmt.Sprintf("p%d", i), "")
		if err != nil {
			t.Fatalf("no limit: %v", err)
		}
		ids = append(ids, p.ID)
	}
	u, err := s.AssetUsage(ctx)
	if err != nil || u.Projects != 3 || u.ProjectLimit != nil || u.ProjectsAtLimit || u.ReadOnly != nil || u.ReportMode != store.ReportFull {
		t.Fatalf("usage without limits: %+v %v", u, err)
	}
	// A lower limit than the projects there are keeps every one of them.
	if err := s.SetProjectLimit(ctx, tenant.DefaultWorkspace, limit(2)); err != nil {
		t.Fatal(err)
	}
	ps, err := s.ListProjects(ctx, false)
	if err != nil || len(ps) != 3 {
		t.Fatalf("projects after a lower limit: %d %v", len(ps), err)
	}
	_, err = s.CreateProject(ctx, "p3", "")
	var pe *store.ProjectLimitError
	if !errors.As(err, &pe) || pe.Limit != 2 || pe.Projects != 3 {
		t.Fatalf("over the limit: %v", err)
	}
	if u, _ := s.AssetUsage(ctx); u.Projects != 3 || u.ProjectLimit == nil || *u.ProjectLimit != 2 || !u.ProjectsAtLimit {
		t.Errorf("usage at the limit: %+v", u)
	}
	// Archiving two makes room for one; taking one out of the archive
	// again is refused when that would go over.
	yes, no := true, false
	for _, id := range ids[:2] {
		if err := s.UpdateProject(ctx, id, store.ProjectUpdate{Archived: &yes}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateProject(ctx, "p3", ""); err != nil {
		t.Fatalf("with room: %v", err)
	}
	if err := s.UpdateProject(ctx, ids[0], store.ProjectUpdate{Archived: &no}); !errors.Is(err, store.ErrProjectLimit) {
		t.Errorf("unarchive at the limit: %v", err)
	}
	// Renaming an active project at the limit is fine.
	name := "renamed"
	if err := s.UpdateProject(ctx, ids[2], store.ProjectUpdate{Name: &name, Archived: &no}); err != nil {
		t.Errorf("rename at the limit: %v", err)
	}
	if err := s.SetProjectLimit(ctx, tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateProject(ctx, ids[0], store.ProjectUpdate{Archived: &no}); err != nil {
		t.Errorf("unarchive without a limit: %v", err)
	}
	if err := s.SetProjectLimit(ctx, tenant.DefaultWorkspace, limit(-1)); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("negative limit: %v", err)
	}
}

// TestProjectLimitConcurrent: admins racing for the last place cannot go
// over the limit.
func TestProjectLimitConcurrent(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := s.SetProjectLimit(ctx, tenant.DefaultWorkspace, limit(2)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.CreateProject(ctx, fmt.Sprintf("race-%d", i), "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrProjectLimit):
				refused++
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 2 || refused != 6 {
		t.Errorf("created %d, refused %d; want 2 and 6", ok, refused)
	}
}

// TestReadOnlyStore: a read-only workspace refuses every upload, for new
// and existing assets, and enrollment, keeps its earliest time when set
// again, is left out of the collecting workspaces, and works again when
// cleared. Another workspace is not affected.
func TestReadOnlyStore(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	wsB, _, err := s.CreateWorkspace(bg, "Beta", "", "admin-b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)
	if _, err := s.Ingest(a, quotaBatch(model.AssetHost, "a-1", "machine-id"), 0); err != nil {
		t.Fatal(err)
	}
	e, code, err := s.CreateEnrollment(a, store.Enrollment{Label: "later", UsesLeft: 1}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckWritable(a); err != nil {
		t.Fatalf("writable by default: %v", err)
	}
	first := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	if err := s.SetReadOnly(bg, tenant.DefaultWorkspace, &first, "The trial ended."); err != nil {
		t.Fatal(err)
	}
	later := time.Now()
	if err := s.SetReadOnly(bg, tenant.DefaultWorkspace, &later, "The plan ended."); err != nil {
		t.Fatal(err)
	}
	var ro *store.ReadOnlyError
	for name, b := range map[string]*model.ObservationBatch{
		"existing host": quotaBatch(model.AssetHost, "a-1", "machine-id"),
		"new host":      quotaBatch(model.AssetHost, "a-2", "machine-id"),
	} {
		if _, err := s.Ingest(a, b, 0); !errors.As(err, &ro) || !ro.Since.Equal(first) || ro.Reason != "The plan ended." {
			t.Errorf("%s while read-only: %v", name, err)
		}
	}
	if _, _, err := s.RedeemEnrollment(bg, code, "web-9"); !errors.Is(err, store.ErrReadOnly) {
		t.Errorf("redeem while read-only: %v", err)
	}
	if es, _ := s.ListEnrollments(a); len(es) != 1 || es[0].UsesLeft != 1 || es[0].ID != e.ID {
		t.Errorf("the code was used up: %+v", es)
	}
	ids, err := s.CollectingWorkspaceIDs(tenant.System(bg))
	if err != nil || len(ids) != 1 || ids[0] != wsB.ID {
		t.Errorf("collecting workspaces: %v %v", ids, err)
	}
	if u, _ := s.AssetUsage(a); u.ReadOnly == nil || !u.ReadOnly.Since.Equal(first) {
		t.Errorf("usage while read-only: %+v", u)
	}
	// B is not affected.
	if _, err := s.Ingest(b, quotaBatch(model.AssetHost, "b-1", "machine-id"), 0); err != nil {
		t.Errorf("B: %v", err)
	}
	// System work (demo data) has no workspace and is never read-only.
	if err := s.CheckWritable(bg); err != nil {
		t.Errorf("system scope: %v", err)
	}
	if err := s.SetReadOnly(bg, tenant.DefaultWorkspace, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(a, quotaBatch(model.AssetHost, "a-2", "machine-id"), 0); err != nil {
		t.Errorf("writable again: %v", err)
	}
	if _, _, err := s.RedeemEnrollment(bg, code, "web-9"); err != nil {
		t.Errorf("redeem when writable: %v", err)
	}
	if err := s.SetReadOnly(bg, 9999, &later, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown workspace: %v", err)
	}
}

// TestReportModeStore: full by default, trial when set, per workspace.
func TestReportModeStore(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	if m, err := s.ReportMode(a); err != nil || m != store.ReportFull {
		t.Fatalf("default: %q %v", m, err)
	}
	if err := s.SetReportMode(bg, tenant.DefaultWorkspace, "half"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad mode: %v", err)
	}
	if err := s.SetReportMode(bg, tenant.DefaultWorkspace, store.ReportTrial); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.ReportMode(a); m != store.ReportTrial {
		t.Errorf("after set: %q", m)
	}
	if m, _ := s.ReportMode(bg); m != store.ReportFull {
		t.Errorf("no workspace: %q", m)
	}
}

// TestDeleteWorkspace: everything in the workspace goes, accounts that
// belonged only to it go, accounts in another workspace and instance
// administrators stay, and other workspaces are untouched.
func TestDeleteWorkspace(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	wsB, _, err := s.CreateWorkspace(bg, "Beta", "", "admin-b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	wsC, _, err := s.CreateWorkspace(bg, "Gamma", "", "admin-c@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	// admin-c is a member of Beta too: the account stays with Gamma.
	if _, err := s.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role)
		SELECT $1, id, 'viewer' FROM users WHERE email = 'admin-c@x.io'`, wsB.ID); err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)
	c := tenant.WithWorkspace(bg, wsC.ID)
	for _, ctx := range []context.Context{b, c} {
		if _, err := s.Ingest(ctx, quotaBatch(model.AssetHost, "shared-name", "machine-id"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateProject(ctx, "p", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Audit(b, store.Actor{Type: "system"}, "test.event", "x", "1", nil); err != nil {
		t.Fatal(err)
	}
	d, err := s.DeleteWorkspace(bg, wsB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "Beta" || d.Assets != 1 || len(d.Users) != 1 || d.Users[0] != "admin-b@x.io" {
		t.Errorf("deleted: %+v", d)
	}
	if _, err := s.GetWorkspace(tenant.System(bg), wsB.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("workspace still there: %v", err)
	}
	for _, table := range []string{"assets", "projects", "audit_events", "workspace_members", "api_tokens"} {
		var n int
		if err := s.Pool.QueryRow(tenant.System(bg), `SELECT count(*) FROM `+table+` WHERE workspace_id = $1`, wsB.ID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s left: %d %v", table, n, err)
		}
	}
	if ok, _ := s.UserExists(tenant.System(bg), "admin-b@x.io"); ok {
		t.Error("the Beta-only account was kept")
	}
	if ok, _ := s.UserExists(tenant.System(bg), "admin-c@x.io"); !ok {
		t.Error("an account in another workspace was removed")
	}
	if u, err := s.AssetUsage(c); err != nil || u.Monitored != 1 || u.Projects != 1 {
		t.Errorf("Gamma after Beta was deleted: %+v %v", u, err)
	}
	if _, err := s.DeleteWorkspace(bg, tenant.DefaultWorkspace); !errors.Is(err, store.ErrConflict) {
		t.Errorf("default workspace: %v", err)
	}
	if _, err := s.DeleteWorkspace(bg, wsB.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("twice: %v", err)
	}
}
