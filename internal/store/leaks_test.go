package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func fp(c string) string { return strings.Repeat(c, 32) }

func leak(c, path, severity string) model.Leak {
	return model.Leak{Rule: "github-token", Title: "GitHub token", Severity: severity, Path: path, Line: 2,
		Fingerprint: fp(c), Preview: "ghp_…" + c + c + c + c}
}

// leakBatch is a host's batch with a key scan.
func leakBatch(name string, ids []model.Identifier, complete bool, found ...model.Leak) *model.ObservationBatch {
	b := batch(ids, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Name = name
	b.Leaks = &model.LeakScan{Found: found, Complete: complete}
	if !complete {
		b.Leaks.Reason = "the directory is larger than the scan's limits"
	}
	b.ObservedAt = time.Now().UTC()
	if err := b.Validate(); err != nil {
		panic(err)
	}
	return b
}

func leakState(t *testing.T, s *store.Store, ctx context.Context, assetID int64) map[string]string {
	t.Helper()
	ls, _, err := s.ListLeaks(ctx, store.LeakFilter{AssetID: assetID, Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, l := range ls {
		out[l.Path] = l.Status + "/" + l.Resolution
	}
	return out
}

func TestLeakIngest(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))

	r, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("a", "/srv/app/.env", "critical"), leak("b", "/srv/app/config.php", "high")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.LeaksFound != 2 || r.LeaksGone != 0 {
		t.Errorf("first scan: %+v", r)
	}
	id := r.AssetID

	// An incomplete scan that misses one does not resolve it.
	if r, err = s.Ingest(ctx, leakBatch("web-1", mid, false, leak("a", "/srv/app/.env", "critical")), 0); err != nil || r.LeaksGone != 0 {
		t.Fatalf("incomplete scan: %+v %v", r, err)
	}
	if got := leakState(t, s, ctx, id); got["/srv/app/config.php"] != "open/" {
		t.Errorf("after an incomplete scan: %v", got)
	}
	scans, err := s.LeakScans(ctx, id)
	if err != nil || len(scans) != 1 || scans[0].Complete || scans[0].Reason == "" || scans[0].Found != 1 {
		t.Errorf("scans after an incomplete scan: %+v %v", scans, err)
	}

	// A complete one does.
	if r, err = s.Ingest(ctx, leakBatch("web-1", mid, true, leak("a", "/srv/app/.env", "critical")), 0); err != nil || r.LeaksGone != 1 {
		t.Fatalf("complete scan: %+v %v", r, err)
	}
	if got := leakState(t, s, ctx, id); got["/srv/app/config.php"] != "resolved/gone" || got["/srv/app/.env"] != "open/" {
		t.Errorf("after a complete scan: %v", got)
	}

	// Dismissed stays dismissed when seen again; gone opens again.
	ls, _, _ := s.ListLeaks(ctx, store.LeakFilter{AssetID: id})
	if _, err := s.DismissLeak(ctx, ls[0].ID, nil, "test key, kept on purpose"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Ingest(ctx, leakBatch("web-1", mid, true, leak("a", "/srv/app/.env", "critical"), leak("b", "/srv/app/config.php", "high")), 0); err != nil {
		t.Fatal(err)
	}
	got := leakState(t, s, ctx, id)
	if got["/srv/app/.env"] != "resolved/dismissed" || got["/srv/app/config.php"] != "open/" {
		t.Errorf("after the leak came back: %v", got)
	}
	l, err := s.UndismissLeak(ctx, ls[0].ID)
	if err != nil || l.Status != "open" || l.ResolutionNote != "" {
		t.Errorf("undismiss: %+v %v", l, err)
	}
	// Only a dismissed leak can be opened by hand.
	if _, err := s.UndismissLeak(ctx, ls[0].ID); err == nil {
		t.Error("undismissed an open leak")
	}

	// A batch without a scan (an older agent) keeps what was reported.
	b := batch(mid, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Name = "web-1"
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if got := leakState(t, s, ctx, id); got["/srv/app/.env"] != "open/" || got["/srv/app/config.php"] != "open/" {
		t.Errorf("after a batch without a scan: %v", got)
	}
}

// The value has nowhere to go: the table has no column that could hold
// more than the masked preview and a fingerprint of fixed form.
func TestLeakStoresNoValue(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("a", "/srv/app/.env", "critical")), 0); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(tenant.System(context.Background()), `SELECT column_name FROM information_schema.columns
		WHERE table_name = 'leaks' AND table_schema = current_schema() ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		cols = append(cols, c)
	}
	want := "id workspace_id asset_id collector_id fingerprint path line rule title name preview severity exposure status resolution " +
		"resolution_note resolved_by first_seen last_seen resolved_at last_collection_id " +
		// 0101: the rotation workflow. Its only text is a person's note.
		"assignee_user_id assignee_team_id due_at rotated_at rotated_by rotation_note"
	if strings.Join(cols, " ") != want {
		t.Errorf("leaks has columns %v; a new one must not hold the value", cols)
	}
	// A fingerprint that is not 32 hex characters is refused by the
	// database too, so a raw key cannot be stored in its place.
	if _, err := pool.Exec(tenant.System(context.Background()), `UPDATE leaks SET fingerprint = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'`); err == nil {
		t.Error("a raw value was stored as the fingerprint")
	}
}

func TestLeakIsolation(t *testing.T) {
	bg := context.Background()
	s := store.New(testdb.New(t))
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	wsB, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)

	r1, err := s.Ingest(a, leakBatch("web-1", mid, true, leak("a", "/srv/one/.env", "critical")), 0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.Ingest(a, leakBatch("web-2", []model.Identifier{{Scheme: "machine-id", Value: "m2"}}, true, leak("b", "/srv/two/.env", "high")), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Another organisation sees none of them and cannot dismiss them.
	if ls, n, err := s.ListLeaks(b, store.LeakFilter{Status: "all"}); err != nil || n != 0 || len(ls) != 0 {
		t.Errorf("B sees %v (%d) %v", ls, n, err)
	}
	all, _, _ := s.ListLeaks(a, store.LeakFilter{})
	if len(all) != 2 {
		t.Fatalf("A sees %d leaks", len(all))
	}
	if _, err := s.DismissLeak(b, all[0].ID, nil, ""); err == nil {
		t.Error("B dismissed A's leak")
	}
	if ls, _ := s.LeakScans(b, r1.AssetID); len(ls) != 0 {
		t.Errorf("B sees A's scans: %+v", ls)
	}
	// A project member sees only the project's assets' leaks.
	p, err := s.CreateProject(a, "one", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(a, p.ID, []int64{r1.AssetID}); err != nil {
		t.Fatal(err)
	}
	narrowed := tenant.WithProject(a, p.ID)
	ls, n, err := s.ListLeaks(narrowed, store.LeakFilter{})
	if err != nil || n != 1 || ls[0].AssetID != r1.AssetID {
		t.Errorf("narrowed sees %+v (%d) %v", ls, n, err)
	}
	var other int64
	for _, l := range all {
		if l.AssetID == r2.AssetID {
			other = l.ID
		}
	}
	if _, err := s.GetLeak(narrowed, other); err == nil {
		t.Error("narrowed read another project's leak")
	}
	if _, err := s.DismissLeak(narrowed, other, nil, ""); err == nil {
		t.Error("narrowed dismissed another project's leak")
	}
}

func TestLeakIncidents(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	sync := func() []store.Incident {
		t.Helper()
		sys, err := s.DetectSystemProblems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SyncSystemIncidents(ctx, sys); err != nil {
			t.Fatal(err)
		}
		incs, _, err := s.ListIncidents(ctx, store.IncidentFilter{Kind: "leak"})
		if err != nil {
			t.Fatal(err)
		}
		return incs
	}
	// Low and medium leaks are listed, never alerted on.
	r, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("a", "/srv/app/.env", "low"), leak("b", "/srv/app/x.js", "medium")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if incs := sync(); len(incs) != 0 {
		t.Errorf("low and medium leaks raised %+v", incs)
	}
	// A high one raises a P2 incident on the asset; a critical one makes it P1.
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("c", "/srv/app/deploy.sh", "high")), 0); err != nil {
		t.Fatal(err)
	}
	incs := sync()
	if len(incs) != 1 || incs[0].Priority != "P2" || incs[0].Key != "asset:"+itoa64(r.AssetID) || !strings.Contains(incs[0].Title, "GitHub token") {
		t.Fatalf("high leak: %+v", incs)
	}
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("c", "/srv/app/deploy.sh", "high"), leak("d", "/srv/app/public/.env", "critical")), 0); err != nil {
		t.Fatal(err)
	}
	if incs = sync(); len(incs) != 1 || incs[0].Priority != "P1" || !strings.Contains(incs[0].Title, "2 leaked keys") {
		t.Fatalf("critical leak: %+v", incs)
	}
	// Gone from a complete scan: the incident is resolved.
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, true), 0); err != nil {
		t.Fatal(err)
	}
	if incs = sync(); len(incs) != 0 {
		t.Errorf("open after the leaks went: %+v", incs)
	}
	all, _, _ := s.ListIncidents(ctx, store.IncidentFilter{Kind: "leak", Status: "all"})
	if len(all) != 1 || all[0].Status != "resolved" {
		t.Errorf("resolved incident: %+v", all)
	}
}

// Every surface takes a leak's reason from LeakWhy.
func TestLeakWhy(t *testing.T) {
	for _, tc := range []struct{ kind, exposure, severity, want string }{
		{"application", "served", "critical", "The web server may send this file"},
		{"host", "served", "critical", "The web server may send this file"},
		{"repository", "", "high", "Committed to the repository"},
		{"repository", "", "low", "Committed to the repository"},
		{"image", "", "high", "Built into the container image"},
		{"application", "world_readable", "medium", "every account on this server can read"},
		// A live key written into a PHP file is 644 like every web file:
		// the advice is to move it out of the code, not to chmod a config.
		{"application", "world_readable", "critical", "Written into the application's code"},
		{"application", "", "low", "Kept in the application's configuration file"},
		{"host", "", "critical", "Written into the application's code"},
		{"application", "", "high", "Written into the application's code"},
	} {
		if got := store.LeakWhy(tc.kind, tc.exposure, tc.severity); !strings.HasPrefix(got, tc.want) && !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q", tc, got)
		}
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	served := leak("a", "/var/www/html/.env", "critical")
	served.Exposure = model.ExposureServed
	r, err := s.Ingest(ctx, leakBatch("web-1", mid, true, served, leak("b", "/srv/app/.env", "low")), 0)
	if err != nil {
		t.Fatal(err)
	}
	ls, _, err := s.ListLeaks(ctx, store.LeakFilter{AssetID: r.AssetID, Severity: "critical,high"})
	if err != nil || len(ls) != 1 || !strings.HasPrefix(ls[0].Why, "The web server may send") {
		t.Fatalf("critical,high: %+v %v", ls, err)
	}
	if one, err := s.GetLeak(ctx, ls[0].ID); err != nil || one.Why != ls[0].Why {
		t.Errorf("get: %+v %v", one, err)
	}
	sys, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sys {
		if p.Kind == "leak" && p.Detail["why"] != ls[0].Why {
			t.Errorf("incident why: %v", p.Detail["why"])
		}
	}
}

// The rotation workflow: a leak needs rotation, is assigned, marked
// rotated, still found by a scan that sees it, and verified gone by a
// complete scan that no longer does.
func TestLeakWorkflow(t *testing.T) {
	bg := context.Background()
	ctx := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	ravi, err := s.CreateUser(ctx, "ravi@example.com", "Ravi", "engineer", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	web, err := s.CreateTeam(ctx, "Web", "")
	if err != nil {
		t.Fatal(err)
	}

	// Seen three days ago: the critical one (1 day) is overdue, the high one
	// (7 days) is not, the low one has no deadline.
	b := leakBatch("web-1", mid, true, leak("a", "/srv/app/deploy.js", "critical"), leak("b", "/srv/app/db.js", "high"),
		leak("c", "/srv/app/.env", "low"))
	b.ObservedAt = time.Now().UTC().Add(-72 * time.Hour)
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	byPath := func() map[string]store.Leak {
		t.Helper()
		ls, _, err := s.ListLeaks(ctx, store.LeakFilter{AssetID: r.AssetID, Status: "all"})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]store.Leak{}
		for _, l := range ls {
			m[l.Path] = l
		}
		return m
	}
	ls := byPath()
	crit, high, low := ls["/srv/app/deploy.js"], ls["/srv/app/db.js"], ls["/srv/app/.env"]
	if crit.DueAt == nil || crit.DueAt.Sub(b.ObservedAt).Round(time.Hour) != 24*time.Hour || !crit.Overdue || crit.State != store.LeakNeedsRotation {
		t.Errorf("critical: due %v overdue %v state %s", crit.DueAt, crit.Overdue, crit.State)
	}
	if high.DueAt == nil || high.DueAt.Sub(b.ObservedAt).Round(time.Hour) != 7*24*time.Hour || high.Overdue {
		t.Errorf("high: due %v overdue %v", high.DueAt, high.Overdue)
	}
	if low.DueAt != nil || low.Overdue {
		t.Errorf("low: due %v overdue %v", low.DueAt, low.Overdue)
	}
	if got, _, err := s.ListLeaks(ctx, store.LeakFilter{State: "overdue"}); err != nil || len(got) != 1 || got[0].ID != crit.ID {
		t.Errorf("overdue filter: %+v %v", got, err)
	}
	if _, _, err := s.ListLeaks(ctx, store.LeakFilter{State: "urgent"}); err == nil {
		t.Error("unknown state accepted")
	}

	// Assign: a person and a team; 0 clears; unknown ids are refused.
	uid, tid, zero := ravi.ID, web.ID, int64(0)
	l, err := s.AssignLeak(ctx, crit.ID, &uid, &tid)
	if err != nil || l.AssigneeEmail != "ravi@example.com" || l.AssigneeTeam != "Web" {
		t.Fatalf("assign: %+v %v", l, err)
	}
	if got, _, _ := s.ListLeaks(ctx, store.LeakFilter{AssigneeUser: uid}); len(got) != 1 || got[0].ID != crit.ID {
		t.Errorf("owner filter: %+v", got)
	}
	if l, err = s.AssignLeak(ctx, crit.ID, nil, &zero); err != nil || l.AssigneeTeamID != nil || l.AssigneeUserID == nil {
		t.Errorf("clear team: %+v %v", l, err)
	}
	bad := int64(999999)
	if _, err := s.AssignLeak(ctx, crit.ID, &bad, nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := s.AssignLeak(ctx, crit.ID, nil, nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("nobody: %v", err)
	}

	// Rotated: waiting for a check, no longer overdue.
	if l, err = s.MarkLeakRotated(ctx, crit.ID, &uid, "revoked in GitHub, new token in the vault"); err != nil ||
		l.State != store.LeakWaitingCheck || l.Overdue || l.RotatedByName != "Ravi" || l.Status != "open" {
		t.Fatalf("rotated: %+v %v", l, err)
	}
	sum, err := s.SummariseLeaks(ctx, store.LeakFilter{Severity: "critical,high"})
	if err != nil || sum.NeedsRotation != 1 || sum.WaitingCheck != 1 || sum.Overdue != 0 || sum.StillFound != 0 || sum.Unassigned != 1 {
		t.Errorf("summary after rotation: %+v %v", sum, err)
	}

	// A scan after the rotation that still sees the key: still found, and
	// overdue again.
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, false, leak("a", "/srv/app/deploy.js", "critical")), 0); err != nil {
		t.Fatal(err)
	}
	if l := byPath()["/srv/app/deploy.js"]; l.State != store.LeakStillFound || !l.Overdue {
		t.Errorf("seen after rotation: %s overdue %v", l.State, l.Overdue)
	}
	if sum, _ = s.SummariseLeaks(ctx, store.LeakFilter{}); sum.StillFound != 1 {
		t.Errorf("summary still found: %+v", sum)
	}

	// Rotated again, then a complete scan without it: verified gone.
	if _, err := s.MarkLeakRotated(ctx, crit.ID, &uid, "removed from the file too"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := s.Ingest(ctx, leakBatch("web-1", mid, true, leak("b", "/srv/app/db.js", "high"), leak("c", "/srv/app/.env", "low")), 0); err != nil {
		t.Fatal(err)
	}
	gone := byPath()["/srv/app/deploy.js"]
	l = &gone
	if l.State != store.LeakVerifiedGone || l.Overdue || l.RotationNote != "removed from the file too" {
		t.Errorf("after a complete scan: %+v", l)
	}
	if sum, _ = s.SummariseLeaks(ctx, store.LeakFilter{}); sum.VerifiedGone30 != 1 || sum.NeedsRotation != 2 {
		t.Errorf("summary verified gone: %+v", sum)
	}
	if _, err := s.MarkLeakRotated(ctx, crit.ID, &uid, ""); !errors.Is(err, store.ErrConflict) {
		t.Errorf("rotated a resolved leak: %v", err)
	}
	if _, err := s.MarkLeakRotated(ctx, 999999, &uid, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("rotated an unknown leak: %v", err)
	}

	// Another organisation can neither assign nor rotate it.
	wsB, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	other := tenant.WithWorkspace(bg, wsB.ID)
	if _, err := s.AssignLeak(other, high.ID, nil, &zero); err == nil {
		t.Error("B assigned A's leak")
	}
	if _, err := s.MarkLeakRotated(other, high.ID, nil, ""); err == nil {
		t.Error("B rotated A's leak")
	}
	// And A cannot assign A's leak to B's people.
	bUser, err := s.CreateUser(other, "b-eng@x.io", "", "engineer", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignLeak(ctx, high.ID, &bUser.ID, nil); err == nil {
		t.Error("A assigned a leak to B's user")
	}
}

func TestLeakDueDays(t *testing.T) {
	def := risk.DefaultPolicy()
	if got := store.LeakDueDays(def); got["critical"] != 1 || got["high"] != 7 || got["medium"] != 30 || got["low"] != 0 {
		t.Errorf("defaults: %v", got)
	}
	p := risk.DefaultPolicy()
	p.SLA = map[string]risk.SLA{"P1": {FixDays: 2}, "P2": {FixDays: 10}, "P3": {FixDays: 40}, "P4": {FixDays: 90}}
	if got := store.LeakDueDays(p); got["critical"] != 2 || got["high"] != 10 || got["medium"] != 40 || got["low"] != 0 {
		t.Errorf("custom: %v", got)
	}
}
