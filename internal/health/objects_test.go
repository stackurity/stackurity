package health

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Problems with workspaces' own objects carry the last success, the latest
// error, the scope and a next step; they count every workspace but name
// objects only in the viewer's workspace, and never become platform incidents.
func TestObjectProblems(t *testing.T) {
	st := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(sys, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO workspaces (id, name, slug) VALUES (2, 'Other', 'other')`)
	// Feeds synced, so only the problems below show.
	exec(`INSERT INTO feeds (name, kind, last_attempt, last_success) VALUES ('osv:npm', 'vulnerability', now(), now())`)

	host := func(ws int64, name, env string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "agent", Version: "1", Method: "agent"},
			model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
		b.Observations = []model.Observation{{Purl: "pkg:generic/odd-thing@1.0", Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := st.Ingest(tenant.WithWorkspace(context.Background(), ws), b, 0)
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE assets SET environment = $2 WHERE id = $1`, r.AssetID, env)
		return r.AssetID
	}
	mine := host(1, "prod-web-mine", "production")
	theirs := host(2, "prod-db-theirs", "prod")
	host(1, "dev-box-mine", "dev")
	// Workspace 2 treats "prod" as production only through the default list;
	// workspace 1 renamed production, so "production" no longer counts there.
	exec(`INSERT INTO settings (workspace_id, key, value) VALUES (1, 'risk_policy', '{"production_environments": ["production", "live"]}')`)

	exec(`UPDATE assets SET collection_status = 'stale', last_seen = now() - interval '3 days'`)
	exec(`INSERT INTO coverage (workspace_id, asset_id, collector_id, scope, status, reason, last_attempt, last_success)
		SELECT workspace_id, id, 'agent', 'os-packages', 'failed', 'dpkg not readable', now(), now() - interval '1 day' FROM assets WHERE id IN ($1, $2)`, mine, theirs)
	exec(`UPDATE inventory SET coverage = 'unsupported', coverage_reason = 'no vulnerability source for generic', evaluated_at = now()`)
	exec(`INSERT INTO integrations (workspace_id, kind, name, schedule, last_attempt, last_success, last_error, created_at) VALUES
		(1, 'git_repository', 'repo-mine', '1 hour', now(), now() - interval '90 minutes', 'authentication failed', now() - interval '1 day'),
		(2, 'git_repository', 'repo-theirs', '1 hour', now(), NULL, 'theirs: secret path', now() - interval '1 day'),
		(1, 'git_repository', 'repo-ok', '1 hour', now(), now(), '', now() - interval '1 day')`)
	exec(`INSERT INTO channels (workspace_id, kind, name, last_ok_at) VALUES (1, 'webhook', 'hook-mine', now() - interval '2 days'),
		(2, 'webhook', 'hook-theirs', NULL)`)
	exec(`INSERT INTO routes (workspace_id, name, channel_id) SELECT workspace_id, 'route-' || name, id FROM channels`)
	exec(`INSERT INTO deliveries (workspace_id, channel_id, route_id, event, dedupe_key, payload, status, attempts, last_error)
		SELECT c.workspace_id, c.id, r.id, 'opened', 'k1', '{}', 'failed', 8, 'HTTP 500 from ' || c.name
		FROM channels c JOIN routes r ON r.channel_id = c.id`)
	exec(`INSERT INTO jobs (workspace_id, kind, payload, attempts, last_error, run_at) VALUES (1, 'evaluate', '{}', 3, 'deadlock detected', now() + interval '5 minutes')`)

	c := &Checker{Store: st, FeedsEnabled: true}
	r, err := c.CheckFor(sys, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "theirs") {
		t.Errorf("workspace 1's report names workspace 2's objects: %s", raw)
	}
	type want struct {
		count, hidden int64
		items         int
		item, err     string
	}
	for k, w := range map[[2]string]want{
		{"integration", "failing"}:            {count: 2, hidden: 1, items: 1, item: "repo-mine", err: "authentication failed"},
		{"notification", "delivery"}:          {count: 2, hidden: 1, items: 1, item: "hook-mine", err: "HTTP 500 from hook-mine"},
		{"collector", "silent"}:               {count: 3, hidden: 1, items: 2, item: "prod-web-mine"},
		{"coverage", "production-collection"}: {count: 2, hidden: 1, items: 1, item: "prod-web-mine", err: "dpkg not readable"},
		{"coverage", "production-evaluation"}: {count: 2, hidden: 1, items: 1, item: "prod-web-mine", err: "no vulnerability source for generic"},
		{"jobs", "evaluate"}:                  {count: 1},
	} {
		p := find(r, k[0], k[1])
		if p == nil {
			t.Errorf("%v: missing in %+v", k, r.Problems)
			continue
		}
		if p.Scope.Count != w.count || p.Scope.Hidden != w.hidden || len(p.Scope.Items) != w.items || p.NextStep == "" || p.Docs == "" || p.Scope.Summary == "" {
			t.Errorf("%v: %+v", k, p)
		}
		if w.items > 0 && (p.Scope.Items[0].Name != w.item || p.Scope.Items[0].Link == "") {
			t.Errorf("%v: first item %+v, want %s", k, p.Scope.Items[0], w.item)
		}
		if w.err != "" && p.LastError != w.err {
			t.Errorf("%v: last error %q, want %q", k, p.LastError, w.err)
		}
	}
	if p := find(r, "jobs", "evaluate"); p != nil && (p.LastError != "deadlock detected" || !strings.Contains(p.Title, "retried")) {
		t.Errorf("retried jobs: %+v", p)
	}
	if p := find(r, "integration", "failing"); p != nil && (p.LastSuccess == nil || !strings.Contains(p.Title, "1 of them")) {
		t.Errorf("integration: %+v", p)
	}
	if p := find(r, "collector", "silent"); p != nil && !strings.Contains(p.Title, "2 of them production") {
		t.Errorf("silent collectors: production count wrong: %s", p.Title)
	}

	// Without a viewer workspace nothing is named and no error is shown.
	anon, err := c.Check(sys)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(anon)
	for _, s := range []string{"mine", "theirs", "authentication failed", "HTTP 500"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("report without a viewer contains %q", s)
		}
	}
	// Workspace 2's view names its own objects only.
	r2, err := c.CheckFor(sys, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(r2)
	if strings.Contains(string(raw), "-mine") || !strings.Contains(string(raw), "repo-theirs") {
		t.Errorf("workspace 2's report: %s", raw)
	}
	// None of these become platform incidents.
	if incs, err := c.PlatformIncidents(sys); err != nil || len(incs) != 0 {
		t.Errorf("platform incidents: %+v %v", incs, err)
	}
}
