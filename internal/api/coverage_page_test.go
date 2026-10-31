package api_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestCoveragePage: the headline's segments add up to the total and each
// segment's link (GET /components?segment=) lists exactly its count; the
// asset table and support requests work over HTTP, and the requests are
// counted on the instance-wide coverage-gap report.
func TestCoveragePage(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	e.instanceAdmin("owner@x.io")
	owner, viewer := e.login("owner@x.io"), e.login("viewer@x.io")
	bg := context.Background()
	sys := tenant.System(bg)
	ws := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)

	// An empty workspace: every section has its empty answer.
	var ov store.CoverageOverview
	if code := viewer.do("GET", "/api/v1/coverage/overview", nil, &ov); code != 200 || ov.Total != 0 || len(ov.Segments) != 5 || ov.Ecosystems == nil {
		t.Fatalf("empty overview: %d %+v", code, ov)
	}
	var al store.AssetCoverageList
	if code := viewer.do("GET", "/api/v1/coverage/assets", nil, &al); code != 200 || al.Total != 0 || al.Items == nil || len(al.Groups) != 5 {
		t.Fatalf("empty assets: %d %+v", code, al)
	}

	if err := e.st.EnsureFeed(sys, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(sys, `UPDATE feeds SET last_success = now(), ecosystems = '{Debian:12}' WHERE name = 'osv:Debian'`); err != nil {
		t.Fatal(err)
	}
	ingest := func(kind model.AssetKind, name string, obs ...string) {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "t-" + name, Method: "test"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
		for _, p := range obs {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Location: "x", Confidence: model.ConfidenceConfirmed})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.Ingest(ws, b, 0); err != nil {
			t.Fatal(err)
		}
	}
	ingest(model.AssetRepository, "web", "pkg:npm/left-pad", "pkg:npm/express@4.0.0", "pkg:cocoapods/Alamofire@5.0.0")
	ingest(model.AssetHost, "db", "pkg:deb/debian/openssl@3.0.0?distro=debian-14", "pkg:deb/debian/curl@7.88.1?distro=debian-12")
	ev := &intel.Evaluator{Store: e.st, Now: time.Now}
	if _, err := ev.Evaluate(ws, nil, 0); err != nil {
		t.Fatal(err)
	}

	if code := viewer.do("GET", "/api/v1/coverage/overview", nil, &ov); code != 200 {
		t.Fatalf("overview: %d", code)
	}
	var sum int64
	for _, seg := range store.Segments {
		var list struct {
			Items []store.Component `json:"items"`
			Total int64             `json:"total"`
		}
		if code := viewer.do("GET", "/api/v1/components?segment="+seg, nil, &list); code != 200 {
			t.Fatalf("components?segment=%s: %d", seg, code)
		}
		if list.Total != ov.Segments[seg] || int64(len(list.Items)) != list.Total {
			t.Errorf("segment %s: list %d (%d items), headline %d", seg, list.Total, len(list.Items), ov.Segments[seg])
		}
		sum += ov.Segments[seg]
	}
	if ov.Total != 5 || sum != ov.Total {
		t.Errorf("total %d, segments %v", ov.Total, ov.Segments)
	}
	want := map[string]int64{"checked": 1, "needs_you": 1, "waiting": 1, "not_supported": 1, "no_advisories": 1}
	if fmt.Sprint(ov.Segments) != fmt.Sprint(want) {
		t.Errorf("segments %v, want %v", ov.Segments, want)
	}
	if code := viewer.do("GET", "/api/v1/components?segment=nope", nil, nil); code != 400 {
		t.Errorf("bad segment: %d", code)
	}

	if code := viewer.do("GET", "/api/v1/coverage/assets", nil, &al); code != 200 || al.Total != 2 {
		t.Fatalf("assets: %d %+v", code, al)
	}
	if code := viewer.do("GET", "/api/v1/coverage/assets?group=nope", nil, nil); code != 400 {
		t.Errorf("bad group: %d", code)
	}

	// Support requests: viewers may ask, once per ecosystem.
	var resp map[string]any
	if code := viewer.do("POST", "/api/v1/coverage/support-requests", map[string]string{"ecosystem": "cocoapods"}, &resp); code != 200 || resp["label"] != "CocoaPods" {
		t.Fatalf("request: %d %v", code, resp)
	}
	if code := owner.do("POST", "/api/v1/coverage/support-requests", map[string]string{"ecosystem": "cocoapods"}, nil); code != 200 {
		t.Errorf("asking again: %d", code)
	}
	for _, bad := range []string{"npm", "", "nothing-here"} {
		if code := viewer.do("POST", "/api/v1/coverage/support-requests", map[string]string{"ecosystem": bad}, nil); code != 400 {
			t.Errorf("%q: %d", bad, code)
		}
	}
	var audits int
	if err := e.st.Pool.QueryRow(sys, `SELECT count(*) FROM audit_events WHERE action = 'coverage.support_request'`).Scan(&audits); err != nil || audits != 1 {
		t.Errorf("audited %d times (%v)", audits, err)
	}
	if code := viewer.do("GET", "/api/v1/coverage/overview", nil, &ov); code != 200 {
		t.Fatal(code)
	}
	for _, x := range ov.Ecosystems {
		if x.Requested != (x.Key == "cocoapods") {
			t.Errorf("%s requested %v", x.Key, x.Requested)
		}
	}

	var rep struct {
		SupportRequests []store.SupportRequestTotal `json:"support_requests"`
	}
	if code := owner.do("GET", "/api/v1/admin/coverage-gaps", nil, &rep); code != 200 {
		t.Fatalf("coverage gaps: %d", code)
	}
	if len(rep.SupportRequests) != 1 || rep.SupportRequests[0].Ecosystem != "cocoapods" || rep.SupportRequests[0].Workspaces != 1 {
		t.Errorf("support requests on the report: %+v", rep.SupportRequests)
	}
	if code := viewer.do("GET", "/api/v1/admin/coverage-gaps", nil, nil); code != 403 {
		t.Errorf("workspace viewer reads the report: %d", code)
	}
}
