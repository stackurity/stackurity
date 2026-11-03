package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Leaked keys over the API: anyone who sees the asset reads them; only the
// security role dismisses one, on the asset when the role comes from a
// project grant.
func TestLeaksAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)

	var meta struct{ Features []string }
	if code := admin.do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureLeaks) {
		t.Errorf("meta features: %d %v", code, meta.Features)
	}

	send := func(name string, l model.Leak) store.IngestResult {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		b.Leaks = &model.LeakScan{Found: []model.Leak{l}, Complete: true}
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+collector)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		if resp.StatusCode != 201 || json.NewDecoder(resp.Body).Decode(&res) != nil {
			t.Fatalf("ingest %s: %d", name, resp.StatusCode)
		}
		return res
	}
	var before struct {
		ScannedAssets int64 `json:"scanned_assets"`
	}
	if code := admin.do("GET", "/api/v1/leaks", nil, &before); code != 200 || before.ScannedAssets != 0 {
		t.Errorf("scanned assets before any scan: %d %+v", code, before)
	}
	served := model.Leak{Rule: "password-assignment", Title: "Password or key in configuration", Severity: "critical",
		Path: "/var/www/html/.env", Line: 4, Name: "DB_PASSWORD", Fingerprint: strings.Repeat("1f", 16), Exposure: model.ExposureServed}
	one := send("web-1", served)
	two := send("web-2", model.Leak{Rule: "stripe-live-key", Title: "Stripe live secret key", Severity: "critical",
		Path: "/srv/shop/billing.py", Line: 9, Fingerprint: strings.Repeat("2e", 16), Preview: "sk_live_…9xQa"})
	if one.LeaksFound != 1 {
		t.Errorf("ingest result: %+v", one)
	}

	type leaks struct {
		Items         []store.Leak
		Total         int64
		Scans         []store.LeakScan
		ScannedAssets int64 `json:"scanned_assets"`
	}
	var all leaks
	if code := admin.do("GET", "/api/v1/leaks?severity=critical", nil, &all); code != 200 || all.Total != 2 || all.ScannedAssets != 2 {
		t.Fatalf("list: %d %+v", code, all)
	}
	var mine leaks
	if code := admin.do("GET", fmt.Sprintf("/api/v1/assets/%d/leaks", one.AssetID), nil, &mine); code != 200 || len(mine.Items) != 1 ||
		mine.Items[0].Exposure != "served" || !strings.HasPrefix(mine.Items[0].Why, "The web server may send") || len(mine.Scans) != 1 ||
		!mine.Scans[0].Complete {
		t.Fatalf("asset leaks: %d %+v", code, mine)
	}
	if code := admin.do("GET", "/api/v1/leaks?severity=urgent", nil, nil); code != 400 {
		t.Errorf("bad severity: %d", code)
	}
	if code := admin.do("GET", "/api/v1/assets/999999/leaks", nil, nil); code != 404 {
		t.Errorf("unknown asset: %d", code)
	}
	leakOn := func(asset int64) int64 {
		for _, l := range all.Items {
			if l.AssetID == asset {
				return l.ID
			}
		}
		t.Fatalf("no leak on %d", asset)
		return 0
	}
	l1, l2 := leakOn(one.AssetID), leakOn(two.AssetID)

	// Organisation roles below security may read, not dismiss.
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleEngineer} {
		email := string(role) + "@x.io"
		e.user(email, role)
		s := e.login(email)
		if code := s.do("GET", "/api/v1/leaks", nil, nil); code != 200 {
			t.Errorf("%s list: %d", role, code)
		}
		if code := s.do("POST", fmt.Sprintf("/api/v1/leaks/%d/dismiss", l1), map[string]string{"note": "x"}, nil); code != 403 {
			t.Errorf("%s dismissed: %d", role, code)
		}
	}

	// Security role from a grant on web-1's project: web-1's leak only.
	p, err := e.st.CreateProject(ctx, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddProjectAssets(ctx, p.ID, []int64{one.AssetID}); err != nil {
		t.Fatal(err)
	}
	if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": "proj-sec@x.io", "password": pw, "project_id": p.ID,
		"role": auth.RoleSecurity}, nil); code != 201 {
		t.Fatalf("grant: %d", code)
	}
	member := e.signIn("proj-sec@x.io")
	var seen leaks
	if code := member.do("GET", "/api/v1/leaks", nil, &seen); code != 200 || seen.Total != 1 || seen.Items[0].ID != l1 || seen.ScannedAssets != 1 {
		t.Errorf("member list: %d %+v", code, seen)
	}
	if code := member.do("GET", fmt.Sprintf("/api/v1/assets/%d/leaks", two.AssetID), nil, nil); code != 404 {
		t.Errorf("member read another project's asset: %d", code)
	}
	if code := member.do("POST", fmt.Sprintf("/api/v1/leaks/%d/dismiss", l2), nil, nil); code != 404 {
		t.Errorf("member dismissed another project's leak: %d", code)
	}
	var got store.Leak
	if code := member.do("POST", fmt.Sprintf("/api/v1/leaks/%d/dismiss", l1), map[string]string{"note": "rotated 2 Nov"}, &got); code != 200 ||
		got.Resolution != "dismissed" || got.ResolutionNote != "rotated 2 Nov" || got.ResolvedBy == nil {
		t.Errorf("member dismiss: %d %+v", code, got)
	}
	if code := member.do("POST", fmt.Sprintf("/api/v1/leaks/%d/undismiss", l1), nil, &got); code != 200 || got.Status != "open" {
		t.Errorf("member undismiss: %d %+v", code, got)
	}
	if code := member.do("POST", fmt.Sprintf("/api/v1/leaks/%d/undismiss", l1), nil, nil); code != 409 {
		t.Errorf("undismiss an open leak: %d", code)
	}
	audit, _, err := e.st.ListAudit(ctx, "leak", fmt.Sprint(l1), store.Page{Limit: 10})
	if err != nil || len(audit) != 2 {
		t.Errorf("audit: %+v %v", audit, err)
	}
}
