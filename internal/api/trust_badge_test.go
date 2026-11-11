package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

// Names in the seeded estate that must never reach public output.
const (
	tbHost    = "db-prod-7.internal.acme"
	tbPackage = "left-pad"
	tbDeb     = "openssl"
	tbProject = "Payments platform"
)

type tbFixture struct {
	e       *env
	admin   *session
	ctx     context.Context
	assetID int64
	project int64
	badge   int64
}

// newTrustFixture seeds an estate with distinctive names, a project over
// it and a badge (off) covering the project.
func newTrustFixture(t *testing.T, adjust func(*api.Server)) *tbFixture {
	t.Helper()
	e := newEnvWith(t, adjust)
	e.user("admin@x.io", auth.RoleAdmin)
	f := &tbFixture{e: e, admin: e.login("admin@x.io"), ctx: tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)}
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: tbHost, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "tb-1"}}})
	b.Observations = []model.Observation{
		{Purl: "pkg:npm/" + tbPackage + "@1.3.0", Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:deb/debian/" + tbDeb + "@3.0.11", Confidence: model.ConfidenceConfirmed},
	}
	body, _ := json.Marshal(b)
	_, secret, err := e.st.CreateToken(f.ctx, "c", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, secret, "POST", "/api/v1/ingest", body, nil); code != 201 {
		t.Fatalf("ingest: %d", code)
	}
	assets, _, err := e.st.ListAssets(f.ctx, store.AssetFilter{})
	if err != nil || len(assets) != 1 {
		t.Fatalf("assets %v %v", assets, err)
	}
	f.assetID = assets[0].ID
	var proj store.Project
	if code := f.admin.do("POST", "/api/v1/projects", map[string]any{"name": tbProject, "asset_ids": []int64{f.assetID}}, &proj); code != 201 {
		t.Fatalf("project: %d", code)
	}
	f.project = proj.ID
	var badge store.TrustBadge
	if code := f.admin.do("POST", "/api/v1/trust-badges", map[string]any{"slug": "acme", "scope_kind": "projects",
		"project_ids": []int64{f.project}, "display_name": "Acme Ltd", "website_url": "https://acme.example"}, &badge); code != 201 {
		t.Fatalf("create badge: %d", code)
	}
	f.badge = badge.ID
	return f
}

// turnOn accepts the terms and turns the badge on.
func (f *tbFixture) turnOn(t *testing.T) {
	t.Helper()
	if code := f.admin.do("POST", fmt.Sprintf("/api/v1/trust-badges/%d/terms", f.badge),
		map[string]any{"version": api.TrustBadgeTermsVersion, "accepted": true}, nil); code != 200 {
		t.Fatalf("terms: %d", code)
	}
	if code := f.admin.do("POST", fmt.Sprintf("/api/v1/trust-badges/%d/enabled", f.badge), map[string]any{"enabled": true}, nil); code != 200 {
		t.Fatalf("enable: %d", code)
	}
}

// decide appends a decision as the evaluator would, with the badge's real
// inputs (which name the asset, its sources and cursors) and the result
// given, so public output can be checked against rich evidence.
func (f *tbFixture) decide(t *testing.T, result string, at time.Time) {
	t.Helper()
	b, err := f.e.st.TrustBadgeByID(f.ctx, f.badge)
	if err != nil {
		t.Fatal(err)
	}
	in, err := f.e.st.TrustBadgeInputs(f.ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	oldest := at.Add(-30 * time.Minute).UTC().Truncate(time.Second)
	d := trustbadge.Decision{Result: result, Reason: trustbadge.ReasonActive, RuleVersion: trustbadge.RuleVersion, Failed: []string{},
		States: map[string]int64{trustbadge.StateEvaluated: 41, trustbadge.StateUnsupported: 3}, OldestEvaluated: &oldest,
		UnsupportedKinds: []string{"WordPress core", "npm packages from a private registry"}}
	if result != trustbadge.Active {
		d.Reason, d.Failed = trustbadge.ReasonNotReporting, []string{trustbadge.ReasonNotReporting}
	}
	if _, err := f.e.st.AppendTrustBadgeStatus(f.ctx, f.badge, at.UTC().Truncate(time.Microsecond), trustbadge.Evidence{Inputs: in, Decision: d}); err != nil {
		t.Fatal(err)
	}
}

func (f *tbFixture) get(t *testing.T, path string) (int, http.Header, string) {
	t.Helper()
	resp, err := http.Get(f.e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// assertNothingPrivate fails if public output names anything from the
// estate, carries an id or count, or a number of any kind in JSON.
func assertNothingPrivate(t *testing.T, where, out string, f *tbFixture) {
	t.Helper()
	low := strings.ToLower(out)
	for _, bad := range []string{strings.ToLower(tbHost), tbPackage, tbDeb, strings.ToLower(tbProject), "osv:", "cursor",
		"badge_id", "workspace", "asset", `"id"`, `"count"`, "states"} {
		if strings.Contains(low, bad) {
			t.Errorf("%s contains %q: %s", where, bad, out)
		}
	}
	_ = f
}

// jsonHasNumbers reports whether any value in the JSON document is a
// number: the public contract has none (no counts, no ids).
func jsonHasNumbers(v any) bool {
	switch x := v.(type) {
	case float64, json.Number:
		return true
	case map[string]any:
		for _, e := range x {
			if jsonHasNumbers(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if jsonHasNumbers(e) {
				return true
			}
		}
	}
	return false
}

// The public contract: exactly the agreed fields, never a count, id,
// package, host, project or source name, never a switched-off item, and
// not active whenever the last decision is not active, stale or missing.
func TestTrustBadgePublicContract(t *testing.T) {
	f := newTrustFixture(t, nil)

	// Off: no trust data, and the image is the grey "not active" one.
	if code, _, _ := f.get(t, "/api/v1/public/trust/acme"); code != 404 {
		t.Errorf("off badge trust data: %d, want 404", code)
	}
	if code, h, svg := f.get(t, "/badge/acme.svg"); code != 200 || !strings.Contains(svg, "Stackurity badge not active") ||
		h.Get("Content-Type") != "image/svg+xml" {
		t.Errorf("off badge image: %d %s %s", code, h.Get("Content-Type"), svg)
	}

	f.turnOn(t)
	f.decide(t, trustbadge.Active, time.Now())
	code, h, body := f.get(t, "/api/v1/public/trust/acme")
	if code != 200 {
		t.Fatalf("trust data: %d %s", code, body)
	}
	if cc := h.Get("Cache-Control"); cc != "public, max-age=900" {
		t.Errorf("trust data Cache-Control %q", cc)
	}
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"kinds", "last_evaluated_at", "listed", "logo_url", "name", "rule_version", "show_marketing", "slug", "state",
		"unsupported_kinds", "website_url"}
	if !slices.Equal(keys, want) {
		t.Errorf("fields %v, want %v", keys, want)
	}
	if jsonHasNumbers(raw) {
		t.Errorf("trust data carries a number: %s", body)
	}
	assertNothingPrivate(t, "trust data", body, f)
	var tp struct {
		Name             string   `json:"name"`
		State            string   `json:"state"`
		WebsiteURL       *string  `json:"website_url"`
		LogoURL          *string  `json:"logo_url"`
		LastEvaluatedAt  *string  `json:"last_evaluated_at"`
		Kinds            []string `json:"kinds"`
		UnsupportedKinds []string `json:"unsupported_kinds"`
		ShowMarketing    bool     `json:"show_marketing"`
	}
	_ = json.Unmarshal([]byte(body), &tp)
	if tp.State != "active" || tp.Name != "Acme Ltd" || tp.LastEvaluatedAt == nil || tp.WebsiteURL == nil || *tp.WebsiteURL != "https://acme.example" {
		t.Errorf("active trust data %+v", tp)
	}
	// Switched off by default: kinds. The Free plan: no logo, marketing on.
	if tp.Kinds != nil || tp.LogoURL != nil || !tp.ShowMarketing {
		t.Errorf("hidden items shown: %+v", tp)
	}
	if !slices.Equal(tp.UnsupportedKinds, []string{"WordPress core releases", "npm packages from a private registry"}) {
		t.Errorf("unsupported kinds %v", tp.UnsupportedKinds)
	}
	// The badge image: active, with the marketing line, and nothing private.
	code, h, svg := f.get(t, "/badge/acme.svg?time=1")
	if code != 200 || !strings.Contains(svg, "Monitored by Stackurity") || !strings.Contains(svg, "Monitor yours, free") ||
		!strings.Contains(svg, "evaluated ") || h.Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("active image: %d %s %s", code, h.Get("Cache-Control"), svg)
	}
	assertNothingPrivate(t, "badge image", svg, f)
	var listed struct{ Slugs []string }
	if code, _, body := f.get(t, "/api/v1/public/trust?listed=1"); code != 200 || json.Unmarshal([]byte(body), &listed) != nil ||
		!slices.Equal(listed.Slugs, []string{"acme"}) {
		t.Errorf("listed: %d %s", code, body)
	}

	// Kinds switched on: kinds of systems, no names or counts.
	var b store.TrustBadge
	f.admin.do("PUT", fmt.Sprintf("/api/v1/trust-badges/%d", f.badge), map[string]any{"slug": "acme", "scope_kind": "projects",
		"project_ids": []int64{f.project}, "display_name": "Acme Ltd", "website_url": "https://acme.example", "show_kinds": true,
		"show_logo": false, "listed": false}, &b)
	f.decide(t, trustbadge.Active, time.Now())
	_, _, body = f.get(t, "/api/v1/public/trust/acme")
	tp = struct {
		Name             string   `json:"name"`
		State            string   `json:"state"`
		WebsiteURL       *string  `json:"website_url"`
		LogoURL          *string  `json:"logo_url"`
		LastEvaluatedAt  *string  `json:"last_evaluated_at"`
		Kinds            []string `json:"kinds"`
		UnsupportedKinds []string `json:"unsupported_kinds"`
		ShowMarketing    bool     `json:"show_marketing"`
	}{}
	_ = json.Unmarshal([]byte(body), &tp)
	if !slices.Equal(tp.Kinds, []string{"servers"}) || tp.WebsiteURL != nil {
		t.Errorf("kinds on, link off: %s", body)
	}
	assertNothingPrivate(t, "trust data with kinds", body, f)
	if _, _, body := f.get(t, "/api/v1/public/trust?listed=1"); strings.Contains(body, "acme") {
		t.Errorf("unlisted badge in the listing: %s", body)
	}

	// Not active: no evaluation time or kinds, the grey image.
	f.decide(t, trustbadge.NotActive, time.Now())
	_, _, body = f.get(t, "/api/v1/public/trust/acme")
	if !strings.Contains(body, `"state":"not_active"`) || !strings.Contains(body, `"last_evaluated_at":null`) || !strings.Contains(body, `"kinds":null`) {
		t.Errorf("not active trust data: %s", body)
	}
	if _, h, svg := f.get(t, "/badge/acme.svg"); !strings.Contains(svg, "not active") || strings.Contains(svg, "Monitor yours") ||
		h.Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("not active image: %s %s", h.Get("Cache-Control"), svg)
	}

	// A decision older than two hours is not trusted.
	f.decide(t, trustbadge.Active, time.Now().Add(-3*time.Hour))
	if _, _, body := f.get(t, "/api/v1/public/trust/acme"); !strings.Contains(body, `"state":"not_active"`) {
		t.Errorf("stale decision shown as active: %s", body)
	}

	// Turning it off takes effect at origin at once.
	f.decide(t, trustbadge.Active, time.Now())
	if code := f.admin.do("POST", fmt.Sprintf("/api/v1/trust-badges/%d/enabled", f.badge), map[string]any{"enabled": false}, nil); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code, _, _ := f.get(t, "/api/v1/public/trust/acme"); code != 404 {
		t.Errorf("turned-off badge trust data: %d", code)
	}
	if _, _, svg := f.get(t, "/badge/acme.svg"); !strings.Contains(svg, "not active") {
		t.Errorf("turned-off badge image: %s", svg)
	}
	// Unknown slugs and other files.
	if code, _, svg := f.get(t, "/badge/nobody-here.svg"); code != 200 || !strings.Contains(svg, "not active") {
		t.Errorf("unknown badge image: %d", code)
	}
	if code, _, _ := f.get(t, "/badge/acme.png"); code != 404 {
		t.Errorf("non-svg badge: %d", code)
	}
	if code, _, _ := f.get(t, "/api/v1/public/trust/nobody-here"); code != 404 {
		t.Errorf("unknown trust data: %d", code)
	}
}

// The image says only what the badge may say: no banned words, no verdict
// colours, the alt text, brand blue or grey.
func TestTrustBadgeImageWording(t *testing.T) {
	now := time.Date(2026, 11, 11, 9, 5, 0, 0, time.UTC)
	for _, c := range []struct {
		active, marketing bool
		when              *time.Time
		dark              bool
	}{{true, true, &now, false}, {true, false, nil, true}, {true, true, nil, false}, {false, false, nil, false}, {false, true, &now, true}} {
		svg := api.TrustBadgeImage(c.active, c.marketing, c.when, c.dark)
		low := strings.ToLower(svg)
		for _, banned := range []string{"secure", "protected", "certified ", "verified", "guaranteed", "safe"} {
			if strings.Contains(low, banned) {
				t.Errorf("%+v: image contains %q", c, banned)
			}
		}
		// Only brand blue, grey and the neutral background and text colours.
		allowed := map[string]bool{"#ffffff": true, "#1f2937": true, "#4b5563": true, "#d6dbe6": true, "#2952cc": true, "#111827": true,
			"#f3f4f6": true, "#c7cdd8": true, "#374151": true, "#3f63d4": true, "#8a8f98": true}
		for _, col := range regexp.MustCompile(`#[0-9a-f]{6}`).FindAllString(low, -1) {
			if !allowed[col] {
				t.Errorf("%+v: colour %s", c, col)
			}
		}
		if !strings.Contains(svg, `height="44"`) || !strings.Contains(svg, "<title>") {
			t.Errorf("%+v: size or title missing: %s", c, svg)
		}
		if c.active {
			if !strings.Contains(svg, "Monitored by Stackurity. Not a security certification.") || strings.Contains(svg, "#8a8f98") {
				t.Errorf("active image: %s", svg)
			}
			if strings.Contains(svg, "Monitor yours, free") != c.marketing {
				t.Errorf("marketing line %v: %s", c.marketing, svg)
			}
			if c.when != nil && !strings.Contains(svg, "evaluated 11 Nov 2026, 09:05 UTC") {
				t.Errorf("evaluation time: %s", svg)
			}
		} else if !strings.Contains(svg, "Stackurity badge not active") || strings.Contains(svg, "Monitor yours") || strings.Contains(svg, "evaluated") {
			t.Errorf("not active image: %s", svg)
		}
	}
}

// Free plan limits hold on the server whatever the request asks; a paid
// plan (set by the licensed Cloud build) lifts them.
func TestTrustBadgePlans(t *testing.T) {
	defer api.SetTrustBadgePlan(nil)()
	f := newTrustFixture(t, nil)
	path := fmt.Sprintf("/api/v1/trust-badges/%d", f.badge)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
	upload := func(data []byte) int {
		resp := f.admin.req("PUT", path+"/logo", bytes.NewReader(data), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/octet-stream"})
		resp.Body.Close()
		return resp.StatusCode
	}

	// Free: one badge, the marketing line always on, no logo.
	if code := f.admin.do("POST", "/api/v1/trust-badges", map[string]any{"slug": "second", "scope_kind": "projects", "project_ids": []int64{f.project}}, nil); code != 402 {
		t.Errorf("second badge on Free: %d, want 402", code)
	}
	var b store.TrustBadge
	f.admin.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{f.project}, "show_marketing": false}, &b)
	if !b.ShowMarketing {
		t.Error("Free plan switched the marketing line off")
	}
	if code := upload(png); code != 402 {
		t.Errorf("logo on Free: %d, want 402", code)
	}
	var list struct {
		Plan api.TrustBadgePlan `json:"plan"`
	}
	f.admin.do("GET", "/api/v1/trust-badges", nil, &list)
	if list.Plan != (api.TrustBadgePlan{MaxBadges: 1}) {
		t.Errorf("Free plan %+v", list.Plan)
	}

	// Paid.
	api.SetTrustBadgePlan(&api.TrustBadgePlan{HideMarketing: true, MaxBadges: 3, Logo: true})
	f.admin.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{f.project}, "show_marketing": false, "show_logo": true}, &b)
	if b.ShowMarketing {
		t.Error("paid plan could not switch the marketing line off")
	}
	if code := upload([]byte("<svg onload=alert(1)>")); code != 400 {
		t.Errorf("non-image logo: %d, want 400", code)
	}
	if code := upload(append(png, bytes.Repeat([]byte{0}, store.TrustBadgeMaxLogo)...)); code != 413 {
		t.Errorf("oversized logo: %d, want 413", code)
	}
	if code := upload(png); code != 204 {
		t.Fatalf("logo: %d", code)
	}
	f.turnOn(t)
	f.decide(t, trustbadge.Active, time.Now())
	_, _, body := f.get(t, "/api/v1/public/trust/acme")
	var tp struct {
		LogoURL       *string `json:"logo_url"`
		ShowMarketing bool    `json:"show_marketing"`
	}
	_ = json.Unmarshal([]byte(body), &tp)
	if tp.LogoURL == nil || !strings.Contains(*tp.LogoURL, "/api/v1/public/trust/acme/logo") || tp.ShowMarketing {
		t.Errorf("paid trust data: %s", body)
	}
	code, h, logo := f.get(t, "/api/v1/public/trust/acme/logo")
	if code != 200 || h.Get("Content-Type") != "image/png" || h.Get("X-Content-Type-Options") != "nosniff" || logo != string(png) {
		t.Errorf("logo: %d %s", code, h.Get("Content-Type"))
	}
	if _, _, svg := f.get(t, "/badge/acme.svg"); strings.Contains(svg, "Monitor yours") {
		t.Errorf("paid badge with the line switched off still shows it: %s", svg)
	}
	// Back to Free: the logo and the switch stop applying at once.
	api.SetTrustBadgePlan(nil)
	if code, _, _ := f.get(t, "/api/v1/public/trust/acme/logo"); code != 404 {
		t.Errorf("logo after downgrade: %d", code)
	}
	if _, _, svg := f.get(t, "/badge/acme.svg"); !strings.Contains(svg, "Monitor yours") {
		t.Errorf("marketing line missing after downgrade: %s", svg)
	}
}

// Only organisation admins, and admins of every project a badge covers,
// may see or change it; the terms come before turning it on, and every
// change is audited.
func TestTrustBadgeSettingsPermissionsAndAudit(t *testing.T) {
	f := newTrustFixture(t, nil)
	e := f.e
	path := fmt.Sprintf("/api/v1/trust-badges/%d", f.badge)
	for _, role := range []auth.Role{auth.RoleSecurity, auth.RoleEngineer, auth.RoleViewer} {
		email := string(role) + "@x.io"
		e.user(email, role)
		s := e.login(email)
		if code := s.do("GET", "/api/v1/trust-badges", nil, nil); code != 403 {
			t.Errorf("%s lists badges: %d", role, code)
		}
		if code := s.do("POST", path+"/enabled", map[string]any{"enabled": true}, nil); code != 403 {
			t.Errorf("%s turns a badge on: %d", role, code)
		}
	}

	// Terms first, and only the current version.
	if code := f.admin.do("POST", path+"/enabled", map[string]any{"enabled": true}, nil); code != 400 {
		t.Errorf("on without terms: %d, want 400", code)
	}
	if code := f.admin.do("POST", path+"/terms", map[string]any{"version": "old", "accepted": true}, nil); code != 400 {
		t.Errorf("old terms: %d, want 400", code)
	}
	if code := f.admin.do("POST", path+"/terms", map[string]any{"version": api.TrustBadgeTermsVersion}, nil); code != 400 {
		t.Errorf("terms not ticked: %d, want 400", code)
	}
	f.turnOn(t)

	// A project admin with access to that project only.
	var other store.Project
	f.admin.do("POST", "/api/v1/projects", map[string]any{"name": "Other"}, &other)
	if code := f.admin.do("POST", "/api/v1/access-grants", map[string]any{"email": "padmin@x.io", "password": pw, "role": "admin",
		"project_id": f.project}, nil); code != 201 && code != 200 {
		t.Fatalf("grant: %d", code)
	}
	pa := e.login("padmin@x.io")
	var list struct {
		Badges []store.TrustBadge `json:"badges"`
	}
	if code := pa.do("GET", "/api/v1/trust-badges", nil, &list); code != 200 || len(list.Badges) != 1 {
		t.Errorf("project admin's badges: %d %+v", code, list.Badges)
	}
	if code := pa.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{f.project, other.ID}}, nil); code != 403 && code != 404 {
		t.Errorf("project admin widening the scope to a project they don't administer: %d", code)
	}
	if code := pa.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{f.project}, "display_name": "Acme"}, nil); code != 200 {
		t.Errorf("project admin editing their badge: %d", code)
	}
	// Another workspace's project in the scope is refused.
	if code := f.admin.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{999999}}, nil); code != 404 {
		t.Errorf("unknown project in the scope: %d, want 404", code)
	}
	// Reserved and malformed addresses.
	for _, slug := range []string{"stackurity", "stackurity-official", "admin", "a", "bad--slug", "UPPER CASE"} {
		if code := f.admin.do("PUT", path, map[string]any{"slug": slug, "scope_kind": "projects", "project_ids": []int64{f.project}}, nil); code != 400 {
			t.Errorf("slug %q: %d, want 400", slug, code)
		}
	}
	if code := f.admin.do("PUT", path, map[string]any{"slug": "acme", "scope_kind": "projects", "project_ids": []int64{f.project}, "website_url": "javascript:alert(1)"}, nil); code != 400 {
		t.Errorf("non-https website: %d", code)
	}
	// History reads are audited; the customer's timeline has no evidence.
	var hist struct{ Items []map[string]any }
	if code := f.admin.do("GET", path+"/history", nil, &hist); code != 200 || len(hist.Items) == 0 {
		t.Fatalf("history: %d %+v", code, hist)
	}
	if _, ok := hist.Items[0]["evidence"]; ok {
		t.Error("the customer's timeline carries the evidence")
	}
	if code := f.admin.do("DELETE", path, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	rows, err := e.st.Pool.Query(tenant.System(context.Background()), `SELECT action FROM audit_events WHERE object_type = 'trust_badge' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	for _, want := range []string{"trust_badge.create", "trust_badge.terms.accept", "trust_badge.enable", "trust_badge.update",
		"trust_badge.history.read", "trust_badge.delete"} {
		if !slices.Contains(actions, want) {
			t.Errorf("no %s audit entry in %v", want, actions)
		}
	}
}

// Operators see every badge's evidence; each view is audited; nobody else
// may.
func TestTrustBadgeEvidenceViewer(t *testing.T) {
	f := newTrustFixture(t, nil)
	f.turnOn(t)
	f.decide(t, trustbadge.Active, time.Now())
	if code := f.admin.do("GET", "/api/v1/admin/trust-badges", nil, nil); code != 403 {
		t.Errorf("organisation admin opens the evidence viewer: %d", code)
	}
	f.e.instanceAdmin("admin@x.io")
	op := f.e.login("admin@x.io")
	var list struct{ Items []store.AdminTrustBadge }
	if code := op.do("GET", "/api/v1/admin/trust-badges", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].Slug != "acme" {
		t.Fatalf("operator list: %d %+v", code, list)
	}
	var hist struct {
		Items []store.TrustBadgeStatus `json:"items"`
	}
	if code := op.do("GET", fmt.Sprintf("/api/v1/admin/trust-badges/%d/history", f.badge), nil, &hist); code != 200 || len(hist.Items) < 2 {
		t.Fatalf("operator history: %d %+v", code, hist)
	}
	if len(hist.Items[0].Evidence.Inputs.Assets) != 1 || hist.Items[0].Evidence.Inputs.Assets[0].ID != f.assetID {
		t.Errorf("evidence without its inputs: %+v", hist.Items[0].Evidence.Inputs)
	}
	var n int
	_ = f.e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM audit_events
		WHERE action IN ('trust_badge.admin.list', 'trust_badge.admin.history.read')`).Scan(&n)
	if n != 2 {
		t.Errorf("%d audit entries for two operator views", n)
	}
}

// Changing or turning off a badge purges its cached copies at the CDN.
func TestTrustBadgePurgesCache(t *testing.T) {
	var mu sync.Mutex
	var got []string
	done := make(chan struct{}, 4)
	f := newTrustFixture(t, func(s *api.Server) {
		s.BaseURL = "https://app.example"
		s.TrustBadgePurge = func(ctx context.Context, urls []string) error {
			mu.Lock()
			got = append(got, urls...)
			mu.Unlock()
			done <- struct{}{}
			return nil
		}
	})
	f.turnOn(t)
	<-done
	mu.Lock()
	got = nil
	mu.Unlock()
	f.admin.do("POST", fmt.Sprintf("/api/v1/trust-badges/%d/enabled", f.badge), map[string]any{"enabled": false}, nil)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no purge after turning the badge off")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"https://app.example/badge/acme.svg", "https://app.example/badge/acme.svg?theme=dark",
		"https://app.example/api/v1/public/trust/acme", "https://stackurity.ai/trust/acme"} {
		if !slices.Contains(got, want) {
			t.Errorf("purge without %s: %v", want, got)
		}
	}
}

// Outside Stackurity Cloud, or with the badge off, none of its routes
// exist and the dashboard is not told about it.
func TestTrustBadgeOffServesNothing(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustBadge = false })
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	for _, p := range []string{"/badge/acme.svg", "/api/v1/public/trust/acme", "/api/v1/public/trust?listed=1", "/api/v1/trust-badges", "/api/v1/admin/trust-badges"} {
		if code := admin.do("GET", p, nil, nil); code != 404 {
			t.Errorf("GET %s with the badge off: %d, want 404", p, code)
		}
	}
	var meta map[string]any
	admin.do("GET", "/api/v1/meta", nil, &meta)
	if _, ok := meta["trust_badge"]; ok {
		t.Error("meta offers the trust badge while it is off")
	}
}

// The public endpoints are limited per address.
func TestTrustBadgeRateLimited(t *testing.T) {
	f := newTrustFixture(t, nil)
	limited := false
	for range 130 {
		if code, _, _ := f.get(t, "/api/v1/public/trust/acme"); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("no 429 after 130 requests in a minute")
	}
}
