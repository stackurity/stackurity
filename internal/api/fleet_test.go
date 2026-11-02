package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type createdCode struct {
	Enrollment store.Enrollment `json:"enrollment"`
	Code       string           `json:"code"`
}

// redeemFrom redeems code as hostname from address ip (CF-Connecting-IP,
// trusted from the loopback test client) and returns the status, the
// answer and the Retry-After header.
func redeemFrom(e *env, code, hostname, ip string, project int64) (int, map[string]any, string) {
	in := map[string]any{"code": code, "hostname": hostname}
	if project != 0 {
		in["project_id"] = project
	}
	b, _ := json.Marshal(in)
	resp := e.anon().req("POST", "/api/v1/enroll", bytes.NewReader(b), map[string]string{
		"X-Stackurity-CSRF": "1", "Content-Type": "application/json", "CF-Connecting-IP": ip})
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header.Get("Retry-After")
}

func sysCount(t *testing.T, e *env, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Fleet codes: an explicit count and expiry (up to 1,000 servers and 90
// days), a project, only the hash stored, a usage list, revocation and
// expiry, and every step in the audit log.
func TestFleetEnrollmentCodes(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin, eng := e.login("admin@x.io"), e.login("eng@x.io")

	if code := eng.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 10, "ttl_hours": 24}, nil); code != 403 {
		t.Errorf("engineer created a fleet code: %d", code)
	}
	for _, bad := range []map[string]any{
		{"fleet": true},                                                    // no count or expiry
		{"fleet": true, "uses": 10},                                        // no expiry
		{"fleet": true, "ttl_hours": 24},                                   // no count
		{"fleet": true, "uses": 1001, "ttl_hours": 24},                     // over 1,000
		{"fleet": true, "uses": 10, "ttl_hours": 2161},                     // over 90 days
		{"fleet": true, "uses": -1, "ttl_hours": 24},                       // negative
		{"uses": 501},                                                      // a standard code stays at 500
		{"ttl_hours": 721},                                                 // and 30 days
		{"fleet": true, "uses": 10, "ttl_hours": 24, "project_id": 999999}, // no such project
	} {
		var out struct {
			Error struct{ Message string } `json:"error"`
		}
		if code := admin.do("POST", "/api/v1/enrollments", bad, &out); code != 400 {
			t.Errorf("accepted %v: %d", bad, code)
		} else if bad["uses"] == 501 && !strings.Contains(out.Error.Message, "fleet") {
			t.Errorf("a standard code over 500 does not point to fleet codes: %q", out.Error.Message)
		}
	}
	// The single-use default is unchanged.
	var single createdCode
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{}, &single); code != 201 || single.Enrollment.UsesLeft != 1 || single.Enrollment.Fleet ||
		single.Enrollment.MaxUses == nil || *single.Enrollment.MaxUses != 1 || time.Until(single.Enrollment.ExpiresAt) > 25*time.Hour {
		t.Fatalf("default code: %d %+v", code, single.Enrollment)
	}
	// The limits themselves are accepted.
	var big createdCode
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 1000, "ttl_hours": 2160}, &big); code != 201 ||
		big.Enrollment.UsesLeft != 1000 || !big.Enrollment.Fleet || time.Until(big.Enrollment.ExpiresAt) < 89*24*time.Hour {
		t.Fatalf("fleet code at the limits: %d %+v", code, big.Enrollment)
	}

	var proj struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "web fleet"}, &proj); code != 201 || proj.ID == 0 {
		t.Fatalf("project: %d", code)
	}
	var fleet createdCode
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 3, "ttl_hours": 48, "label": "web",
		"environment": "production", "project_id": proj.ID}, &fleet); code != 201 || !strings.HasPrefix(fleet.Code, "enr_") ||
		fleet.Enrollment.ProjectID == nil || *fleet.Enrollment.ProjectID != proj.ID {
		t.Fatalf("fleet code: %d %+v", code, fleet)
	}

	// Only the hash is stored: the code is in no column of any table that
	// records it (enrollments, uses, the audit log, rate limits).
	sum := sha256.Sum256([]byte(fleet.Code))
	if n := sysCount(t, e, `SELECT count(*) FROM enrollments WHERE code_hash = $1`, sum[:]); n != 1 {
		t.Errorf("code hash stored %d times", n)
	}
	checkNoPlain := func(when string) {
		t.Helper()
		for _, tbl := range []string{"enrollments", "enrollment_uses", "audit_events", "rate_limits", "api_tokens"} {
			if n := sysCount(t, e, `SELECT count(*) FROM `+tbl+` x WHERE row_to_json(x)::text LIKE '%' || $1 || '%'`, strings.TrimPrefix(fleet.Code, "enr_")); n != 0 {
				t.Errorf("%s: the code is stored in clear in %s", when, tbl)
			}
		}
	}
	checkNoPlain("after create")

	// The code checks the project it is asked for, without using it up.
	if status, _, _ := redeemFrom(e, fleet.Code, "web-x", "198.51.100.9", proj.ID+1000); status != 403 {
		t.Errorf("redeemed for another project: %d", status)
	}
	// Three servers enroll; the fourth is refused.
	var tokens []string
	for i := range 3 {
		status, out, _ := redeemFrom(e, fleet.Code, fmt.Sprintf("web-%d", i+1), fmt.Sprintf("203.0.113.%d", i+1), proj.ID)
		if status != 200 || out["environment"] != "production" || out["project_id"] != float64(proj.ID) {
			t.Fatalf("redeem %d: %d %v", i+1, status, out)
		}
		tokens = append(tokens, out["token"].(string))
	}
	if status, _, _ := redeemFrom(e, fleet.Code, "web-4", "203.0.113.4", 0); status != 403 {
		t.Errorf("fourth use of a three-server code: %d", status)
	}
	if n := sysCount(t, e, `SELECT count(*) FROM api_tokens WHERE project_id = $1 AND role = 'collector' AND name LIKE 'agent on web-%'`, proj.ID); n != 3 {
		t.Errorf("collector tokens in the project: %d", n)
	}
	if code := bearer(e, tokens[0], "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Errorf("a token from a fleet code cannot ingest: %d", code)
	}
	checkNoPlain("after use")

	// The usage list: which hosts, from where, with which token.
	var uses struct{ Items []store.EnrollmentUse }
	if code := admin.do("GET", "/api/v1/enrollments/"+itoa(fleet.Enrollment.ID)+"/uses", nil, &uses); code != 200 || len(uses.Items) != 3 {
		t.Fatalf("uses: %d %+v", code, uses.Items)
	}
	if u := uses.Items[0]; u.Hostname != "web-3" || u.RemoteAddr != "203.0.113.3" || u.TokenPrefix == "" || u.TokenRevoked {
		t.Errorf("newest use: %+v", u)
	}
	if code := eng.do("GET", "/api/v1/enrollments/"+itoa(fleet.Enrollment.ID)+"/uses", nil, nil); code != 403 {
		t.Errorf("engineer read the usage list: %d", code)
	}
	if code := admin.do("GET", "/api/v1/enrollments/999999/uses", nil, nil); code != 404 {
		t.Errorf("uses of a missing code: %d", code)
	}

	// Revocation stops a fleet code at once; the fleet list keeps it, with
	// its usage, while the pending list drops it.
	var rev createdCode
	admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 50, "ttl_hours": 24, "label": "to revoke"}, &rev)
	if status, _, _ := redeemFrom(e, rev.Code, "db-1", "203.0.113.20", 0); status != 200 {
		t.Fatalf("redeem before revoke: %d", status)
	}
	if code := admin.do("DELETE", "/api/v1/enrollments/"+itoa(rev.Enrollment.ID), nil, nil); code != 204 {
		t.Fatal(code)
	}
	if status, _, _ := redeemFrom(e, rev.Code, "db-2", "203.0.113.21", 0); status != 403 {
		t.Errorf("revoked fleet code redeemed: %d", status)
	}
	var list struct{ Items []store.Enrollment }
	admin.do("GET", "/api/v1/enrollments?fleet=1", nil, &list)
	var found *store.Enrollment
	for i := range list.Items {
		if !list.Items[i].Fleet {
			t.Errorf("fleet list has a standard code: %+v", list.Items[i])
		}
		if list.Items[i].ID == rev.Enrollment.ID {
			found = &list.Items[i]
		}
	}
	if found == nil || found.RevokedAt == nil || found.UsesLeft != 49 || found.MaxUses == nil || *found.MaxUses != 50 {
		t.Errorf("revoked fleet code in the fleet list: %+v", found)
	}
	admin.do("GET", "/api/v1/enrollments", nil, &list)
	for _, it := range list.Items {
		if it.ID == rev.Enrollment.ID {
			t.Errorf("revoked code still pending")
		}
	}

	// Expiry: a fleet code past its expiry is refused like any other.
	var exp createdCode
	admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 10, "ttl_hours": 1}, &exp)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE enrollments SET expires_at = now() - interval '1 second' WHERE id = $1`, exp.Enrollment.ID); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := redeemFrom(e, exp.Code, "late-1", "203.0.113.30", 0); status != 403 {
		t.Errorf("expired fleet code redeemed: %d", status)
	}
	if n := sysCount(t, e, `SELECT uses_left FROM enrollments WHERE id = $1`, exp.Enrollment.ID); n != 10 {
		t.Errorf("expired code used up: %d left", n)
	}

	// Audit: creation (with the fleet flag), each use, the revocation.
	if n := sysCount(t, e, `SELECT count(*) FROM audit_events WHERE action = 'enrollment.create' AND object_id = $1 AND detail->>'fleet' = 'true' AND (detail->>'uses')::int = 3`, itoa(fleet.Enrollment.ID)); n != 1 {
		t.Errorf("enrollment.create audit events: %d", n)
	}
	if n := sysCount(t, e, `SELECT count(*) FROM audit_events WHERE action = 'enrollment.redeem' AND object_id = $1 AND detail->>'fleet' = 'true'`, itoa(fleet.Enrollment.ID)); n != 3 {
		t.Errorf("enrollment.redeem audit events: %d", n)
	}
	if n := sysCount(t, e, `SELECT count(*) FROM audit_events WHERE action = 'enrollment.revoke' AND object_id = $1`, itoa(rev.Enrollment.ID)); n != 1 {
		t.Errorf("enrollment.revoke audit events: %d", n)
	}
}

// Enrollment rate limits: successful enrollments from one address (a fleet
// behind a NAT gateway) are not held to the ten-a-minute limit that stops
// guessing, each code enrolls at most 60 hosts a minute, and refused hosts
// are told when to retry.
func TestFleetEnrollRateLimits(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true })
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var c createdCode
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 100, "ttl_hours": 24}, &c); code != 201 {
		t.Fatal(code)
	}
	freshWindow(time.Minute)
	const nat = "198.51.100.77"
	for i := range 60 {
		if status, out, _ := redeemFrom(e, c.Code, fmt.Sprintf("node-%d", i), nat, 0); status != 200 {
			t.Fatalf("enrollment %d from one address: %d %v", i+1, status, out)
		}
	}
	status, _, retry := redeemFrom(e, c.Code, "node-60", "198.51.100.78", 0)
	if status != 429 {
		t.Fatalf("61st enrollment with one code in a minute: %d; want 429", status)
	}
	if n, err := strconv.Atoi(retry); err != nil || n < 1 || n > 60 {
		t.Errorf("Retry-After = %q", retry)
	}
	if n := sysCount(t, e, `SELECT uses_left FROM enrollments WHERE id = $1`, c.Enrollment.ID); n != 40 {
		t.Errorf("uses left after the per-code limit: %d; want 40 (a refused host uses nothing)", n)
	}

	// Guessing is still limited per address: ten failures, then even a good
	// code from that address waits; another address is not held up.
	var other createdCode
	admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 5, "ttl_hours": 24}, &other)
	const guesser = "192.0.2.50"
	for i := range 10 {
		if status, _, _ := redeemFrom(e, fmt.Sprintf("enr_guess%d", i), "x", guesser, 0); status != 403 {
			t.Fatalf("guess %d: %d", i+1, status)
		}
	}
	if status, _, retry := redeemFrom(e, other.Code, "x", guesser, 0); status != 429 || retry == "" {
		t.Errorf("after ten failures: %d (Retry-After %q); want 429", status, retry)
	}
	if status, _, _ := redeemFrom(e, other.Code, "y", "192.0.2.51", 0); status != 200 {
		t.Errorf("another address held up by the guesser: %d", status)
	}
}

// fakeDO is a DigitalOcean API with n droplets, 200 a page.
type fakeDO struct {
	mu       sync.Mutex
	token    string
	droplets []map[string]any
	requests []string
	auth     []string
}

func (f *fakeDO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.String())
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"id":"unauthorized","message":"Unable to authenticate you"}`))
		return
	}
	if r.URL.Path != "/v2/droplets" {
		w.WriteHeader(404)
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	all := f.droplets
	if tag := q.Get("tag_name"); tag == "endless" {
		// A listing that never ends: one droplet a page, always a next page.
		_ = json.NewEncoder(w).Encode(map[string]any{"droplets": all[:1],
			"links": map[string]any{"pages": map[string]any{"next": "https://evil.invalid/v2/droplets?page=" + strconv.Itoa(page+1)}}})
		return
	} else if tag != "" {
		var sel []map[string]any
		for _, d := range all {
			for _, t := range d["tags"].([]string) {
				if t == tag {
					sel = append(sel, d)
				}
			}
		}
		all = sel
	}
	from, to := (page-1)*per, page*per
	from, to = min(from, len(all)), min(to, len(all))
	links := map[string]any{}
	if to < len(all) {
		// Real answers carry an absolute URL; it must not be followed.
		links["pages"] = map[string]any{"next": "https://evil.invalid/v2/droplets?page=" + strconv.Itoa(page+1)}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"droplets": all[from:to], "links": links, "meta": map[string]any{"total": len(all)}})
}

func droplet(id int, name, pub, priv string, tags ...string) map[string]any {
	if tags == nil {
		tags = []string{}
	}
	return map[string]any{"id": id, "name": name, "status": "active", "tags": tags,
		"region": map[string]any{"slug": "blr1", "name": "Bangalore 1"},
		"image":  map[string]any{"distribution": "Ubuntu", "name": "24.04 (LTS) x64"},
		"networks": map[string]any{
			"v4": []map[string]any{{"ip_address": pub, "type": "public"}, {"ip_address": priv, "type": "private"}},
			"v6": []map[string]any{}}}
}

func ingestHost(t *testing.T, e *env, token, hostname string) {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: hostname, Identifiers: []model.Identifier{{Scheme: "hostname", Value: hostname}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	body, _ := json.Marshal(b)
	if code := bearer(e, token, "POST", "/api/v1/ingest", body, nil); code != 201 {
		t.Fatalf("ingest %s: %d", hostname, code)
	}
}

// DigitalOcean discovery: the token is checked, stored encrypted and never
// returned; droplets are listed page by page from the configured API only,
// through the outbound guard; and each is matched to the agents that report.
func TestDigitalOceanDiscovery(t *testing.T) {
	const good = "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
	fake := &fakeDO{token: good}
	// 203 droplets: two pages. web-000 reports by name, db-1.example.com
	// reports as db-1, web-002 enrolled from its address under another name.
	fake.droplets = append(fake.droplets,
		droplet(1, "web-000", "203.0.113.100", "10.0.0.100", "web"),
		droplet(2, "db-1.example.com", "203.0.113.101", "10.0.0.101", "db"),
		droplet(3, "web-002", "203.0.113.102", "10.0.0.102", "web"))
	for i := range 200 {
		fake.droplets = append(fake.droplets, droplet(100+i, fmt.Sprintf("batch-%03d", i), fmt.Sprintf("198.18.%d.%d", i/250, i%250+1), "10.1.0.1"))
	}
	doSrv := httptest.NewServer(fake)
	t.Cleanup(doSrv.Close)

	box, err := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, func(s *api.Server) { s.TrustProxy = true; s.SecretBox = box; s.DigitalOceanAPI = doSrv.URL })
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin, eng := e.login("admin@x.io"), e.login("eng@x.io")

	var st map[string]any
	if code := admin.do("GET", "/api/v1/integrations/digitalocean", nil, &st); code != 200 || st["connected"] != false {
		t.Fatalf("status before connecting: %d %v", code, st)
	}
	if code := admin.do("GET", "/api/v1/integrations/digitalocean/droplets", nil, nil); code != 409 {
		t.Errorf("droplets before connecting: %d", code)
	}
	if code := eng.do("PUT", "/api/v1/integrations/digitalocean/token", map[string]string{"token": good}, nil); code != 403 {
		t.Errorf("engineer connected DigitalOcean: %d", code)
	}
	if code := eng.do("GET", "/api/v1/integrations/digitalocean/droplets", nil, nil); code != 403 {
		t.Errorf("engineer listed droplets: %d", code)
	}
	// A token DigitalOcean refuses is not stored.
	if code := admin.do("PUT", "/api/v1/integrations/digitalocean/token", map[string]string{"token": "dop_v1_wrong"}, nil); code != 400 {
		t.Errorf("refused token: %d", code)
	}
	if n := sysCount(t, e, `SELECT count(*) FROM workspace_secrets WHERE name = 'digitalocean-token'`); n != 0 {
		t.Errorf("a refused token was stored")
	}
	if code := admin.do("PUT", "/api/v1/integrations/digitalocean/token", map[string]string{"token": good}, nil); code != 204 {
		t.Fatalf("connect: %d", code)
	}

	// Coverage: one host reports as web-000, one as db-1; one agent enrolled
	// from web-002's public address under another name and has not reported.
	var c createdCode
	admin.do("POST", "/api/v1/enrollments", map[string]any{"fleet": true, "uses": 10, "ttl_hours": 24}, &c)
	_, out, _ := redeemFrom(e, c.Code, "web-000", "203.0.113.100", 0)
	ingestHost(t, e, out["token"].(string), "web-000")
	_, out, _ = redeemFrom(e, c.Code, "db-1", "192.0.2.200", 0)
	ingestHost(t, e, out["token"].(string), "db-1")
	redeemFrom(e, c.Code, "ubuntu-s-1vcpu", "203.0.113.102", 0)

	fake.mu.Lock()
	fake.requests = nil
	fake.mu.Unlock()
	var list struct {
		Items     []api.FleetMachine
		Total     int
		Covered   int
		Truncated bool
	}
	resp := admin.req("GET", "/api/v1/integrations/digitalocean/droplets", nil, nil)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("droplets: %d %s", resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 203 || len(list.Items) != 203 || list.Covered != 3 || list.Truncated {
		t.Errorf("listing: total %d, items %d, covered %d, truncated %v", list.Total, len(list.Items), list.Covered, list.Truncated)
	}
	// Two pages, both from the configured API with per_page=200; the
	// absolute next link (another host) was never followed.
	fake.mu.Lock()
	reqs := append([]string(nil), fake.requests...)
	fake.mu.Unlock()
	if len(reqs) != 2 || !strings.Contains(reqs[0], "page=1") || !strings.Contains(reqs[1], "page=2") || !strings.Contains(reqs[1], "per_page=200") {
		t.Errorf("pages requested: %v", reqs)
	}
	by := map[string]api.FleetMachine{}
	for _, m := range list.Items {
		by[m.Name] = m
	}
	if m := by["web-000"]; m.Coverage != "reporting" || m.Match != "hostname" || m.AssetID == 0 || m.PublicIPv4 != "203.0.113.100" || m.Region != "blr1" {
		t.Errorf("web-000: %+v", m)
	}
	if m := by["db-1.example.com"]; m.Coverage != "reporting" || m.Asset != "db-1" {
		t.Errorf("db-1.example.com (reports as db-1): %+v", m)
	}
	if m := by["web-002"]; m.Coverage != "enrolled" || m.Match != "address" || m.EnrolledAs != "ubuntu-s-1vcpu" {
		t.Errorf("web-002 (enrolled from its address): %+v", m)
	}
	if m := by["batch-000"]; m.Coverage != "not_covered" || m.AssetID != 0 {
		t.Errorf("batch-000: %+v", m)
	}
	if list.Items[0].Coverage != "not_covered" {
		t.Errorf("droplets not covered are not listed first: %+v", list.Items[0])
	}

	// The token is never returned: not by the listing, the status, the
	// secrets list or the audit log; and it is stored only encrypted.
	for _, path := range []string{"/api/v1/integrations/digitalocean", "/api/v1/secrets", "/api/v1/audit"} {
		resp := admin.req("GET", path, nil, nil)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), good) || strings.Contains(string(raw), good) {
			t.Errorf("%s returns the DigitalOcean token", path)
		}
	}
	for _, tbl := range []string{"workspace_secrets", "audit_events"} {
		if n := sysCount(t, e, `SELECT count(*) FROM `+tbl+` x WHERE row_to_json(x)::text LIKE '%' || $1 || '%'`, good[8:40]); n != 0 {
			t.Errorf("the token is in %s in clear", tbl)
		}
	}
	if n := sysCount(t, e, `SELECT count(*) FROM audit_events WHERE action = 'digitalocean.connect'`); n != 1 {
		t.Errorf("digitalocean.connect audit events: %d", n)
	}
	// Every request carried the stored token: it round-trips through the
	// encrypted secret.
	fake.mu.Lock()
	for _, a := range fake.auth[len(fake.auth)-2:] {
		if a != "Bearer "+good {
			t.Errorf("request sent Authorization %q", a)
		}
	}
	fake.mu.Unlock()

	// A tag narrows the listing.
	admin.do("GET", "/api/v1/integrations/digitalocean/droplets?tag=web", nil, &list)
	if list.Total != 2 {
		t.Errorf("tag=web: %d droplets", list.Total)
	}
	// A listing that never ends stops at the bound and says so.
	admin.do("GET", "/api/v1/integrations/digitalocean/droplets?tag=endless", nil, &list)
	if !list.Truncated || list.Total != 25 {
		t.Errorf("endless listing: truncated %v, %d droplets", list.Truncated, list.Total)
	}

	// The outbound guard applies: with private targets off, the fake API on
	// loopback is unreachable and nothing is sent to it.
	t.Run("netguard", func(t *testing.T) {
		netguard.Set(netguard.Config{Mode: "none"})
		defer netguard.Set(netguard.FromEnv())
		fake.mu.Lock()
		before := len(fake.requests)
		fake.mu.Unlock()
		var out struct{ Error struct{ Message string } }
		if code := admin.do("GET", "/api/v1/integrations/digitalocean/droplets", nil, &out); code != 400 || !strings.Contains(out.Error.Message, "internal address") {
			t.Errorf("listing through a blocked address: %d %q", code, out.Error.Message)
		}
		fake.mu.Lock()
		after := len(fake.requests)
		fake.mu.Unlock()
		if after != before {
			t.Errorf("%d requests reached a blocked address", after-before)
		}
	})

	// A token DigitalOcean stops accepting (revoked there) is reported as such.
	fake.mu.Lock()
	fake.token = "dop_v1_rotated"
	fake.mu.Unlock()
	var refused struct {
		Error struct{ Code, Message string }
	}
	if code := admin.do("GET", "/api/v1/integrations/digitalocean/droplets", nil, &refused); code != 409 || refused.Error.Code != "token_refused" {
		t.Errorf("refused stored token: %d %+v", code, refused)
	}

	// Disconnecting deletes the secret.
	if code := admin.do("DELETE", "/api/v1/integrations/digitalocean/token", nil, nil); code != 204 {
		t.Fatalf("disconnect: %d", code)
	}
	if n := sysCount(t, e, `SELECT count(*) FROM workspace_secrets WHERE name = 'digitalocean-token'`); n != 0 {
		t.Errorf("token kept after disconnecting")
	}
	if n := sysCount(t, e, `SELECT count(*) FROM audit_events WHERE action = 'digitalocean.disconnect'`); n != 1 {
		t.Errorf("digitalocean.disconnect audit events: %d", n)
	}
	if code := admin.do("GET", "/api/v1/integrations/digitalocean/droplets", nil, nil); code != 409 {
		t.Errorf("droplets after disconnecting: %d", code)
	}
}

// Without STACKURITY_SECRET_KEY there is nowhere to keep the token.
func TestDigitalOceanNeedsSecretKey(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.DigitalOceanAPI = "http://127.0.0.1:1" })
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	if code := admin.do("PUT", "/api/v1/integrations/digitalocean/token", map[string]string{"token": "dop_v1_x"}, nil); code != 409 {
		t.Errorf("connect without a secret key: %d", code)
	}
}
