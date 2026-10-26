package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// projectScopes declares, for every route, how it treats project access
// (docs/design/projects.md). TestEveryRouteIsClassified fails when a route
// is missing here or disagrees with the router (api.ProjectScopeOf).
//
//	public        no credentials; outside the project gate
//	account       the caller's own account; open to members with project access only
//	global        data shared by every workspace
//	scoped        workspace data narrowed by row-level security to the caller's
//	              projects and to the project chosen in the switcher
//	scoped-write  as scoped, and the handler checks the caller's role on each asset
//	org           organisation-wide roles only: members with project access get 403
var projectScopes = map[string]string{
	"GET /healthz":                   "public",
	"GET /readyz":                    "public",
	"GET /install/agent.sh":          "public",
	"GET /download/agent/{platform}": "public",
	"GET /api/v1/meta":               "public",
	"POST /api/v1/setup":             "public",
	"POST /api/v1/auth/login":        "public",
	"POST /api/v1/auth/logout":       "public",
	"POST /api/v1/enroll":            "public",
	"GET /api/v1/auth/oidc/login":    "public",
	"GET /api/v1/auth/oidc/callback": "public",

	"GET /api/v1/auth/me":                   "account",
	"POST /api/v1/auth/password":            "account",
	"PUT /api/v1/auth/default-project":      "account",
	"POST /api/v1/feedback":                 "account",
	"GET /api/v1/workspaces":                "account",
	"POST /api/v1/workspaces/{id}/activate": "account",
	"GET /api/v1/tokens":                    "account",
	"POST /api/v1/tokens":                   "account",
	"DELETE /api/v1/tokens/{id}":            "account",

	"GET /api/v1/packs":              "global",
	"GET /api/v1/packs/{id}/archive": "global",
	"GET /api/v1/feeds":              "global",
	"GET /api/v1/advisories/{key}":   "global",

	"GET /api/v1/projects":                     "scoped",
	"GET /api/v1/projects/{id}":                "scoped",
	"GET /api/v1/overview":                     "scoped",
	"GET /api/v1/facets":                       "scoped",
	"GET /api/v1/search":                       "scoped",
	"GET /api/v1/assets":                       "scoped",
	"GET /api/v1/assets/{id}":                  "scoped",
	"GET /api/v1/assets/{id}/inventory":        "scoped",
	"GET /api/v1/assets/{id}/coverage":         "scoped",
	"GET /api/v1/assets/{id}/coverage-summary": "scoped",
	"GET /api/v1/assets/{id}/collections":      "scoped",
	"GET /api/v1/assets/{id}/relations":        "scoped",
	"GET /api/v1/assets/{id}/drift":            "scoped",
	"GET /api/v1/assets/{id}/stack":            "scoped",
	"GET /api/v1/assets/{id}/sbom":             "scoped",
	"GET /api/v1/assets/{id}/remediation":      "scoped",
	"GET /api/v1/components":                   "scoped",
	"GET /api/v1/components/{id}":              "scoped",
	"GET /api/v1/components/{id}/intel":        "scoped",
	"GET /api/v1/components/{id}/upgrade":      "scoped",
	"GET /api/v1/findings":                     "scoped",
	"GET /api/v1/findings/summary":             "scoped",
	"GET /api/v1/findings/verify":              "scoped",
	"GET /api/v1/findings/{id}":                "scoped",
	"GET /api/v1/findings/{id}/events":         "scoped",
	"GET /api/v1/findings/{id}/upgrade":        "scoped",
	"GET /api/v1/findings/{id}/explain":        "scoped",
	"GET /api/v1/fix-groups":                   "scoped",
	"GET /api/v1/fix-groups/summary":           "scoped",
	"GET /api/v1/fix-groups/{id}":              "scoped",
	"GET /api/v1/evaluation-gaps":              "scoped",
	"GET /api/v1/reports/outcomes":             "scoped",
	"GET /api/v1/reports/evidence":             "scoped",
	"GET /api/v1/incidents":                    "scoped",
	"GET /api/v1/incidents/{id}":               "scoped",
	"GET /api/v1/risk-policy":                  "scoped",
	"GET /api/v1/inventory":                    "scoped",
	"GET /api/v1/coverage":                     "scoped",
	"GET /api/v1/audit":                        "scoped",
	"GET /api/v1/users/directory":              "scoped",
	"GET /api/v1/checks":                       "scoped",
	"GET /api/v1/checks/{id}":                  "scoped",
	"GET /api/v1/ignore-rules":                 "scoped",
	"GET /api/v1/ignore-requests":              "scoped",
	"GET /api/v1/ignore-requests/{id}":         "scoped",

	"PATCH /api/v1/assets/{id}":                  "scoped-write",
	"POST /api/v1/assets/{id}/relations":         "scoped-write",
	"DELETE /api/v1/assets/{id}/relations":       "scoped-write",
	"POST /api/v1/findings/{id}/actions":         "scoped-write",
	"POST /api/v1/findings/actions":              "scoped-write",
	"POST /api/v1/incidents/{id}/actions":        "scoped-write",
	"POST /api/v1/assets/{id}/check":             "scoped-write",
	"POST /api/v1/fix-groups/{id}/check":         "scoped-write",
	"POST /api/v1/fix-groups/{id}/applied":       "scoped-write",
	"POST /api/v1/ignore-requests":               "scoped-write",
	"POST /api/v1/ignore-requests/{id}/decision": "scoped-write",
	"DELETE /api/v1/ignore-rules/{id}":           "scoped-write",
	"GET /api/v1/agent/check":                    "org",

	"POST /api/v1/feeds/{name}/refresh":            "org",
	"GET /api/v1/plugins":                          "org",
	"GET /api/v1/admin/license/":                   "org",
	"PUT /api/v1/admin/license/":                   "org",
	"DELETE /api/v1/admin/license/":                "org",
	"GET /api/v1/admin/packs/":                     "org",
	"POST /api/v1/admin/packs/install":             "org",
	"POST /api/v1/admin/packs/upload":              "org",
	"PATCH /api/v1/admin/packs/{id}":               "org",
	"POST /api/v1/admin/packs/{id}/rollback":       "org",
	"DELETE /api/v1/admin/packs/{id}":              "org",
	"GET /api/v1/admin/health":                     "org",
	"GET /api/v1/updates":                          "org",
	"GET /api/v1/admin/workspaces/":                "org",
	"POST /api/v1/admin/workspaces/":               "org",
	"PATCH /api/v1/admin/workspaces/{id}":          "org",
	"PATCH /api/v1/feeds/{name}":                   "org",
	"POST /api/v1/ingest":                          "org",
	"GET /api/v1/collections/{id}/result":          "org",
	"POST /api/v1/sbom/import":                     "org",
	"GET /api/v1/agent/actions":                    "org",
	"POST /api/v1/agent/actions/{id}/report":       "org",
	"GET /api/v1/remediation/renovate.json":        "org",
	"GET /api/v1/teams":                            "org",
	"GET /api/v1/remediation/plans":                "org",
	"GET /api/v1/remediation/plans/{id}":           "org",
	"GET /api/v1/integrations":                     "org",
	"GET /api/v1/deliveries":                       "org",
	"GET /api/v1/channels":                         "org",
	"GET /api/v1/routes":                           "org",
	"GET /api/v1/remediation/policies":             "org",
	"GET /api/v1/conflicts":                        "org",
	"GET /api/v1/users":                            "org",
	"GET /api/v1/jobs":                             "org",
	"GET /api/v1/jobs/{id}":                        "org",
	"GET /api/v1/secrets":                          "org",
	"GET /api/v1/enrollments":                      "org",
	"GET /api/v1/project-suggestions":              "org",
	"POST /api/v1/project-suggestions/dismiss":     "org",
	"GET /api/v1/access-grants":                    "org",
	"POST /api/v1/access-grants":                   "org",
	"PATCH /api/v1/access-grants/{id}":             "org",
	"DELETE /api/v1/access-grants/{id}":            "org",
	"POST /api/v1/projects":                        "org",
	"PATCH /api/v1/projects/{id}":                  "org",
	"POST /api/v1/projects/{id}/assets":            "org",
	"DELETE /api/v1/projects/{id}/assets":          "org",
	"DELETE /api/v1/assets/{id}":                   "org",
	"POST /api/v1/assets/{id}/remediation-token":   "org",
	"POST /api/v1/integrations/{id}/run":           "org",
	"PATCH /api/v1/integrations/{id}":              "org",
	"DELETE /api/v1/integrations/{id}":             "org",
	"POST /api/v1/conflicts/{id}/resolve":          "org",
	"PATCH /api/v1/users/{id}":                     "org",
	"DELETE /api/v1/users/{id}":                    "org",
	"PATCH /api/v1/teams/{id}":                     "org",
	"DELETE /api/v1/teams/{id}":                    "org",
	"PATCH /api/v1/channels/{id}":                  "org",
	"DELETE /api/v1/channels/{id}":                 "org",
	"POST /api/v1/channels/{id}/test":              "org",
	"PUT /api/v1/routes/{id}":                      "org",
	"DELETE /api/v1/routes/{id}":                   "org",
	"POST /api/v1/deliveries/{id}/retry":           "org",
	"DELETE /api/v1/enrollments/{id}":              "org",
	"POST /api/v1/remediation/plans/{id}/decision": "org",
	"PUT /api/v1/remediation/policies/{id}":        "org",
	"DELETE /api/v1/remediation/policies/{id}":     "org",
	"PUT /api/v1/secrets/{name}":                   "org",
	"DELETE /api/v1/secrets/{name}":                "org",
	"POST /api/v1/evaluate":                        "org",
	"PUT /api/v1/risk-policy":                      "org",
	"POST /api/v1/risk-policy/preview":             "org",
	"POST /api/v1/users":                           "org",
	"POST /api/v1/teams":                           "org",
	"POST /api/v1/integrations":                    "org",
	"POST /api/v1/channels":                        "org",
	"POST /api/v1/routes":                          "org",
	"POST /api/v1/enrollments":                     "org",
	"POST /api/v1/remediation/policies":            "org",
	"POST /api/v1/remediation/policies/preview":    "org",
}

// --- one organisation, two projects

// org is an organisation with two projects. Everything of Project Beta (and
// the asset in no project) carries the tag "beta" in its name, so a leak to
// a member of Project Alpha shows up as "beta" in their answers.
type org struct {
	e         *env
	admin     *session
	adminID   int64
	collector string
	agent     string
	ids       map[string]int64
	fixGroup  string // one of Beta's fix groups
}

func (o *org) id(k string) int64 {
	v, ok := o.ids[k]
	if !ok {
		o.e.t.Fatalf("no fixture %q", k)
	}
	return v
}

func (o *org) s(k string) string { return fmt.Sprint(o.id(k)) }

func (o *org) ingest(t *testing.T, name, machineID, env string, purls ...string) store.IngestResult {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: machineID}}, Environment: env})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	raw, _ := json.Marshal(b)
	req, _ := http.NewRequest("POST", o.e.srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+o.collector)
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

// grant gives email (a new member with project access only, unless they
// are a member already) a role on a project or an asset.
func (o *org) grant(t *testing.T, email string, project, asset int64, role auth.Role) store.Grant {
	t.Helper()
	body := map[string]any{"email": email, "password": pw, "role": role}
	if project > 0 {
		body["project_id"] = project
	} else {
		body["asset_id"] = asset
	}
	var out struct{ Grant store.Grant }
	if code := o.admin.do("POST", "/api/v1/access-grants", body, &out); code != 201 && code != 200 {
		t.Fatalf("grant %s: %d", email, code)
	}
	return out.Grant
}

func newOrg(t *testing.T) *org {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.EnsureFeed(tenant.System(ctx), "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	var advs []*osv.Vulnerability
	for _, n := range []string{"0001", "0002", "0003"} {
		advs = append(advs, &osv.Vulnerability{ID: "GHSA-proj-" + n, Aliases: []string{"CVE-2099-" + n}, Summary: "Test advisory", Modified: time.Now()})
	}
	if _, err := e.st.UpsertAdvisories(tenant.System(ctx), "osv:npm", advs); err != nil {
		t.Fatal(err)
	}
	e.user("admin-org@x.io", auth.RoleAdmin)
	o := &org{e: e, admin: e.signIn("admin-org@x.io"), ids: map[string]int64{}}
	var me struct{ User store.User }
	o.admin.do("GET", "/api/v1/auth/me", nil, &me)
	o.adminID = me.User.ID
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	_, collector, err := e.st.CreateToken(ws, "collector", auth.RoleCollector, nil, o.adminID, 0)
	if err != nil {
		t.Fatal(err)
	}
	o.collector = collector

	alpha := o.ingest(t, "host-alpha", "alpha-m1", "prod-alpha", "pkg:npm/alpha-private-lib@1.0.0", "pkg:deb/debian/bash@5.2")
	beta := o.ingest(t, "host-beta", "beta-m1", "prod-beta", "pkg:npm/beta-private-lib@1.0.0", "pkg:deb/debian/bash@5.2")
	betaDB := o.ingest(t, "db-beta", "beta-m2", "prod-beta", "pkg:npm/beta-db-lib@2.0.0")
	shared := o.ingest(t, "shared-db", "shared-m1", "prod-shared", "pkg:npm/shared-lib@3.0.0")
	loose := o.ingest(t, "unfiled-beta", "loose-m1", "prod-loose-beta", "pkg:npm/unfiled-beta-lib@1.0.0")
	o.ids["alpha-asset"], o.ids["beta-asset"], o.ids["beta-asset2"] = alpha.AssetID, beta.AssetID, betaDB.AssetID
	o.ids["shared-asset"], o.ids["unfiled-asset"], o.ids["beta-collection"] = shared.AssetID, loose.AssetID, beta.CollectionID
	if code := o.admin.do("POST", "/api/v1/assets/"+o.s("beta-asset")+"/relations", map[string]any{"to_asset": betaDB.AssetID, "kind": "depends_on"}, nil); code != 204 {
		t.Fatalf("relation: %d", code)
	}
	_, agent, err := e.st.CreateAssetToken(ws, alpha.AssetID, "agent-alpha", o.adminID)
	if err != nil {
		t.Fatal(err)
	}
	o.agent = agent

	// Findings as the evaluator leaves them. CVE-2099-0001 is on both
	// projects (one incident spans them); CVE-2099-0002 is on Beta's
	// database and the unfiled host; CVE-2099-0003 on the shared database.
	rows, _, err := e.st.ListInventory(ws, store.InventoryFilter{Page: store.Page{Limit: 500}})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"alpha-private-lib": "CVE-2099-0001", "beta-private-lib": "CVE-2099-0001",
		"beta-db-lib": "CVE-2099-0002", "unfiled-beta-lib": "CVE-2099-0002", "shared-lib": "CVE-2099-0003"}
	var invIDs []int64
	var in []store.FindingInput
	for _, r := range rows {
		invIDs = append(invIDs, r.ID)
		if k, ok := keys[r.Name]; ok {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: k, InventoryID: r.ID, AssetID: r.AssetID, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "critical", FixedVersion: "9.9.9", Sources: []string{"GHSA-proj-" + k[9:]},
				Evidence: map[string]any{"feed": "osv:npm"}})
			if r.Name == "beta-private-lib" {
				o.ids["beta-component"] = r.ComponentID
			}
		}
	}
	if _, _, err := e.st.SyncFindings(ws, []string{"vulnerability"}, invIDs, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Prioritize(ws, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CorrelateIncidents(ws); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(ws, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	fs, _, err := e.st.ListFindings(ws, store.FindingFilter{Status: "all", Page: store.Page{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		switch {
		case f.AssetID == alpha.AssetID && f.Key == "CVE-2099-0001":
			o.ids["alpha-finding"] = f.ID
		case f.AssetID == beta.AssetID && f.Key == "CVE-2099-0001":
			o.ids["beta-finding"] = f.ID
		case f.AssetID == betaDB.AssetID:
			o.ids["beta-db-finding"] = f.ID
		case f.AssetID == shared.AssetID:
			o.ids["shared-finding"] = f.ID
		case f.AssetID == loose.AssetID:
			o.ids["unfiled-finding"] = f.ID
		}
	}
	incs, _, err := e.st.ListIncidents(ws, store.IncidentFilter{Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range incs {
		switch in.Key {
		case "CVE-2099-0001":
			o.ids["shared-incident"] = in.ID
		case "CVE-2099-0002":
			o.ids["beta-incident"] = in.ID
		}
	}
	if len(o.ids) < 14 {
		t.Fatalf("fixtures: %v", o.ids)
	}
	groups, _, err := e.st.ListFixGroups(ws, store.FixGroupFilter{AssetID: beta.AssetID})
	if err != nil || len(groups) == 0 {
		t.Fatalf("fix groups: %v", err)
	}
	var g struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(groups[0], &g)
	o.fixGroup = g.ID
	if code := o.admin.do("POST", "/api/v1/findings/"+o.s("beta-finding")+"/actions", map[string]any{"action": "comment", "note": "note-beta"}, nil); code != 200 {
		t.Fatalf("comment: %d", code)
	}

	// Projects: Alpha has its host and the shared database; Beta has its
	// two hosts and the shared database. The unfiled host is in neither.
	for _, p := range []struct {
		key, name string
		assets    []int64
	}{
		{"alpha-project", "Project Alpha", []int64{alpha.AssetID, shared.AssetID}},
		{"beta-project", "Project Beta", []int64{beta.AssetID, betaDB.AssetID, shared.AssetID}},
		{"gamma-project", "Project Gamma beta-archived", []int64{betaDB.AssetID}},
	} {
		var pr store.Project
		if code := o.admin.do("POST", "/api/v1/projects", map[string]any{"name": p.name, "asset_ids": p.assets}, &pr); code != 201 {
			t.Fatalf("project %s: %d", p.name, code)
		}
		o.ids[p.key] = pr.ID
	}
	o.ids["beta-grant"] = o.grant(t, "beta-viewer@x.io", o.id("beta-project"), 0, auth.RoleViewer).ID

	// The loop (0.7) on Beta: a check, a request to ignore Beta's database
	// issue, and an ignore rule on the unfiled host.
	var chk struct{ ID int64 }
	if code := o.admin.do("POST", "/api/v1/assets/"+o.s("beta-asset")+"/check", nil, &chk); code != 201 {
		t.Fatalf("check: %d", code)
	}
	o.ids["beta-check"] = chk.ID
	e.user("org-engineer@x.io", auth.RoleEngineer)
	var ireq struct{ ID int64 }
	if code := e.signIn("org-engineer@x.io").do("POST", "/api/v1/ignore-requests", map[string]any{"finding_ids": []int64{o.id("beta-db-finding")},
		"reason": "mitigated", "note": "beta-firewall", "scope": "asset", "expiry": "date", "until": time.Now().AddDate(0, 0, 30)}, &ireq); code != 201 {
		t.Fatalf("ignore request: %d", code)
	}
	o.ids["beta-ignorerequest"] = ireq.ID
	if code := o.admin.do("POST", "/api/v1/findings/"+o.s("unfiled-finding")+"/actions", map[string]any{"action": "ignore",
		"reason": "false_positive", "note": "beta-not-used", "scope": "asset", "expiry": "never"}, nil); code != 200 {
		t.Fatalf("ignore: %d", code)
	}
	var rules struct{ Items []store.IgnoreRule }
	o.admin.do("GET", "/api/v1/ignore-rules", nil, &rules)
	if len(rules.Items) != 1 {
		t.Fatalf("ignore rules: %+v", rules.Items)
	}
	o.ids["beta-ignorerule"] = rules.Items[0].ID
	return o
}

// member is a caller whose access the sweep checks.
type member struct {
	name string
	do   func(method, path string, body []byte) (int, string)
}

func sessionMember(name string, s *session, hdr map[string]string) member {
	return member{name: name, do: func(method, path string, body []byte) (int, string) {
		h := map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"}
		for k, v := range hdr {
			h[k] = v
		}
		resp := s.req(method, path, strings.NewReader(string(body)), h)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}}
}

func tokenMember(e *env, name, secret string) member {
	return member{name: name, do: func(method, path string, body []byte) (int, string) {
		req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			e.t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}}
}

func get(m member, path string, out any) int {
	code, body := m.do("GET", path, nil)
	if out != nil {
		_ = json.Unmarshal([]byte(body), out)
	}
	return code
}

func assetNames(t *testing.T, m member, query string) []string {
	t.Helper()
	var res struct{ Items []store.Asset }
	if code := get(m, "/api/v1/assets"+query, &res); code != 200 {
		t.Fatalf("%s: assets: %d", m.name, code)
	}
	var out []string
	for _, a := range res.Items {
		out = append(out, a.Name)
	}
	sort.Strings(out)
	return out
}

var betaTagged = regexp.MustCompile(`(?i)[a-z0-9_:.@-]*beta[a-z0-9_:.@-]*`)

// withoutBetaEchoes drops from resp the words naming Beta that the caller
// itself sent (a search term, a path), as whole words only: echoing "beta"
// does not hide "host-beta".
func withoutBetaEchoes(resp string, sent ...string) string {
	for _, s := range sent {
		for _, m := range betaTagged.FindAllString(s, -1) {
			word := regexp.MustCompile(`(?i)(^|[^a-z0-9_:.@-])` + regexp.QuoteMeta(m) + `($|[^a-z0-9_:.@-])`)
			resp = word.ReplaceAllString(resp, "$1$2")
		}
	}
	return resp
}

// restrictedMembers creates the members of Project Alpha the sweep uses,
// each with project access only and each through a different kind of
// grant, and returns them with a session, an API token and a session that
// asks for Project Beta in the switcher.
func (o *org) restrictedMembers(t *testing.T) []member {
	t.Helper()
	e := o.e
	alphaProject, alphaAsset := o.id("alpha-project"), o.id("alpha-asset")
	var out []member
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleEngineer, auth.RoleSecurity, auth.RoleAdmin} {
		email := "pa-" + string(role) + "@x.io"
		o.grant(t, email, alphaProject, 0, role)
		s := e.signIn(email)
		out = append(out, sessionMember("session:"+email, s, nil))
		out = append(out, sessionMember("session+beta-project:"+email, s, map[string]string{"X-Stackurity-Project": o.s("beta-project")}))
		var tok struct{ Secret string }
		if code := s.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": role}, &tok); code != 201 {
			t.Fatalf("token for %s: %d", email, code)
		}
		out = append(out, tokenMember(e, "token:"+email, tok.Secret))
	}
	// Through a team.
	if _, _, err := e.st.EnsureMember(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "team-member@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	userID := func(email string) int64 {
		var directory struct{ Items []store.User }
		o.admin.do("GET", "/api/v1/users", nil, &directory)
		for _, u := range directory.Items {
			if u.Email == email {
				return u.ID
			}
		}
		t.Fatalf("no user %s", email)
		return 0
	}
	var team store.Team
	if code := o.admin.do("POST", "/api/v1/teams", map[string]any{"name": "team-x", "members": []int64{userID("team-member@x.io")}}, &team); code != 201 {
		t.Fatalf("team: %d", code)
	}
	o.ids["team-x"] = team.ID
	var tg struct{ Grant store.Grant }
	if code := o.admin.do("POST", "/api/v1/access-grants", map[string]any{"project_id": alphaProject, "team_id": team.ID, "role": "engineer"}, &tg); code != 201 {
		t.Fatalf("team grant: %d", code)
	}
	out = append(out, sessionMember("session:team-member@x.io", e.signIn("team-member@x.io"), nil))
	// One asset only.
	o.grant(t, "asset-only@x.io", 0, alphaAsset, auth.RoleEngineer)
	out = append(out, sessionMember("session:asset-only@x.io", e.signIn("asset-only@x.io"), nil))
	// A grant on Beta, revoked.
	o.grant(t, "revoked@x.io", alphaProject, 0, auth.RoleViewer)
	g := o.grant(t, "revoked@x.io", o.id("beta-project"), 0, auth.RoleSecurity)
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/access-grants/%d", g.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	out = append(out, sessionMember("session:revoked@x.io", e.signIn("revoked@x.io"), nil))
	// An organisation admin downgraded to project access only.
	e.user("downgraded@x.io", auth.RoleAdmin)
	down := e.signIn("downgraded@x.io")
	if code := o.admin.do("PATCH", fmt.Sprintf("/api/v1/users/%d", userID("downgraded@x.io")), map[string]any{"role": "none"}, nil); code != 200 {
		t.Fatalf("downgrade: %d", code)
	}
	o.grant(t, "downgraded@x.io", alphaProject, 0, auth.RoleAdmin)
	out = append(out, sessionMember("session:downgraded@x.io", down, nil))
	// A grant on Beta's database through a project that was archived.
	o.grant(t, "archived@x.io", o.id("gamma-project"), 0, auth.RoleAdmin)
	o.grant(t, "archived@x.io", alphaProject, 0, auth.RoleViewer)
	if code := o.admin.do("PATCH", "/api/v1/projects/"+o.s("gamma-project"), map[string]any{"archived": true}, nil); code != 200 {
		t.Fatalf("archive: %d", code)
	}
	out = append(out, sessionMember("session:archived@x.io", e.signIn("archived@x.io"), nil))
	return out
}

// signIn opens a session for email without the sign-in endpoint, whose
// per-address limit the many members of these tests would reach.
func (e *env) signIn(email string) *session {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT id FROM users WHERE email = lower($1)`, email).Scan(&id); err != nil {
		e.t.Fatalf("sign in %s: %v", email, err)
	}
	secret, err := e.st.CreateSession(ctx, id, tenant.DefaultWorkspace)
	if err != nil {
		e.t.Fatal(err)
	}
	s := e.anon()
	u, _ := url.Parse(e.srv.URL)
	s.http.Jar.SetCookies(u, []*http.Cookie{{Name: "stackurity_session", Value: secret, Path: "/"}})
	return s
}

// betaFixture fills route parameters with Project Beta's objects.
func (o *org) betaFixture() *tenantFx {
	ids := map[string]string{"tag": "beta", "workspace": "1"}
	set := func(k, from string) { ids[k] = o.s(from) }
	set("asset", "beta-asset")
	set("asset2", "beta-asset2")
	set("component", "beta-component")
	set("finding", "beta-finding")
	set("incident", "beta-incident")
	set("collection", "beta-collection")
	set("project", "beta-project")
	set("grant", "beta-grant")
	set("team", "team-x")
	set("check", "beta-check")
	set("ignorerequest", "beta-ignorerequest")
	set("ignorerule", "beta-ignorerule")
	ids["fixgroup"] = o.fixGroup
	for _, k := range []string{"user", "job", "channel", "route", "delivery", "integration", "enrollment", "token", "conflict",
		"plan", "policy", "action", "collector-token"} {
		ids[k] = "999999999"
	}
	ids["secret"] = "BETA_TOKEN"
	return &tenantFx{tag: "beta", ws: tenant.DefaultWorkspace, ids: ids}
}

// betaSnapshot reads, as the organisation's admin, what a sweep could change.
func (o *org) betaSnapshot(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, p := range []string{
		"/api/v1/assets/{beta-asset}", "/api/v1/assets/{beta-asset2}", "/api/v1/assets/{beta-asset}/relations",
		"/api/v1/findings/{beta-finding}", "/api/v1/findings/{beta-finding}/events", "/api/v1/findings/{beta-db-finding}",
		"/api/v1/findings/{shared-finding}", "/api/v1/incidents/{beta-incident}", "/api/v1/projects/{beta-project}",
		"/api/v1/access-grants", "/api/v1/assets?project_id={beta-project}", "/api/v1/projects?archived=true",
		"/api/v1/checks/{beta-check}", "/api/v1/ignore-requests/{beta-ignorerequest}", "/api/v1/ignore-rules?status=all",
		"/api/v1/findings/{unfiled-finding}",
	} {
		path := regexp.MustCompile(`\{([a-z0-9-]+)\}`).ReplaceAllStringFunc(p, func(m string) string { return o.s(m[1 : len(m)-1]) })
		resp := o.admin.req("GET", path, nil, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Fprintf(&b, "%s %d %s\n", p, resp.StatusCode, normalise(string(body)))
	}
	return b.String()
}

// TestProjectIsolationSweep: for every route, every member of Project
// Alpha with project access only (each role, through a person, a team and
// an asset grant, a revoked and an archived grant, a downgraded admin, with
// sessions, API tokens and a session asking for Beta in the switcher) tries
// Project Beta's objects. They must never see, count, change or delete
// them, organisation routes must refuse them, and Beta's data must be
// unchanged afterwards.
func TestProjectIsolationSweep(t *testing.T) {
	o := newOrg(t)
	members := o.restrictedMembers(t)
	beta := o.betaFixture()
	before := o.betaSnapshot(t)
	routes := walkRoutes(t, o.e)
	sent := 0
	for _, r := range routes {
		rule, ok := routeRules[r]
		scope := projectScopes[r]
		if !ok || scope == "" || scope == "public" || rule.class == "skip" {
			continue
		}
		method, pattern, _ := strings.Cut(r, " ")
		path := rule.routePath(pattern, beta)
		var body []byte
		if rule.body != nil {
			body, _ = json.Marshal(rule.body(beta))
		}
		for _, m := range members {
			code, resp := m.do(method, path, body)
			sent++
			where := fmt.Sprintf("%s %s as %s", method, path, m.name)
			if code >= 500 {
				t.Errorf("%s: %d %s", where, code, resp)
			}
			if low := strings.ToLower(withoutBetaEchoes(resp, path, string(body))); strings.Contains(low, "beta") {
				t.Errorf("%s leaks Project Beta: %d %s", where, code, resp)
			}
			header := strings.HasPrefix(m.name, "session+beta-project:")
			switch {
			case scope == "org":
				if code != 403 {
					t.Errorf("%s: %d, want 403 for a member with project access only", where, code)
				}
			case header && (scope == "scoped" || scope == "scoped-write"):
				if code != 404 {
					t.Errorf("%s: %d, want 404 for a project the member cannot see", where, code)
				}
			case rule.class == "object" && scope != "account":
				if code < 300 && !rule.emptyOK {
					t.Errorf("%s: %d %s, want 4xx for another project's object", where, code, resp)
				}
				if code < 300 && rule.emptyOK && method == "GET" && strings.Contains(resp, `"id"`) {
					t.Errorf("%s: answered with objects: %s", where, resp)
				}
			}
		}
	}
	t.Logf("%d requests on %d routes by %d members of Project Alpha", sent, len(routes), len(members))
	if sent < 2000 {
		t.Errorf("only %d requests sent", sent)
	}
	if after := o.betaSnapshot(t); after != before {
		t.Errorf("Project Beta changed during the sweep:\nbefore %s\nafter  %s", before, after)
	}

	// What each of them does see: Alpha's host and the shared database,
	// or only the one asset they were granted.
	want := map[string][]string{
		"session:asset-only@x.io": {"host-alpha"},
	}
	for _, m := range members {
		if strings.HasPrefix(m.name, "session+") {
			continue
		}
		w, ok := want[m.name]
		if !ok {
			w = []string{"host-alpha", "shared-db"}
		}
		if got := assetNames(t, m, ""); strings.Join(got, ",") != strings.Join(w, ",") {
			t.Errorf("%s sees %v, want %v", m.name, got, w)
		}
	}
}

// TestProjectAccessRules checks the rules one by one: organisation roles see
// everything, the switcher narrows them, shared assets show in both
// projects, incidents spanning projects show only their own part, roles
// from grants apply per asset, and agents and collectors keep working.
func TestProjectAccessRules(t *testing.T) {
	o := newOrg(t)
	e := o.e
	ctx := context.Background()
	admin := sessionMember("admin", o.admin, nil)
	all := []string{"db-beta", "host-alpha", "host-beta", "shared-db", "unfiled-beta"}

	// Organisation-wide roles see every asset, with or without projects.
	e.user("org-viewer@x.io", auth.RoleViewer)
	viewer := sessionMember("org-viewer", e.signIn("org-viewer@x.io"), nil)
	for _, m := range []member{admin, viewer} {
		if got := assetNames(t, m, ""); strings.Join(got, ",") != strings.Join(all, ",") {
			t.Errorf("%s sees %v, want every asset", m.name, got)
		}
	}
	// The switcher narrows them to one project, by header or parameter.
	headed := sessionMember("admin+beta", o.admin, map[string]string{"X-Stackurity-Project": o.s("beta-project")})
	if got := assetNames(t, headed, ""); strings.Join(got, ",") != "db-beta,host-beta,shared-db" {
		t.Errorf("admin in Project Beta sees %v", got)
	}
	if got := assetNames(t, admin, "?project_id="+o.s("alpha-project")); strings.Join(got, ",") != "host-alpha,shared-db" {
		t.Errorf("admin with project_id=Alpha sees %v", got)
	}
	var fs struct {
		Items []store.Finding
		Total int64
	}
	get(headed, "/api/v1/findings?status=all", &fs)
	for _, f := range fs.Items {
		if f.AssetID == o.id("alpha-asset") || f.AssetID == o.id("unfiled-asset") {
			t.Errorf("admin in Project Beta sees finding %d of asset %d", f.ID, f.AssetID)
		}
	}
	if fs.Total != 3 {
		t.Errorf("admin in Project Beta: %d findings, want 3", fs.Total)
	}
	if code := get(sessionMember("bad", o.admin, map[string]string{"X-Stackurity-Project": "999999"}), "/api/v1/assets", nil); code != 404 {
		t.Errorf("unknown project: %d, want 404", code)
	}
	if code := get(sessionMember("bad", o.admin, map[string]string{"X-Stackurity-Project": "abc"}), "/api/v1/assets", nil); code != 400 {
		t.Errorf("invalid project: %d, want 400", code)
	}
	// Organisation routes ignore the switcher.
	if code := get(headed, "/api/v1/users", nil); code != 200 {
		t.Errorf("admin in a project lists users: %d", code)
	}
	// Assets in no project.
	if got := assetNames(t, admin, "?unfiled=true"); strings.Join(got, ",") != "unfiled-beta" {
		t.Errorf("unfiled: %v", got)
	}
	var projects struct {
		Items         []store.Project
		UnfiledAssets int64 `json:"unfiled_assets"`
	}
	get(admin, "/api/v1/projects", &projects)
	if projects.UnfiledAssets != 1 || len(projects.Items) != 3 {
		t.Errorf("projects: %+v", projects)
	}

	// A member of Alpha.
	o.grant(t, "alpha-viewer@x.io", o.id("alpha-project"), 0, auth.RoleViewer)
	g := o.grant(t, "alpha-engineer@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	av := sessionMember("alpha-viewer", e.signIn("alpha-viewer@x.io"), nil)
	ae := sessionMember("alpha-engineer", e.signIn("alpha-engineer@x.io"), nil)
	var me struct {
		Access   string          `json:"access"`
		Role     string          `json:"role"`
		Projects []store.Project `json:"projects"`
	}
	get(av, "/api/v1/auth/me", &me)
	if me.Access != "projects" || me.Role != "" || len(me.Projects) != 1 || me.Projects[0].Name != "Project Alpha" || me.Projects[0].Role != auth.RoleViewer {
		t.Errorf("me: %+v", me)
	}
	// The shared database shows in both projects.
	o.grant(t, "beta-only@x.io", o.id("beta-project"), 0, auth.RoleViewer)
	bv := sessionMember("beta-viewer", e.signIn("beta-only@x.io"), nil)
	if got := assetNames(t, bv, ""); strings.Join(got, ",") != "db-beta,host-beta,shared-db" {
		t.Errorf("Beta's viewer sees %v", got)
	}
	// The incident on both projects shows only Alpha's part to Alpha.
	var inc struct {
		Incident store.Incident
		Findings []store.Finding
	}
	if code := get(av, "/api/v1/incidents/"+o.s("shared-incident"), &inc); code != 200 {
		t.Fatalf("shared incident: %d", code)
	}
	var detail struct{ Assets []string }
	_ = json.Unmarshal(inc.Incident.Detail, &detail)
	if inc.Incident.FindingCount != 1 || inc.Incident.AssetCount != 1 || len(inc.Findings) != 1 || strings.Join(detail.Assets, ",") != "host-alpha" {
		t.Errorf("Alpha's view of the shared incident: %+v %s", inc.Incident, inc.Incident.Detail)
	}
	get(admin, "/api/v1/incidents/"+o.s("shared-incident"), &inc)
	if inc.Incident.FindingCount != 2 || inc.Incident.AssetCount != 2 {
		t.Errorf("admin's view of the shared incident: %+v", inc.Incident)
	}
	// Components in use count only what the member sees.
	var comps struct{ Items []store.Component }
	get(av, "/api/v1/components?q=bash", &comps)
	if len(comps.Items) != 1 || comps.Items[0].AssetCount != 1 {
		t.Errorf("Alpha's bash: %+v", comps.Items)
	}
	get(admin, "/api/v1/components?q=bash", &comps)
	if len(comps.Items) != 1 || comps.Items[0].AssetCount != 2 {
		t.Errorf("admin's bash: %+v", comps.Items)
	}

	// Roles from grants apply per asset.
	ack := func(m member, finding string) int {
		code, _ := m.do("POST", "/api/v1/findings/"+o.s(finding)+"/actions", []byte(`{"action":"acknowledge"}`))
		return code
	}
	if code := ack(av, "alpha-finding"); code != 403 {
		t.Errorf("Alpha's viewer acknowledges: %d, want 403", code)
	}
	if code := ack(ae, "alpha-finding"); code != 200 {
		t.Errorf("Alpha's engineer acknowledges: %d", code)
	}
	if code := ack(ae, "beta-finding"); code < 400 || code == 403 {
		t.Errorf("Alpha's engineer acknowledges Beta's finding: %d, want an answer that does not tell it exists", code)
	}
	// An incident action changes only the member's part of the incident.
	code, body := ae.do("POST", "/api/v1/incidents/"+o.s("shared-incident")+"/actions", []byte(`{"action":"start"}`))
	if code != 200 || !strings.Contains(body, `"applied":1`) {
		t.Errorf("incident action: %d %s", code, body)
	}
	var bf struct{ Finding store.Finding }
	get(admin, "/api/v1/findings/"+o.s("beta-finding"), &bf)
	if bf.Finding.State != "new" {
		t.Errorf("Beta's finding became %q through Alpha's incident action", bf.Finding.State)
	}
	// An organisation viewer with engineer on Alpha acts on Alpha only.
	e.user("mixed@x.io", auth.RoleViewer)
	o.grant(t, "mixed@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	mixed := sessionMember("mixed", e.signIn("mixed@x.io"), nil)
	if got := assetNames(t, mixed, ""); len(got) != len(all) {
		t.Errorf("mixed sees %v, want every asset", got)
	}
	if code := ack(mixed, "beta-db-finding"); code != 403 {
		t.Errorf("mixed acknowledges Beta's finding: %d, want 403", code)
	}
	if code := ack(mixed, "shared-finding"); code != 200 {
		t.Errorf("mixed acknowledges the shared database's finding: %d", code)
	}
	code, _ = mixed.do("PATCH", "/api/v1/assets/"+o.s("beta-asset"), []byte(`{"environment":"x"}`))
	if code != 403 {
		t.Errorf("mixed changes Beta's asset: %d, want 403", code)
	}
	// Downgrading the grant takes the right away at once.
	if code := o.admin.do("PATCH", fmt.Sprintf("/api/v1/access-grants/%d", g.ID), map[string]any{"role": "viewer"}, nil); code != 200 {
		t.Fatalf("downgrade grant: %d", code)
	}
	if code := ack(ae, "shared-finding"); code != 403 {
		t.Errorf("downgraded engineer acknowledges: %d, want 403", code)
	}
	// A token never acts above its member's grant, and follows it.
	o.grant(t, "token-user@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	ts := e.signIn("token-user@x.io")
	var tok struct{ Secret string }
	if code := ts.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "admin"}, nil); code != 403 {
		t.Errorf("token above the grant: %d, want 403", code)
	}
	if code := ts.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "engineer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	tm := tokenMember(e, "token-user-token", tok.Secret)
	if got := assetNames(t, tm, ""); strings.Join(got, ",") != "host-alpha,shared-db" {
		t.Errorf("member's token sees %v", got)
	}
	if code := ack(tm, "alpha-finding"); code != 200 {
		t.Errorf("member's token acknowledges: %d", code)
	}
	// Leaving the team removes what the team was granted.
	if _, _, err := e.st.EnsureMember(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), "teamed@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	var users struct{ Items []store.User }
	o.admin.do("GET", "/api/v1/users", nil, &users)
	var teamedID int64
	for _, u := range users.Items {
		if u.Email == "teamed@x.io" {
			teamedID = u.ID
			if u.Access != "projects" || u.Role != "" {
				t.Errorf("project-only member in the user list: %+v", u)
			}
		}
	}
	var team store.Team
	o.admin.do("POST", "/api/v1/teams", map[string]any{"name": "team-y", "members": []int64{teamedID}}, &team)
	o.admin.do("POST", "/api/v1/access-grants", map[string]any{"project_id": o.id("beta-project"), "team_id": team.ID, "role": "viewer"}, nil)
	teamed := sessionMember("teamed", e.signIn("teamed@x.io"), nil)
	if got := assetNames(t, teamed, ""); len(got) != 3 {
		t.Errorf("team member sees %v", got)
	}
	o.admin.do("PATCH", fmt.Sprintf("/api/v1/teams/%d", team.ID), map[string]any{"members": []int64{}}, nil)
	var left struct{ Items []store.Asset }
	if code := get(teamed, "/api/v1/assets", &left); code != 403 && (code != 200 || len(left.Items) != 0) {
		t.Errorf("after leaving the team: %d %v", code, left.Items)
	}

	// Removing someone from the organisation removes their grants.
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d", teamedID), nil, nil); code != 204 {
		t.Fatalf("remove member: %d", code)
	}
	var tokenUser int64
	o.admin.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users.Items {
		if u.Email == "token-user@x.io" {
			tokenUser = u.ID
		}
	}
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d", tokenUser), nil, nil); code != 204 {
		t.Fatalf("remove member: %d", code)
	}
	var left2 struct{ Items []store.Grant }
	o.admin.do("GET", fmt.Sprintf("/api/v1/access-grants?user_id=%d", tokenUser), nil, &left2)
	if len(left2.Items) != 0 {
		t.Errorf("grants of a removed member: %+v", left2.Items)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 401 {
		t.Errorf("removed member's token: %d, want 401", code)
	}

	// Agents and collectors are bound to the workspace and keep working.
	if code := bearer(e, o.agent, "GET", "/api/v1/agent/actions", nil, nil); code != 200 {
		t.Errorf("agent token: %d", code)
	}
	o.ingest(t, "host-alpha", "alpha-m1", "prod-alpha", "pkg:npm/alpha-private-lib@1.0.1")

	// Ignore rules and the approval inbox (0.7). A member with security on
	// Alpha may ignore Alpha's issues on their asset, but not on every
	// asset of the organisation, and decides only Alpha's requests.
	o.grant(t, "alpha-sec@x.io", o.id("alpha-project"), 0, auth.RoleSecurity)
	sec := sessionMember("alpha-sec", e.signIn("alpha-sec@x.io"), nil)
	ignore := func(m member, finding, scope string) (int, string) {
		return m.do("POST", "/api/v1/findings/"+o.s(finding)+"/actions",
			[]byte(`{"action":"ignore","reason":"false_positive","note":"n","scope":"`+scope+`","expiry":"never"}`))
	}
	if code, body := ignore(sec, "alpha-finding", "everywhere"); code != 403 {
		t.Errorf("project security ignores everywhere: %d %s", code, body)
	}
	if code, body := ignore(sec, "alpha-finding", "asset"); code != 200 {
		t.Errorf("project security ignores on the asset: %d %s", code, body)
	}
	// An organisation admin ignores Beta's issue everywhere: it covers no
	// finding Alpha's members can see, so they do not see the rule.
	if code, body := ignore(admin, "beta-finding", "everywhere"); code != 200 {
		t.Fatalf("admin ignores everywhere: %d %s", code, body)
	}
	var rules struct{ Items []store.IgnoreRule }
	o.admin.do("GET", "/api/v1/ignore-rules", nil, &rules)
	var betaRule int64
	for _, r := range rules.Items {
		if r.Scope == "everywhere" && r.Key == "CVE-2099-0001" {
			betaRule = r.ID
		}
	}
	code, body = sec.do("GET", "/api/v1/ignore-rules?status=all", nil)
	if code != 200 || strings.Contains(body, fmt.Sprintf(`"id":%d,`, betaRule)) || strings.Contains(strings.ToLower(body), "beta") {
		t.Errorf("Alpha's view of ignore rules: %d %s", code, body)
	}
	if code, _ := sec.do("DELETE", fmt.Sprintf("/api/v1/ignore-rules/%d", betaRule), nil); code != 404 {
		t.Errorf("project security ends a rule it cannot see: %d, want 404", code)
	}
	// A rule for every asset that covers a visible finding is shown, with
	// only the member's findings counted, and only the organisation ends it.
	if code, body := ignore(admin, "shared-finding", "everywhere"); code != 200 {
		t.Fatalf("admin ignores the shared database's issue everywhere: %d %s", code, body)
	}
	var mine struct{ Items []store.IgnoreRule }
	get(sec, "/api/v1/ignore-rules", &mine)
	var sharedRule *store.IgnoreRule
	for i, r := range mine.Items {
		if r.Scope == "everywhere" {
			sharedRule = &mine.Items[i]
		}
	}
	if sharedRule == nil || sharedRule.Findings != 1 {
		t.Fatalf("Alpha's view of the rule on the shared database: %+v", mine.Items)
	}
	if code, _ := sec.do("DELETE", fmt.Sprintf("/api/v1/ignore-rules/%d", sharedRule.ID), nil); code != 403 {
		t.Errorf("project security ends a rule for every asset: %d, want 403", code)
	}
	// The inbox: Beta's request is not Alpha's to see or decide.
	var inbox struct {
		Items     []store.IgnoreRequest
		CanDecide bool `json:"can_decide"`
	}
	get(sec, "/api/v1/ignore-requests?status=all", &inbox)
	if !inbox.CanDecide || len(inbox.Items) != 0 {
		t.Errorf("Alpha's inbox: %+v", inbox)
	}
	if code, _ := sec.do("POST", "/api/v1/ignore-requests/"+o.s("beta-ignorerequest")+"/decision", []byte(`{"decision":"approve"}`)); code != 404 {
		t.Errorf("project security decides Beta's request: %d, want 404", code)
	}
	// An organisation viewer with security on Alpha sees every request but
	// may decide only Alpha's.
	o.grant(t, "mixed@x.io", o.id("alpha-project"), 0, auth.RoleSecurity)
	get(mixed, "/api/v1/ignore-requests?status=all", &inbox)
	if len(inbox.Items) != 0 {
		t.Errorf("mixed's inbox lists requests outside Alpha: %+v", inbox.Items)
	}
	if code, _ := mixed.do("POST", "/api/v1/ignore-requests/"+o.s("beta-ignorerequest")+"/decision", []byte(`{"decision":"decline"}`)); code != 403 {
		t.Errorf("mixed decides Beta's request: %d, want 403", code)
	}
	// Checks follow the asset.
	if code, _ := sec.do("POST", "/api/v1/assets/"+o.s("beta-asset")+"/check", nil); code != 404 {
		t.Errorf("project member checks Beta's asset: %d, want 404", code)
	}
	if code, _ := av.do("POST", "/api/v1/assets/"+o.s("alpha-asset")+"/check", nil); code != 403 {
		t.Errorf("Alpha's viewer checks: %d, want 403", code)
	}
	if code, _ := sec.do("POST", "/api/v1/assets/"+o.s("alpha-asset")+"/check", nil); code != 201 && code != 200 {
		t.Errorf("Alpha's security member checks Alpha's asset: %d", code)
	}

	// The evidence report follows the switcher (licensed build).
	if api.BuildEdition == "ee" {
		var rep struct {
			Assets struct{ Total int64 } `json:"assets"`
		}
		if code := get(admin, "/api/v1/reports/evidence?project_id="+o.s("alpha-project"), &rep); code != 200 || rep.Assets.Total != 2 {
			t.Errorf("evidence report for Alpha: %d %+v", code, rep)
		}
	}
}

// TestProjectScopeInDatabase checks the second lock on its own: a
// connection narrowed to a member reads no row of another project's
// assets from any table, whatever the query asks for.
func TestProjectScopeInDatabase(t *testing.T) {
	o := newOrg(t)
	o.grant(t, "db-member@x.io", o.id("alpha-project"), 0, auth.RoleViewer)
	var users struct{ Items []store.User }
	o.admin.do("GET", "/api/v1/users", nil, &users)
	var uid int64
	for _, u := range users.Items {
		if u.Email == "db-member@x.io" {
			uid = u.ID
		}
	}
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	member := tenant.WithMember(ws, uid)
	hidden := []int64{o.id("beta-asset"), o.id("beta-asset2"), o.id("unfiled-asset")}
	pool := o.e.st.Pool
	var tables []string
	rows, err := pool.Query(tenant.System(context.Background()), `SELECT table_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND column_name = 'asset_id' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) < 8 {
		t.Fatalf("tables with asset_id: %v", tables)
	}
	for _, tbl := range tables {
		switch tbl {
		case "api_tokens", "integrations", "access_grants", "project_assets":
			continue // organisation administration; their routes refuse members
		}
		var n int
		if err := pool.QueryRow(member, `SELECT count(*) FROM `+tbl+` WHERE asset_id = ANY($1)`, hidden).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("%s: a member of Alpha reads %d rows of other assets", tbl, n)
		}
		var all int
		if err := pool.QueryRow(ws, `SELECT count(*) FROM `+tbl+` WHERE asset_id = ANY($1)`, hidden).Scan(&all); err != nil {
			t.Fatal(err)
		}
		_ = all
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM assets`:                                                                                         2,
		`SELECT count(*) FROM components WHERE name LIKE '%beta%'`:                                                            0,
		`SELECT count(*) FROM incidents WHERE id = ` + o.s("beta-incident"):                                                   0,
		`SELECT count(*) FROM finding_events WHERE note = 'note-beta'`:                                                        0,
		`SELECT count(*) FROM coverage_history WHERE collection_id = ` + o.s("beta-collection"):                               0,
		`SELECT count(*) FROM asset_relations`:                                                                                0,
		`SELECT count(*) FROM projects`:                                                                                       1,
		`SELECT count(*) FROM audit_events WHERE object_type = 'project'`:                                                     0,
		`SELECT count(*) FROM fix_groups WHERE asset_id <> ` + o.s("alpha-asset") + ` AND asset_id <> ` + o.s("shared-asset"): 0,
	} {
		var n int
		if err := pool.QueryRow(member, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if n != want {
			t.Errorf("%s as a member of Alpha: %d, want %d", q, n, want)
		}
	}
	// Writes are narrowed too.
	tag, err := pool.Exec(member, `UPDATE findings SET state = 'acknowledged' WHERE asset_id = ANY($1)`, hidden)
	if err != nil || tag.RowsAffected() != 0 {
		t.Errorf("a member of Alpha updated %d findings of other assets (%v)", tag.RowsAffected(), err)
	}
	if _, err := pool.Exec(member, `INSERT INTO asset_relations (from_asset, to_asset, kind) VALUES ($1, $2, 'depends_on')`,
		o.id("alpha-asset"), o.id("beta-asset")); err == nil {
		t.Error("a member of Alpha related its host to Beta's")
	}
	// Nor can it create an ignore rule for every asset (0.7).
	if _, err := pool.Exec(member, `INSERT INTO finding_exceptions (kind, key, component_id, reason)
		SELECT 'vulnerability', 'CVE-2099-0001', component_id, 'accepted_risk' FROM findings WHERE id = $1`, o.id("alpha-finding")); err == nil {
		t.Error("a member of Alpha created an ignore rule for every asset")
	}
	// Choosing a project narrows an organisation-wide connection the same way.
	var n int
	if err := pool.QueryRow(tenant.WithProject(ws, o.id("alpha-project")), `SELECT count(*) FROM findings`).Scan(&n); err != nil || n != 2 {
		t.Errorf("findings in Project Alpha: %d (%v), want 2", n, err)
	}
}

// TestProjectMCP runs the assistant tools with a member's token: they go
// through the API, so they never return another project's data.
func TestProjectMCP(t *testing.T) {
	o := newOrg(t)
	o.grant(t, "mcp-user@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	s := o.e.signIn("mcp-user@x.io")
	var tok struct{ Secret string }
	if code := s.do("POST", "/api/v1/tokens", map[string]any{"name": "mcp", "role": "viewer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	cl, err := client.New(o.e.srv.URL, tok.Secret, "test")
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"query": "beta", "asset_id": o.id("beta-asset"), "finding_id": o.id("beta-finding"),
		"component_id": o.id("beta-component"), "name": "beta-private-lib", "since": "2000-01-01"}
	plain := map[string]any{"since": "2000-01-01"}
	var lines []string
	n := 1
	add := func(name string, a map[string]any) {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": map[string]any{"name": name, "arguments": a}})
		lines = append(lines, string(b))
		n++
	}
	tools := []string{"search", "list_assets", "action_plan", "asset_stack", "list_findings", "get_finding", "find_component",
		"explain_finding", "upgrade_recommendation", "remediation_plan", "verify_since"}
	for _, name := range tools {
		add(name, args)
		add(name, plain)
	}
	var out strings.Builder
	srv := &mcp.Server{API: cl, Version: "test"}
	if err := srv.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	res := out.String()
	if strings.Count(res, `"jsonrpc"`) != len(lines) {
		t.Fatalf("answers: %s", res)
	}
	if low := strings.ToLower(withoutBetaEchoes(res, "beta-private-lib", "beta")); strings.Contains(low, "beta") {
		t.Errorf("MCP tools leak Project Beta: %s", res)
	}
	if !strings.Contains(res, "host-alpha") {
		t.Errorf("MCP tools do not show the member's own assets: %s", res)
	}
}

// TestProjectSuggestions: related assets are proposed for a project, never
// added by themselves; a dismissed suggestion stays away.
func TestProjectSuggestions(t *testing.T) {
	o := newOrg(t)
	app := o.ingest(t, "billing-app", "app-m1", "prod", "pkg:npm/billing@1.0.0")
	host := o.ingest(t, "billing-host", "app-m2", "prod", "pkg:deb/debian/bash@5.2")
	rel := func(from, to int64, kind string) {
		if code := o.admin.do("POST", fmt.Sprintf("/api/v1/assets/%d/relations", from), map[string]any{"to_asset": to, "kind": kind}, nil); code != 204 {
			t.Fatalf("relation: %d", code)
		}
	}
	rel(app.AssetID, host.AssetID, "runs_on")
	rel(o.id("unfiled-asset"), o.id("alpha-asset"), "built_from")
	type suggestion struct {
		Key           string `json:"key"`
		ProjectID     int64  `json:"project_id"`
		SuggestedName string `json:"suggested_name"`
		Assets        []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"assets"`
	}
	list := func() []suggestion {
		var res struct{ Items []suggestion }
		if code := o.admin.do("GET", "/api/v1/project-suggestions", nil, &res); code != 200 {
			t.Fatalf("suggestions: %d", code)
		}
		return res.Items
	}
	got := list()
	if len(got) != 2 || got[0].ProjectID != o.id("alpha-project") || len(got[0].Assets) != 1 || got[0].Assets[0].Name != "unfiled-beta" ||
		got[1].ProjectID != 0 || len(got[1].Assets) != 2 {
		t.Fatalf("suggestions: %+v", got)
	}
	// Nothing was filed by itself.
	if names := assetNames(t, sessionMember("admin", o.admin, nil), "?unfiled=true"); len(names) != 3 {
		t.Errorf("unfiled after suggesting: %v", names)
	}
	// Accepting is adding the assets; dismissing hides the other one.
	if code := o.admin.do("POST", "/api/v1/projects/"+o.s("alpha-project")+"/assets", map[string]any{"asset_ids": []int64{o.id("unfiled-asset")}}, nil); code != 200 {
		t.Fatalf("accept: %d", code)
	}
	if code := o.admin.do("POST", "/api/v1/project-suggestions/dismiss", map[string]any{"key": got[1].Key}, nil); code != 204 {
		t.Fatalf("dismiss: %d", code)
	}
	if got := list(); len(got) != 0 {
		t.Errorf("after accepting and dismissing: %+v", got)
	}
	// Every change is audited.
	var audit struct{ Items []store.AuditEvent }
	o.admin.do("GET", "/api/v1/audit?object_type=project&object_id="+o.s("alpha-project"), nil, &audit)
	actions := map[string]bool{}
	for _, ev := range audit.Items {
		actions[ev.Action] = true
	}
	if !actions["project.create"] || !actions["project.assets_add"] {
		t.Errorf("audit of Project Alpha: %v", actions)
	}
	// Routes to Jira cannot be limited to projects.
	var ch store.Channel
	if code := o.admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "jira",
		"config": map[string]any{"base_url": "https://x.atlassian.net", "email": "a@x.io", "project": "SEC"}, "secret_ref": "env:X"}, &ch); code == 201 {
		if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "j", "channel_id": ch.ID, "enabled": true,
			"project_ids": []int64{o.id("alpha-project")}}, nil); code != 400 {
			t.Errorf("Jira route limited to a project: %d, want 400", code)
		}
	}
	var hook store.Channel
	if code := o.admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "hook",
		"config": map[string]string{"url": "https://hooks.example/x"}}, &hook); code != 201 {
		t.Fatalf("channel: %d", code)
	}
	if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "r", "channel_id": hook.ID, "enabled": true,
		"project_ids": []int64{999999}}, nil); code != 400 {
		t.Errorf("route with an unknown project: %d, want 400", code)
	}
	var rt store.Route
	if code := o.admin.do("POST", "/api/v1/routes", map[string]any{"name": "r", "channel_id": hook.ID, "enabled": true,
		"project_ids": []int64{o.id("alpha-project")}}, &rt); code != 201 || len(rt.ProjectIDs) != 1 {
		t.Errorf("route limited to Project Alpha: %d %+v", code, rt)
	}
}
