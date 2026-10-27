package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The isolation sweep walks every route the router serves. Each route must
// be classified below; a new route without a rule fails the sweep, so no
// endpoint can skip the cross-workspace checks by being forgotten.
//
// Classes:
//
//	public    no credentials needed; GETs are sent and must not leak tenant data
//	account   the caller's own account; GETs are sent
//	global    data shared by every workspace (feeds, advisories, packs, plugins)
//	instance  instance administrators only: every workspace principal gets 403
//	list      a workspace listing or aggregate: B sees nothing of A's, and its
//	          answer is identical whether or not A has any data
//	object    names one of A's objects by id: B gets 4xx (or, with emptyOK, an
//	          empty answer), and A's data is unchanged afterwards
//	create    creates in the caller's workspace; sent with references to A's
//	          objects, must not leak or change A
//	skip      not sent (it would end the caller's session or change their
//	          password); covered by dedicated tests
type routeRule struct {
	class   string
	obj     map[string]string // chi parameter -> fixture key whose A value fills it
	query   string            // appended to the path; {key} is filled from A's fixture
	body    func(a *tenantFx) any
	emptyOK bool   // object routes that answer an empty 200 for ids they cannot see
	edition string // "ee": only registered in the licensed build
}

func id(k string) map[string]string { return map[string]string{"id": k} }

var routeRules = map[string]routeRule{
	// Unauthenticated and account endpoints.
	"GET /healthz":                   {class: "public"},
	"GET /readyz":                    {class: "public"},
	"GET /install/agent.sh":          {class: "public"},
	"GET /download/agent/{platform}": {class: "public"},
	"GET /api/v1/meta":               {class: "public"},
	"POST /api/v1/setup":             {class: "skip"},
	"POST /api/v1/auth/login":        {class: "skip"},
	"POST /api/v1/auth/logout":       {class: "skip"},
	"POST /api/v1/enroll":            {class: "public"},
	// Following an invitation link: a token B does not have is refused
	// without saying why; accepting is tested in onboarding_test.go.
	"POST /api/v1/invitations/preview": {class: "public", body: func(*tenantFx) any { return map[string]string{"token": "inv_guessed"} }},
	"POST /api/v1/invitations/accept": {class: "public", body: func(*tenantFx) any {
		return map[string]string{"token": "inv_guessed", "password": pw}
	}},
	"GET /api/v1/auth/oidc/login":           {class: "skip", edition: "ee"},
	"GET /api/v1/auth/oidc/callback":        {class: "skip", edition: "ee"},
	"GET /api/v1/auth/me":                   {class: "account"},
	"POST /api/v1/auth/password":            {class: "skip"},
	"GET /api/v1/workspaces":                {class: "account"},
	"POST /api/v1/workspaces/{id}/activate": {class: "object", obj: id("workspace")},
	// Choosing another workspace's project as the default must fail.
	"PUT /api/v1/auth/default-project": {class: "create", body: func(a *tenantFx) any { return map[string]any{"project_id": a.int("project")} }},

	// Sends what the user typed to the feedback URL outside the
	// installation, nothing of the workspace; see feedback_test.go.
	"POST /api/v1/feedback": {class: "skip"},

	// Shared by every workspace.
	"GET /api/v1/packs":                 {class: "global"},
	"GET /api/v1/packs/{id}/archive":    {class: "global"},
	"GET /api/v1/feeds":                 {class: "global"},
	"POST /api/v1/feeds/{name}/refresh": {class: "global"},
	"GET /api/v1/advisories/{key}":      {class: "global"},
	"GET /api/v1/plugins":               {class: "global"},

	// Instance administration.
	"GET /api/v1/admin/license/":             {class: "instance"},
	"PUT /api/v1/admin/license/":             {class: "instance"},
	"DELETE /api/v1/admin/license/":          {class: "instance"},
	"GET /api/v1/admin/packs/":               {class: "instance"},
	"POST /api/v1/admin/packs/install":       {class: "instance"},
	"POST /api/v1/admin/packs/upload":        {class: "instance"},
	"PATCH /api/v1/admin/packs/{id}":         {class: "instance"},
	"POST /api/v1/admin/packs/{id}/rollback": {class: "instance"},
	"DELETE /api/v1/admin/packs/{id}":        {class: "instance"},
	"GET /api/v1/admin/health":               {class: "instance"},
	"GET /api/v1/updates":                    {class: "instance"},
	"GET /api/v1/admin/workspaces/":          {class: "instance"},
	"POST /api/v1/admin/workspaces/":         {class: "instance"},
	"PATCH /api/v1/admin/workspaces/{id}":    {class: "instance", obj: id("workspace")},
	"PATCH /api/v1/feeds/{name}":             {class: "instance"},

	// Collectors and agents.
	"POST /api/v1/ingest":                 {class: "create", body: func(a *tenantFx) any { return a.claimBatch() }},
	"GET /api/v1/collections/{id}/result": {class: "object", obj: id("collection")},
	"POST /api/v1/sbom/import": {class: "create", query: "?asset_name=host-{tag}", body: func(*tenantFx) any {
		return json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	}},
	"GET /api/v1/agent/actions":              {class: "list"},
	"GET /api/v1/agent/check":                {class: "list", query: "?asset_id={asset}&asset_id={asset2}"},
	"POST /api/v1/agent/actions/{id}/report": {class: "object", obj: id("action"), edition: "ee", body: func(*tenantFx) any { return map[string]any{"phase": "failed", "error": "x"} }},
	"GET /api/v1/remediation/renovate.json":  {class: "list"},

	// Workspace listings and aggregates.
	"GET /api/v1/overview":             {class: "list"},
	"GET /api/v1/facets":               {class: "list"},
	"GET /api/v1/search":               {class: "list", query: "?q={tag}"},
	"GET /api/v1/assets":               {class: "list"},
	"GET /api/v1/components":           {class: "list", query: "?q={tag}"},
	"GET /api/v1/findings":             {class: "list", query: "?status=all&asset_id={asset}"},
	"GET /api/v1/findings/summary":     {class: "list"},
	"GET /api/v1/findings/verify":      {class: "list", query: "?since=2000-01-01&asset_id={asset}"},
	"GET /api/v1/fix-groups":           {class: "list", query: "?asset_id={asset}"},
	"GET /api/v1/fix-groups/summary":   {class: "list", query: "?asset_id={asset}"},
	"GET /api/v1/evaluation-gaps":      {class: "list"},
	"GET /api/v1/second-checks":        {class: "list"},
	"GET /api/v1/reports/outcomes":     {class: "list"},
	"GET /api/v1/reports/evidence":     {class: "list"},
	"GET /api/v1/incidents":            {class: "list", query: "?status=all&team_id={team}"},
	"GET /api/v1/risk-policy":          {class: "list"},
	"GET /api/v1/inventory":            {class: "list", query: "?asset_id={asset}"},
	"GET /api/v1/coverage":             {class: "list", query: "?asset_id={asset}"},
	"GET /api/v1/teams":                {class: "list"},
	"GET /api/v1/audit":                {class: "list", query: "?object_type=asset&object_id={asset}"},
	"GET /api/v1/tokens":               {class: "list"},
	"GET /api/v1/remediation/plans":    {class: "list"},
	"GET /api/v1/integrations":         {class: "list"},
	"GET /api/v1/users/directory":      {class: "list"},
	"GET /api/v1/deliveries":           {class: "list", query: "?channel_id={channel}&incident_id={incident}"},
	"GET /api/v1/channels":             {class: "list"},
	"GET /api/v1/routes":               {class: "list"},
	"GET /api/v1/remediation/policies": {class: "list"},
	"GET /api/v1/conflicts":            {class: "list"},
	"GET /api/v1/users":                {class: "list"},
	"GET /api/v1/jobs":                 {class: "list"},
	"GET /api/v1/secrets":              {class: "list"},
	"GET /api/v1/enrollments":          {class: "list"},
	"GET /api/v1/checks":               {class: "list", query: "?asset_id={asset}"},
	"GET /api/v1/ignore-rules":         {class: "list", query: "?status=all"},
	"GET /api/v1/ignore-requests":      {class: "list", query: "?status=all"},
	"GET /api/v1/projects":             {class: "list"},
	"GET /api/v1/project-suggestions":  {class: "list"},
	"GET /api/v1/access-grants":        {class: "list", query: "?project_id={project}"},
	"GET /api/v1/onboarding":           {class: "list"},
	"GET /api/v1/onboarding/results":   {class: "list", query: "?since=2000-01-01T00:00:00Z"},
	"GET /api/v1/invitations":          {class: "list", query: "?project_id={project}"},
	"GET /api/v1/usage":                {class: "list"},

	// A's objects by id.
	"GET /api/v1/assets/{id}":                      {class: "object", obj: id("asset")},
	"GET /api/v1/assets/{id}/inventory":            {class: "object", obj: id("asset"), emptyOK: true},
	"GET /api/v1/assets/{id}/coverage":             {class: "object", obj: id("asset"), emptyOK: true},
	"GET /api/v1/assets/{id}/coverage-summary":     {class: "object", obj: id("asset")},
	"GET /api/v1/assets/{id}/collections":          {class: "object", obj: id("asset"), emptyOK: true},
	"GET /api/v1/assets/{id}/relations":            {class: "object", obj: id("asset"), emptyOK: true},
	"GET /api/v1/assets/{id}/drift":                {class: "object", obj: id("asset")},
	"GET /api/v1/assets/{id}/stack":                {class: "object", obj: id("asset")},
	"GET /api/v1/assets/{id}/sbom":                 {class: "object", obj: id("asset")},
	"GET /api/v1/assets/{id}/remediation":          {class: "object", obj: id("asset"), emptyOK: true},
	"GET /api/v1/components/{id}":                  {class: "object", obj: id("component")},
	"GET /api/v1/components/{id}/intel":            {class: "object", obj: id("component")},
	"GET /api/v1/components/{id}/upgrade":          {class: "object", obj: id("component")},
	"GET /api/v1/fix-groups/{id}":                  {class: "object", obj: id("fixgroup")},
	"GET /api/v1/findings/{id}":                    {class: "object", obj: id("finding")},
	"GET /api/v1/findings/{id}/events":             {class: "object", obj: id("finding"), emptyOK: true},
	"GET /api/v1/findings/{id}/upgrade":            {class: "object", obj: id("finding")},
	"GET /api/v1/findings/{id}/explain":            {class: "object", obj: id("finding")},
	"GET /api/v1/incidents/{id}":                   {class: "object", obj: id("incident")},
	"GET /api/v1/jobs/{id}":                        {class: "object", obj: id("job")},
	"GET /api/v1/remediation/plans/{id}":           {class: "object", obj: id("plan"), edition: "ee"},
	"PATCH /api/v1/assets/{id}":                    {class: "object", obj: id("asset"), body: func(*tenantFx) any { return map[string]any{"environment": "hacked"} }},
	"POST /api/v1/assets/{id}/relations":           {class: "object", obj: id("asset"), body: func(a *tenantFx) any { return map[string]any{"to_asset": a.int("asset2"), "kind": "depends_on"} }},
	"DELETE /api/v1/assets/{id}/relations":         {class: "object", obj: id("asset"), emptyOK: true, body: func(a *tenantFx) any { return map[string]any{"to_asset": a.int("asset2"), "kind": "depends_on"} }},
	"DELETE /api/v1/assets/{id}":                   {class: "object", obj: id("asset")},
	"POST /api/v1/assets/{id}/remediation-token":   {class: "object", obj: id("asset")},
	"POST /api/v1/integrations/{id}/run":           {class: "object", obj: id("integration")},
	"PATCH /api/v1/integrations/{id}":              {class: "object", obj: id("integration"), body: func(*tenantFx) any { return map[string]any{"enabled": false} }},
	"DELETE /api/v1/integrations/{id}":             {class: "object", obj: id("integration")},
	"POST /api/v1/findings/{id}/actions":           {class: "object", obj: id("finding"), body: func(*tenantFx) any { return map[string]any{"action": "acknowledge"} }},
	"POST /api/v1/incidents/{id}/actions":          {class: "object", obj: id("incident"), body: func(*tenantFx) any { return map[string]any{"action": "acknowledge"} }},
	"POST /api/v1/conflicts/{id}/resolve":          {class: "object", obj: id("conflict"), body: func(a *tenantFx) any { return map[string]any{"target_asset_id": a.int("asset2")} }},
	"GET /api/v1/checks/{id}":                      {class: "object", obj: id("check")},
	"POST /api/v1/assets/{id}/check":               {class: "object", obj: id("asset")},
	"POST /api/v1/fix-groups/{id}/check":           {class: "object", obj: id("fixgroup")},
	"POST /api/v1/fix-groups/{id}/applied":         {class: "object", obj: id("fixgroup")},
	"DELETE /api/v1/ignore-rules/{id}":             {class: "object", obj: id("ignorerule")},
	"GET /api/v1/ignore-requests/{id}":             {class: "object", obj: id("ignorerequest")},
	"POST /api/v1/ignore-requests/{id}/decision":   {class: "object", obj: id("ignorerequest"), body: func(*tenantFx) any { return map[string]any{"decision": "approve"} }},
	"PATCH /api/v1/users/{id}":                     {class: "object", obj: id("user"), body: func(*tenantFx) any { return map[string]any{"role": "viewer"} }},
	"DELETE /api/v1/users/{id}":                    {class: "object", obj: id("user")},
	"PATCH /api/v1/teams/{id}":                     {class: "object", obj: id("team"), body: func(*tenantFx) any { return map[string]any{"name": "hacked"} }},
	"DELETE /api/v1/teams/{id}":                    {class: "object", obj: id("team")},
	"PATCH /api/v1/channels/{id}":                  {class: "object", obj: id("channel"), body: func(*tenantFx) any { return map[string]any{"enabled": false} }},
	"DELETE /api/v1/channels/{id}":                 {class: "object", obj: id("channel")},
	"POST /api/v1/channels/{id}/test":              {class: "object", obj: id("channel")},
	"PUT /api/v1/routes/{id}":                      {class: "object", obj: id("route"), body: func(a *tenantFx) any { return map[string]any{"name": "hacked", "channel_id": a.int("channel")} }},
	"DELETE /api/v1/routes/{id}":                   {class: "object", obj: id("route")},
	"POST /api/v1/deliveries/{id}/retry":           {class: "object", obj: id("delivery")},
	"DELETE /api/v1/tokens/{id}":                   {class: "object", obj: id("token")},
	"DELETE /api/v1/enrollments/{id}":              {class: "object", obj: id("enrollment")},
	"POST /api/v1/remediation/plans/{id}/decision": {class: "object", obj: id("plan"), body: func(*tenantFx) any { return map[string]any{"decision": "approve"} }},
	"PUT /api/v1/remediation/policies/{id}":        {class: "object", obj: id("policy"), edition: "ee", body: func(*tenantFx) any { return map[string]any{"name": "hacked"} }},
	"DELETE /api/v1/remediation/policies/{id}":     {class: "object", obj: id("policy"), edition: "ee"},
	"GET /api/v1/projects/{id}":                    {class: "object", obj: id("project")},
	"PATCH /api/v1/projects/{id}":                  {class: "object", obj: id("project"), body: func(*tenantFx) any { return map[string]any{"name": "hacked"} }},
	"POST /api/v1/projects/{id}/assets":            {class: "object", obj: id("project"), body: func(a *tenantFx) any { return map[string]any{"asset_ids": []int64{a.int("asset2")}} }},
	"DELETE /api/v1/projects/{id}/assets":          {class: "object", obj: id("project"), body: func(a *tenantFx) any { return map[string]any{"asset_ids": []int64{a.int("asset")}} }},
	"PATCH /api/v1/access-grants/{id}":             {class: "object", obj: id("grant"), body: func(*tenantFx) any { return map[string]any{"role": "admin"} }},
	"DELETE /api/v1/access-grants/{id}":            {class: "object", obj: id("grant")},
	"DELETE /api/v1/invitations/{id}":              {class: "object", obj: id("invitation")},
	// Secrets are named per workspace: B writing a name A uses creates B's own.
	"PUT /api/v1/secrets/{name}":    {class: "object", obj: map[string]string{"name": "secret"}, emptyOK: true, body: func(*tenantFx) any { return map[string]string{"value": "overwritten-by-b"} }},
	"DELETE /api/v1/secrets/{name}": {class: "object", obj: map[string]string{"name": "secret"}, emptyOK: true},

	// Creation in the caller's workspace, with references to A's objects.
	"POST /api/v1/tokens":   {class: "create", body: func(*tenantFx) any { return map[string]any{"name": "sweep", "role": "viewer"} }},
	"POST /api/v1/evaluate": {class: "create"},
	"POST /api/v1/findings/actions": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"action": "acknowledge", "ids": []int64{a.int("finding")}}
	}},
	"PUT /api/v1/risk-policy": {class: "create", body: func(*tenantFx) any { return map[string]any{} }},
	"POST /api/v1/ignore-requests": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"finding_ids": []int64{a.int("finding")}, "reason": "false_positive", "note": "sweep", "scope": "everywhere", "expiry": "never"}
	}},
	"POST /api/v1/risk-policy/preview": {class: "create", body: func(*tenantFx) any {
		return map[string]any{"known_exploited": 9, "thresholds": map[string]float64{"p1": 5, "p2": 3, "p3": 1}}
	}},
	"POST /api/v1/users": {class: "create", body: func(*tenantFx) any {
		return map[string]any{"email": "sweep-new@x.io", "role": "viewer", "password": pw}
	}},
	"POST /api/v1/teams": {class: "create", body: func(a *tenantFx) any { return map[string]any{"name": "sweep-team", "members": []int64{a.int("user")}} }},
	"POST /api/v1/integrations": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"kind": "git_repository", "config": map[string]string{"url": "https://github.com/sweep/repo"}, "secret_ref": "secret:" + a.ids["secret"]}
	}},
	"POST /api/v1/channels": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"kind": "webhook", "name": "sweep", "config": map[string]string{"url": "https://hooks.example/sweep"}, "secret_ref": "secret:" + a.ids["secret"]}
	}},
	"POST /api/v1/routes": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"name": "sweep", "channel_id": a.int("channel"), "enabled": true}
	}},
	"POST /api/v1/enrollments": {class: "create", body: func(*tenantFx) any { return map[string]any{"label": "sweep"} }},
	"POST /api/v1/projects": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"name": "sweep-project", "asset_ids": []int64{a.int("asset"), a.int("asset2")}}
	}},
	"POST /api/v1/project-suggestions/dismiss": {class: "create", body: func(*tenantFx) any { return map[string]any{"key": "new-0000000000000000"} }},
	// Grants naming A's project, asset, user or team must fail.
	"POST /api/v1/access-grants": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"project_id": a.int("project"), "team_id": a.int("team"), "role": "admin"}
	}},
	"POST /api/v1/remediation/policies": {class: "create", body: func(*tenantFx) any { return map[string]any{"name": "sweep"} }},
	// Onboarding naming A's project, and an invitation to it, must fail.
	"PUT /api/v1/onboarding": {class: "create", body: func(a *tenantFx) any { return map[string]any{"project_id": a.int("project")} }},
	"POST /api/v1/invitations": {class: "create", body: func(a *tenantFx) any {
		return map[string]any{"email": "sweep-invitee@x.io", "project_id": a.int("project"), "role": "admin"}
	}},
	"POST /api/v1/remediation/policies/preview": {class: "create", edition: "ee", query: "?id={policy}", body: func(*tenantFx) any {
		return map[string]any{"name": "sweep", "enabled": true, "target": "host_package", "ecosystems": []string{"deb"}, "change_types": []string{"distro"}}
	}},
}

// tenantFx is one workspace's data and credentials. Every name contains
// tag, so a leak shows up as the tag in another workspace's response.
type tenantFx struct {
	tag    string
	ws     int64
	ids    map[string]string
	sess   map[string]*session // admin, security, engineer, viewer
	tokens map[string]string   // admin-token, collector, agent
	secret string
}

func (f *tenantFx) int(k string) int64 {
	var v int64
	_, _ = fmt.Sscan(f.ids[k], &v)
	return v
}

// claimBatch is a collector batch claiming A's host identity.
func (f *tenantFx) claimBatch() json.RawMessage {
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "host-" + f.tag,
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "shared-machine-id"}, {Scheme: "machine-id", Value: f.tag + "-m2"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/claimed@6.6.6", Confidence: model.ConfidenceConfirmed}}
	raw, _ := json.Marshal(b)
	return raw
}

// eeFixtures adds the licensed edition's objects (remediation policies,
// plans, actions); the ee build sets it.
var eeFixtures func(t *testing.T, e *env, f *tenantFx)

// Further editions built on the core add their own objects, the paths
// that read them back for A's snapshot, and their listings for
// TestWorkspaceIsolation, from an init function.
var (
	editionFixtures       []func(t *testing.T, e *env, f *tenantFx)
	editionSnapshotPaths  []string
	editionIsolationLists []string
)

func (e *env) tenant(t *testing.T, ws int64, tag string, admin *session) *tenantFx {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), ws)
	f := &tenantFx{tag: tag, ws: ws, ids: map[string]string{"tag": tag, "workspace": fmt.Sprint(ws)},
		sess: map[string]*session{"admin": admin}, tokens: map[string]string{}}
	set := func(k string, v any) { f.ids[k] = fmt.Sprint(v) }
	var me struct{ User store.User }
	admin.do("GET", "/api/v1/auth/me", nil, &me)
	set("user", me.User.ID)
	for _, role := range []auth.Role{auth.RoleSecurity, auth.RoleEngineer, auth.RoleViewer} {
		email := string(role) + "-" + tag + "@x.io"
		if _, err := e.st.CreateUser(ctx, email, "", role, pw); err != nil {
			t.Fatal(err)
		}
		f.sess[string(role)] = e.login(email)
	}

	tok, collector, err := e.st.CreateToken(ctx, "collector-"+tag, auth.RoleCollector, nil, me.User.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.tokens["collector"] = collector
	set("collector-token", tok.ID)
	ingest := func(name string, ids []model.Identifier, obs ...model.Observation) store.IngestResult {
		b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: ids, Environment: "prod-" + tag})
		b.Observations = obs
		b.Complete = true
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+collector)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		if resp.StatusCode != 201 || json.NewDecoder(resp.Body).Decode(&res) != nil {
			t.Fatalf("%s ingest %s: %d", tag, name, resp.StatusCode)
		}
		return res
	}
	main := ingest("host-"+tag, []model.Identifier{{Scheme: "machine-id", Value: "shared-machine-id"}},
		model.Observation{Purl: "pkg:npm/" + tag + "-private-lib@1.0.0", Confidence: model.ConfidenceConfirmed},
		model.Observation{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed})
	set("asset", main.AssetID)
	set("collection", main.CollectionID)
	second := ingest("db-"+tag, []model.Identifier{{Scheme: "machine-id", Value: tag + "-m2"}},
		model.Observation{Purl: "pkg:npm/" + tag + "-db-lib@2.0.0", Confidence: model.ConfidenceConfirmed})
	set("asset2", second.AssetID)
	ingest("cache-"+tag, []model.Identifier{{Scheme: "hostname", Value: tag + "-h3"}})
	ingest("merge-"+tag, []model.Identifier{{Scheme: "machine-id", Value: tag + "-m2"}, {Scheme: "hostname", Value: tag + "-h3"}})
	var conflicts struct{ Items []store.Conflict }
	admin.do("GET", "/api/v1/conflicts", nil, &conflicts)
	if len(conflicts.Items) != 1 {
		t.Fatalf("%s conflicts: %+v", tag, conflicts)
	}
	set("conflict", conflicts.Items[0].ID)
	if code := admin.do("POST", "/api/v1/assets/"+f.ids["asset"]+"/relations", map[string]any{"to_asset": second.AssetID, "kind": "depends_on"}, nil); code != 204 {
		t.Fatalf("%s relation: %d", tag, code)
	}
	var comps struct{ Items []map[string]any }
	admin.do("GET", "/api/v1/components?q="+tag+"-private", nil, &comps)
	if len(comps.Items) != 1 {
		t.Fatalf("%s components: %+v", tag, comps.Items)
	}
	set("component", int64(comps.Items[0]["id"].(float64)))

	// A finding, its incident and fix group, as the evaluator would leave them.
	rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: main.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	var invIDs []int64
	var in []store.FindingInput
	for _, r := range rows {
		invIDs = append(invIDs, r.ID)
		if strings.HasPrefix(r.Name, tag) {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-2099-0001", InventoryID: r.ID, AssetID: main.AssetID,
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: "critical", FixedVersion: "1.0.1",
				Sources: []string{"GHSA-sweep-0001"}, Evidence: map[string]any{"feed": "osv:npm"}})
		}
	}
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, invIDs, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Prioritize(ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	fs, _, err := e.st.ListFindings(ctx, store.FindingFilter{Key: "CVE-2099-0001"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("%s findings: %v %v", tag, fs, err)
	}
	set("finding", fs[0].ID)
	// A second check that disagreed with it, and its log entry (purl and
	// inputs name the tenant).
	recordDisagreement(t, e.st, ctx, fs[0].ID)
	incs, _, err := e.st.ListIncidents(ctx, store.IncidentFilter{})
	if err != nil || len(incs) == 0 {
		t.Fatalf("%s incidents: %v", tag, err)
	}
	set("incident", incs[0].ID)
	groups, _, err := e.st.ListFixGroups(ctx, store.FixGroupFilter{})
	if err != nil || len(groups) == 0 {
		t.Fatalf("%s fix groups: %v", tag, err)
	}
	var g struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(groups[0], &g)
	set("fixgroup", g.ID)
	if code := admin.do("POST", "/api/v1/findings/"+f.ids["finding"]+"/actions", map[string]any{"action": "comment", "note": "note-" + tag}, nil); code != 200 {
		t.Fatalf("%s comment: %d", tag, code)
	}
	// The loop (0.7): a check, an ignore request from an engineer, and an
	// ignore rule for every asset.
	var chk store.Check
	if code := admin.do("POST", "/api/v1/assets/"+f.ids["asset"]+"/check", nil, &chk); code != 201 {
		t.Fatalf("%s check: %d", tag, code)
	}
	set("check", chk.ID)
	var ireq store.IgnoreRequest
	if code := f.sess["engineer"].do("POST", "/api/v1/ignore-requests", map[string]any{"finding_ids": []int64{f.int("finding")},
		"reason": "mitigated", "note": "request-" + tag, "scope": "asset", "expiry": "date", "until": time.Now().AddDate(0, 0, 30)}, &ireq); code != 201 {
		t.Fatalf("%s ignore request: %d", tag, code)
	}
	set("ignorerequest", ireq.ID)
	// A second finding on the same component, ignored everywhere.
	if code := admin.do("POST", "/api/v1/findings/"+f.ids["finding"]+"/actions", map[string]any{"action": "ignore", "reason": "false_positive",
		"note": "rule-" + tag, "scope": "everywhere", "expiry": "never"}, nil); code != 200 {
		t.Fatalf("%s ignore: %d", tag, code)
	}
	var rules struct{ Items []store.IgnoreRule }
	admin.do("GET", "/api/v1/ignore-rules", nil, &rules)
	if len(rules.Items) != 1 {
		t.Fatalf("%s ignore rules: %+v", tag, rules)
	}
	set("ignorerule", rules.Items[0].ID)

	var team store.Team
	if code := admin.do("POST", "/api/v1/teams", map[string]any{"name": "team-" + tag, "members": []int64{me.User.ID}}, &team); code != 201 {
		t.Fatalf("%s team: %d", tag, code)
	}
	set("team", team.ID)
	var proj store.Project
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "proj-" + tag, "asset_ids": []int64{main.AssetID}}, &proj); code != 201 {
		t.Fatalf("%s project: %d", tag, code)
	}
	set("project", proj.ID)
	var grant struct{ Grant store.Grant }
	if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"project_id": proj.ID, "team_id": team.ID, "role": "engineer"}, &grant); code != 201 {
		t.Fatalf("%s grant: %d", tag, code)
	}
	set("grant", grant.Grant.ID)
	var inv struct {
		Invitation store.Invitation
		Link       string
	}
	if code := admin.do("POST", "/api/v1/invitations", map[string]any{"email": "invitee-" + tag + "@x.io", "project_id": proj.ID, "role": "engineer"}, &inv); code != 201 || inv.Link == "" {
		t.Fatalf("%s invitation: %d", tag, code)
	}
	set("invitation", inv.Invitation.ID)
	f.secret = tag + "-secret-value-7Hq2"
	f.ids["secret"] = strings.ToUpper(tag) + "_TOKEN"
	if code := admin.do("PUT", "/api/v1/secrets/"+f.ids["secret"], map[string]string{"value": f.secret}, nil); code != 204 {
		t.Fatalf("%s secret: %d", tag, code)
	}
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "chan-" + tag,
		"config": map[string]string{"url": "https://hooks.example/" + tag}, "secret_ref": "secret:" + f.ids["secret"]}, &ch); code != 201 {
		t.Fatalf("%s channel: %d", tag, code)
	}
	set("channel", ch.ID)
	var rt struct{ ID int64 }
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "route-" + tag, "channel_id": ch.ID, "enabled": true}, &rt); code != 201 {
		t.Fatalf("%s route: %d", tag, code)
	}
	set("route", rt.ID)
	route, incident := rt.ID, f.int("incident")
	if _, err := e.st.EnqueueDelivery(ctx, ch.ID, &route, &incident, "opened", "sweep-"+tag, map[string]string{"title": "delivery-" + tag}); err != nil {
		t.Fatal(err)
	}
	ds, _, err := e.st.ListDeliveries(ctx, store.DeliveryFilter{})
	if err != nil || len(ds) != 1 {
		t.Fatalf("%s deliveries: %v %v", tag, ds, err)
	}
	set("delivery", ds[0].ID)
	var integ store.Integration
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "git_repository",
		"config": map[string]string{"url": "https://github.com/" + tag + "/repo"}, "secret_ref": "secret:" + f.ids["secret"]}, &integ); code != 201 {
		t.Fatalf("%s integration: %d", tag, code)
	}
	set("integration", integ.ID)
	var run struct {
		JobID int64 `json:"job_id"`
	}
	if code := admin.do("POST", "/api/v1/integrations/"+f.ids["integration"]+"/run", nil, &run); code != 202 {
		t.Fatalf("%s run: %d", tag, code)
	}
	set("job", run.JobID)
	var enr struct {
		Enrollment store.Enrollment
		Code       string `json:"code"`
	}
	if code := admin.do("POST", "/api/v1/enrollments", map[string]any{"label": "enr-" + tag}, &enr); code != 201 {
		t.Fatalf("%s enrollment: %d", tag, code)
	}
	set("enrollment", enr.Enrollment.ID)
	var at struct {
		Token  store.Token
		Secret string
	}
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "admin-token-" + tag, "role": "admin"}, &at); code != 201 {
		t.Fatalf("%s token: %d", tag, code)
	}
	set("token", at.Token.ID)
	f.tokens["admin-token"] = at.Secret
	_, agent, err := e.st.CreateAssetToken(ctx, main.AssetID, "agent-"+tag, me.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.tokens["agent"] = agent
	// A monitored-asset limit the workspace is at, and a host it refused:
	// the Usage page names it, so a leak would show the tag.
	u, err := e.st.AssetUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetAssetLimit(ctx, ws, &u.Monitored); err != nil {
		t.Fatal(err)
	}
	if code, body := bearerBody(e, collector, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, "refused-"+tag, "machine-id")); code != 402 {
		t.Fatalf("%s refused host: %d %s", tag, code, body)
	}
	if eeFixtures != nil {
		eeFixtures(t, e, f)
	}
	for _, fx := range editionFixtures {
		fx(t, e, f)
	}
	return f
}

// principals are every kind of credential workspace B can hold.
func (f *tenantFx) principals(e *env) map[string]func(method, path string, body []byte) (int, string) {
	out := map[string]func(method, path string, body []byte) (int, string){}
	for role, s := range f.sess {
		s := s
		out["session:"+role] = func(method, path string, body []byte) (int, string) {
			resp := s.req(method, path, strings.NewReader(string(body)), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
	}
	for name, secret := range f.tokens {
		secret := secret
		out["token:"+name] = func(method, path string, body []byte) (int, string) {
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
		}
	}
	return out
}

var placeholder = regexp.MustCompile(`\{([a-z0-9-]+)\}`)

func fill(s string, ids map[string]string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := ids[m[1:len(m)-1]]; ok {
			return v
		}
		return m
	})
}

// routePath fills a route pattern's parameters with A's objects (or a
// harmless value for parameters that name no tenant object).
func (r routeRule) routePath(pattern string, a *tenantFx) string {
	p := strings.TrimSuffix(pattern, "/*")
	for param, key := range r.obj {
		p = strings.ReplaceAll(p, "{"+param+"}", a.ids[key])
	}
	p = strings.NewReplacer("{platform}", "linux-amd64", "{name}", "osv:npm", "{key}", "CVE-2099-0001", "{id}", "999999999").Replace(p)
	return p + fill(r.query, a.ids)
}

// walkRoutes lists "METHOD pattern" for every route the server serves.
func walkRoutes(t *testing.T, e *env) []string {
	t.Helper()
	routes, ok := e.srv.Config.Handler.(chi.Routes)
	if !ok {
		t.Fatal("the server's handler is not a chi router")
	}
	seen := map[string]bool{}
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route == "/*" {
			return nil // the dashboard's static files
		}
		seen[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestEveryRouteIsClassified fails when a route is added without an
// isolation rule, or a rule names a route that no longer exists.
func TestEveryRouteIsClassified(t *testing.T) {
	e := newEnv(t)
	served := map[string]bool{}
	var missing []string
	for _, r := range walkRoutes(t, e) {
		served[r] = true
		if _, ok := routeRules[r]; !ok {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		t.Errorf("routes without an isolation rule in sweep_test.go (classify each, and give object routes the fixture they name):\n  %s",
			strings.Join(missing, "\n  "))
	}
	for r, rule := range routeRules {
		if !served[r] && (rule.edition == "" || rule.edition == api.BuildEdition) {
			t.Errorf("rule for %s, which this build does not serve", r)
		}
	}
	if len(served) < 100 {
		t.Errorf("only %d routes walked; is the walk broken?", len(served))
	}

	// Every route also declares how it treats project access, and the
	// declaration matches the router's (api.ProjectScopeOf): a route the
	// router does not list is for organisation-wide roles only, so a new
	// route is closed to members with project access only until it is
	// classified in both places.
	var unscoped, wrong []string
	for r := range served {
		want, ok := projectScopes[r]
		if !ok {
			unscoped = append(unscoped, r)
			continue
		}
		got := api.ProjectScopeOf(r)
		if want == "public" {
			if c := routeRules[r].class; c != "public" && c != "skip" {
				wrong = append(wrong, r+": public in projectScopes but "+c+" in routeRules")
			}
			got = "public"
		}
		if got != want {
			wrong = append(wrong, fmt.Sprintf("%s: %s in projectScopes, %s in the router", r, want, got))
		}
	}
	sort.Strings(unscoped)
	sort.Strings(wrong)
	if len(unscoped) > 0 {
		t.Errorf("routes without a project scope in projects_test.go:\n  %s", strings.Join(unscoped, "\n  "))
	}
	if len(wrong) > 0 {
		t.Errorf("project scopes that disagree:\n  %s", strings.Join(wrong, "\n  "))
	}
	for r, scope := range projectScopes {
		edition := routeRules[r].edition
		if !served[r] && (edition == "" || edition == api.BuildEdition) {
			t.Errorf("project scope for %s, which this build does not serve", r)
		}
		if scope != "public" && scope != "org" && scope != "account" && scope != "global" && scope != "scoped" && scope != "scoped-write" {
			t.Errorf("%s: unknown project scope %q", r, scope)
		}
	}
}

// normalise drops values that change by themselves (times, ages, counters
// of time) so two snapshots of the same data compare equal.
var volatile = regexp.MustCompile(`"[a-z_]*(_at|_since|_until|_age|_days|_hours|_minutes|generated|now|age|took|last_seen|stale|due|overdue)":("[^"]*"|-?[0-9.e+-]+|true|false|null)`)

var timestamp = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T[0-9:.]+(Z|[+-]\d{2}:\d{2})"`)

// relativeAge is a time in words ("seen just now", "seen 1 min ago"),
// which moves on by itself while a slow sweep runs.
var relativeAge = regexp.MustCompile(`\b(just now|\d+ (sec|min|hour|day)s? ago)`)

func normalise(body string) string {
	body = relativeAge.ReplaceAllString(body, "_ago")
	return timestamp.ReplaceAllString(volatile.ReplaceAllString(body, `"$1":_`), `"_"`)
}

// echoes are the values naming A that B itself sent (a search term, a
// secret reference by name); B's answer may repeat them.
var tagged = regexp.MustCompile(`(?i)[a-z0-9_:.-]*alpha[a-z0-9_:.-]*`)

func withoutEchoes(resp string, sent ...string) string {
	for _, s := range sent {
		for _, m := range tagged.FindAllString(s, -1) {
			resp = strings.ReplaceAll(resp, m, "")
		}
	}
	return resp
}

// TestIsolationSweep: for every route, every credential of workspace B
// (each role's session, an admin API token, a collector token and a
// host-bound agent token) tries A's objects. B must never see, count,
// change or delete them, and A's data must be unchanged afterwards.
func TestIsolationSweep(t *testing.T) {
	e := newEnv(t)
	box, err := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e.api.SecretBox = box
	ctx := context.Background()
	if err := e.st.EnsureFeed(tenant.System(ctx), "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.UpsertAdvisories(tenant.System(ctx), "osv:npm", []*osv.Vulnerability{
		{ID: "GHSA-sweep-0001", Aliases: []string{"CVE-2099-0001"}, Summary: "Test advisory", Modified: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	e.user("admin-alpha@x.io", auth.RoleAdmin)
	betaWS, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "admin-beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	// B first, then a snapshot of B's listings, then A: B's answers must be
	// the same whether or not A has data (nothing of A's is counted).
	b := e.tenant(t, betaWS.ID, "beta", e.login("admin-beta@x.io"))
	routes := walkRoutes(t, e)
	listings := func(f *tenantFx) map[string]string {
		out := map[string]string{}
		for _, r := range routes {
			rule := routeRules[r]
			if rule.class != "list" || !strings.HasPrefix(r, "GET ") {
				continue
			}
			path := rule.routePath(strings.TrimPrefix(r, "GET "), f)
			resp := f.sess["admin"].req("GET", path, nil, nil)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			out[path] = fmt.Sprintf("%d %s", resp.StatusCode, normalise(string(body)))
		}
		return out
	}
	before := listings(b)
	a := e.tenant(t, tenant.DefaultWorkspace, "alpha", e.login("admin-alpha@x.io"))
	after := listings(b)
	for path, want := range before {
		if got := after[path]; got != want {
			t.Errorf("B's %s changed when A added data:\nbefore %s\nafter  %s", path, want, got)
		}
	}

	snapshot := e.snapshot(t, a)
	principals := b.principals(e)
	sent := 0
	for _, r := range routes {
		rule, ok := routeRules[r]
		if !ok {
			continue // TestEveryRouteIsClassified reports it
		}
		method, pattern, _ := strings.Cut(r, " ")
		if rule.class == "skip" || (rule.class == "public" || rule.class == "account" || rule.class == "global") && method != "GET" && rule.body == nil {
			continue
		}
		path := rule.routePath(pattern, a)
		var body []byte
		if rule.body != nil {
			body, _ = json.Marshal(rule.body(a))
		}
		names := make([]string, 0, len(principals))
		for n := range principals {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, who := range names {
			code, resp := principals[who](method, path, body)
			sent++
			where := fmt.Sprintf("%s %s as B's %s", method, path, who)
			if code >= 500 {
				t.Errorf("%s: %d %s", where, code, resp)
			}
			low := strings.ToLower(withoutEchoes(resp, path, string(body)))
			if strings.Contains(low, "alpha") || strings.Contains(resp, a.secret) {
				t.Errorf("%s leaks A's data: %d %s", where, code, resp)
			}
			switch rule.class {
			case "instance":
				if code != 403 && code != 401 {
					t.Errorf("%s: %d, want 403 for anyone but an instance admin", where, code)
				}
			case "object":
				if code < 300 && !rule.emptyOK {
					t.Errorf("%s: %d %s, want 4xx for another workspace's object", where, code, resp)
				}
				if code < 300 && rule.emptyOK && strings.Contains(resp, `"id"`) && method == "GET" {
					t.Errorf("%s: answered with objects: %s", where, resp)
				}
			}
		}
	}
	if sent < 500 {
		t.Errorf("only %d requests sent", sent)
	}
	if after := e.snapshot(t, a); after != snapshot {
		t.Errorf("A's data changed during B's sweep:\nbefore %s\nafter  %s", snapshot, after)
	}
	if v, err := e.st.SecretValue(tenant.WithWorkspace(ctx, a.ws), box, a.ids["secret"]); err != nil || v != a.secret {
		t.Errorf("A's secret after the sweep: %q %v", v, err)
	}
	// A's credentials all still work.
	for name, secret := range a.tokens {
		path := "/api/v1/auth/me"
		if name != "admin-token" {
			path = "/api/v1/agent/actions"
		}
		if code := bearer(e, secret, "GET", path, nil, nil); code >= 400 && code != 403 {
			t.Errorf("A's %s after the sweep: %d", name, code)
		}
	}
}

// recordDisagreement stores a disagreeing second check for each finding, as
// the second check would after re-deriving it differently.
func recordDisagreement(t *testing.T, st *store.Store, ctx context.Context, ids ...int64) {
	t.Helper()
	cands, err := st.SecondCheckCandidates(ctx, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var res []store.SecondCheckResult
	for _, c := range cands {
		if want[c.FindingID] {
			res = append(res, store.SecondCheckResult{FindingID: c.FindingID, AssetID: c.AssetID, Basis: c.Basis,
				Result: store.SecondCheckDisagreed, Reason: "affected: the matcher says affected, the second check finds not affected",
				Differences: []store.SecondCheckDifference{{Field: "affected", Matcher: "affected", Independent: "not affected"}},
				Kind:        c.Kind, Key: c.Key, Purl: c.Purl, Version: c.Version, Inputs: map[string]any{"observed": map[string]any{"purl": c.Purl}}})
		}
	}
	if len(res) != len(ids) {
		t.Fatalf("second check fixtures: %d of %d findings found", len(res), len(ids))
	}
	if _, err := st.RecordSecondChecks(ctx, res); err != nil {
		t.Fatal(err)
	}
}

// snapshot reads, as A's admin, everything B's requests could have changed.
func (e *env) snapshot(t *testing.T, a *tenantFx) string {
	t.Helper()
	var b strings.Builder
	for _, p := range append([]string{
		"/api/v1/assets/{asset}", "/api/v1/assets/{asset2}", "/api/v1/assets/{asset}/relations", "/api/v1/assets/{asset}/inventory",
		"/api/v1/findings/{finding}", "/api/v1/findings/{finding}/events", "/api/v1/incidents/{incident}", "/api/v1/fix-groups/{fixgroup}",
		"/api/v1/teams", "/api/v1/channels", "/api/v1/routes", "/api/v1/deliveries", "/api/v1/integrations", "/api/v1/enrollments",
		"/api/v1/users", "/api/v1/secrets", "/api/v1/tokens", "/api/v1/conflicts", "/api/v1/risk-policy", "/api/v1/collections/{collection}/result",
		"/api/v1/remediation/policies", "/api/v1/remediation/plans", "/api/v1/workspaces",
		"/api/v1/checks?asset_id={asset}", "/api/v1/checks/{check}", "/api/v1/ignore-rules?status=all", "/api/v1/ignore-requests?status=all",
		"/api/v1/second-checks",
		"/api/v1/projects/{project}", "/api/v1/access-grants", "/api/v1/assets?project_id={project}",
		"/api/v1/invitations", "/api/v1/onboarding", "/api/v1/usage",
	}, editionSnapshotPaths...) {
		resp := a.sess["admin"].req("GET", fill(p, a.ids), nil, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Fprintf(&b, "%s %d %s\n", p, resp.StatusCode, normalise(string(body)))
	}
	return b.String()
}
