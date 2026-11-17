package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	// The policy gate check (gate_check.go): B naming A's asset gets 404.
	routeRules["POST /api/v1/gate-policies/check"] = routeRule{class: "object", body: func(a *tenantFx) any {
		return map[string]any{"asset_id": a.int("asset"), "source": "api"}
	}}
	projectScopes["POST /api/v1/gate-policies/check"] = "scoped"
}

// gateCheckAnswer is the check's answer as a client reads it.
type gateCheckAnswer struct {
	CheckID           int64  `json:"check_id"`
	Result            string `json:"result"`
	AssetID           int64  `json:"asset_id"`
	AssetName         string `json:"asset_name"`
	PoliciesEvaluated int    `json:"policies_evaluated"`
	PoliciesEnforced  int    `json:"policies_enforced"`
	DryRun            bool   `json:"dry_run"`
	Violations        []struct {
		PolicyID            int64  `json:"policy_id"`
		PolicyName          string `json:"policy_name"`
		Mode                string `json:"mode"`
		Reason              string `json:"reason"`
		Component           string `json:"component"`
		FindingID           *int64 `json:"finding_id"`
		Link                string `json:"link"`
		EnforceRequiresPlan bool   `json:"enforce_requires_plan"`
	} `json:"violations"`
}

// tokenCheck posts a check with a bearer token and decodes the answer.
func tokenCheck(t *testing.T, e *env, token string, body map[string]any) (int, gateCheckAnswer, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	code, resp := bearerBody(e, token, "POST", "/api/v1/gate-policies/check", raw)
	var out gateCheckAnswer
	_ = json.Unmarshal([]byte(resp), &out)
	return code, out, resp
}

func TestGatePolicyCheckAPI(t *testing.T) {
	o := newOrgWith(t, func(s *api.Server) { s.BaseURL = "https://stackurity.test/" })
	e := o.e
	ctx := context.Background()
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	alpha := o.id("alpha-asset")
	check := func(s *session, body map[string]any) (int, gateCheckAnswer) {
		t.Helper()
		var out gateCheckAnswer
		code := s.do("POST", "/api/v1/gate-policies/check", body, &out)
		return code, out
	}

	// The server says it checks.
	var meta struct {
		Features []string `json:"features"`
	}
	if code := e.anon().do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureGatePolicies) {
		t.Fatalf("meta: %d %v", code, meta.Features)
	}

	// No policy yet: pass, nothing evaluated, and the check is recorded.
	code, a := check(o.admin, map[string]any{"asset_id": alpha})
	if code != 200 || a.Result != "pass" || a.PoliciesEvaluated != 0 || len(a.Violations) != 0 || a.CheckID == 0 || a.AssetName != "host-alpha" {
		t.Fatalf("no policy: %d %+v", code, a)
	}

	// alpha-finding (CVE-2099-0001 on host-alpha) is known to be exploited.
	if _, err := e.st.Pool.Exec(ws, `UPDATE findings SET evidence = evidence || '{"known_exploited": true}' WHERE id = $1`, o.id("alpha-finding")); err != nil {
		t.Fatal(err)
	}
	var kev store.GatePolicy
	if code := o.admin.do("POST", "/api/v1/gate-policies", map[string]any{"name": "No KEV", "kind": "known_exploited"}, &kev); code != 201 {
		t.Fatalf("policy: %d", code)
	}

	// Warn: a violation with an absolute link, the result warn.
	code, a = check(o.admin, map[string]any{"asset_id": alpha, "source": "deploy", "commit": "abc123", "ref": "v1.0.0"})
	if code != 200 || a.Result != "warn" || a.PoliciesEvaluated != 1 || a.PoliciesEnforced != 0 || len(a.Violations) != 1 {
		t.Fatalf("warn: %d %+v", code, a)
	}
	v := a.Violations[0]
	if v.PolicyID != kev.ID || v.Mode != "warn" || v.FindingID == nil || *v.FindingID != o.id("alpha-finding") ||
		v.Link != fmt.Sprintf("https://stackurity.test/findings/%d", o.id("alpha-finding")) ||
		!strings.HasPrefix(v.Reason, "CVE-2099-0001 in alpha-private-lib 1.0.0 is known to be exploited") || v.EnforceRequiresPlan {
		t.Errorf("violation: %+v", v)
	}
	checks, err := e.st.GatePolicyChecks(ws, alpha, 10)
	if err != nil || len(checks) != 2 {
		t.Fatalf("recorded: %v %+v", err, checks)
	}
	c := checks[0]
	if c.Result != "warn" || c.Source != "deploy" || c.Commit != "abc123" || c.Ref != "v1.0.0" || c.AssetName != "host-alpha" ||
		c.ActorType != "user" || c.ActorName != "admin-org@x.io" || !strings.Contains(string(c.Violations), "No KEV") || !slices.Contains(c.PolicyIDs, kev.ID) {
		t.Errorf("recorded check: %+v", c)
	}

	// Enforce: without the plan (the Community default) a warning saying
	// so; with it, fail.
	if code := o.admin.do("PUT", fmt.Sprintf("/api/v1/gate-policies/%d", kev.ID), map[string]any{"name": "No KEV", "kind": "known_exploited", "mode": "enforce"}, nil); code != 200 {
		t.Fatalf("enforce: %d", code)
	}
	code, a = check(o.admin, map[string]any{"asset_id": alpha})
	if code != 200 || a.Result != "warn" || a.PoliciesEnforced != 0 || !a.Violations[0].EnforceRequiresPlan || a.Violations[0].Mode != "enforce" {
		t.Errorf("enforce without the plan: %d %+v", code, a)
	}
	restore := api.SetGateEnforce(true)
	defer restore()
	code, a = check(o.admin, map[string]any{"asset_id": alpha})
	if code != 200 || a.Result != "fail" || a.PoliciesEnforced != 1 || a.Violations[0].EnforceRequiresPlan {
		t.Errorf("enforced: %d %+v", code, a)
	}

	// A dry run says what applies, reads no finding and records nothing.
	before, _ := e.st.GatePolicyChecks(ws, alpha, 100)
	code, a = check(o.admin, map[string]any{"asset_id": alpha, "dry_run": true})
	after, _ := e.st.GatePolicyChecks(ws, alpha, 100)
	if code != 200 || !a.DryRun || a.Result != "" || a.PoliciesEvaluated != 1 || a.PoliciesEnforced != 1 || len(a.Violations) != 0 || a.CheckID != 0 ||
		len(after) != len(before) {
		t.Errorf("dry run: %d %+v (%d → %d checks)", code, a, len(before), len(after))
	}

	// An approved exception that has not expired takes the violation
	// out; once expired, it is back.
	var exc int64
	if err := e.st.Pool.QueryRow(ws, `INSERT INTO gate_policy_exceptions (policy_id, target_kind, asset_id, finding_id, reason, status, decided_at, expires_at)
		VALUES ($1, 'finding', $2, $3, 'mitigated', 'approved', now(), now() + interval '7 days') RETURNING id`,
		kev.ID, alpha, o.id("alpha-finding")).Scan(&exc); err != nil {
		t.Fatal(err)
	}
	if code, a = check(o.admin, map[string]any{"asset_id": alpha}); code != 200 || a.Result != "pass" || len(a.Violations) != 0 {
		t.Errorf("with an exception: %d %+v", code, a)
	}
	if _, err := e.st.Pool.Exec(ws, `UPDATE gate_policy_exceptions SET expires_at = now() - interval '1 minute' WHERE id = $1`, exc); err != nil {
		t.Fatal(err)
	}
	if code, a = check(o.admin, map[string]any{"asset_id": alpha}); code != 200 || a.Result != "fail" {
		t.Errorf("exception expired: %d %+v", code, a)
	}
	// A pending exception does not count.
	if _, err := e.st.Pool.Exec(ws, `INSERT INTO gate_policy_exceptions (policy_id, target_kind, asset_id, reason, status)
		VALUES ($1, 'asset', $2, 'accepted_risk', 'pending')`, kev.ID, alpha); err != nil {
		t.Fatal(err)
	}
	if code, a = check(o.admin, map[string]any{"asset_id": alpha}); code != 200 || a.Result != "fail" {
		t.Errorf("pending exception: %d %+v", code, a)
	}

	// Bad requests.
	for _, bad := range []map[string]any{
		{},
		{"asset_id": alpha, "source": "cron"},
		{"asset_id": alpha, "repository_url": "https://github.com/acme/app"},
		{"image_digest": "nginx:latest"},
		{"asset_id": alpha, "collection_id": o.id("beta-collection")},
		{"asset_id": alpha, "unknown": true},
	} {
		if code, _ := check(o.admin, bad); code != 400 {
			t.Errorf("%v: %d, want 400", bad, code)
		}
	}
	if code, _ := check(o.admin, map[string]any{"asset_id": 99999999}); code != 404 {
		t.Errorf("unknown asset: %d", code)
	}

	// Project members: a viewer on Alpha checks Alpha's host, not Beta's;
	// the answer counts the organisation's policies as they are.
	o.grant(t, "gate-viewer@x.io", o.id("alpha-project"), 0, auth.RoleViewer)
	pv := e.signIn("gate-viewer@x.io")
	if code, a = check(pv, map[string]any{"asset_id": alpha}); code != 200 || a.Result != "fail" {
		t.Errorf("alpha viewer on alpha: %d %+v", code, a)
	}
	if code, _ = check(pv, map[string]any{"asset_id": o.id("beta-asset")}); code != 404 {
		t.Errorf("alpha viewer on beta: %d", code)
	}

	// Collector tokens. The organisation's collector uploaded every host:
	// by its own upload it may check; naming an asset it may not.
	gamma := o.ingest(t, "host-gamma", "gamma-m1", "prod-gamma", "pkg:npm/gamma-lib@1.0.0")
	if code, a, resp := tokenCheck(t, e, o.collector, map[string]any{"collection_id": gamma.CollectionID, "source": "ci"}); code != 200 ||
		a.AssetID != gamma.AssetID || a.Result != "pass" {
		t.Errorf("collector, own upload: %d %s", code, resp)
	}
	if code, _, resp := tokenCheck(t, e, o.collector, map[string]any{"asset_id": gamma.AssetID}); code != 403 {
		t.Errorf("collector naming an asset: %d %s", code, resp)
	}
	_, other, err := e.st.CreateToken(ws, "other collector", auth.RoleCollector, nil, o.adminID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, resp := tokenCheck(t, e, other, map[string]any{"collection_id": gamma.CollectionID}); code != 404 {
		t.Errorf("another token's upload: %d %s", code, resp)
	}
	// A token bound to host-alpha checks host-alpha only.
	if code, a, resp := tokenCheck(t, e, o.agent, map[string]any{"asset_id": alpha}); code != 200 || a.Result != "fail" {
		t.Errorf("bound token on its host: %d %s", code, resp)
	}
	if code, _, resp := tokenCheck(t, e, o.agent, map[string]any{"asset_id": o.id("beta-asset")}); code != 403 {
		t.Errorf("bound token on another host: %d %s", code, resp)
	}

	// A CI job's token: its own repository, by URL or by its upload; no
	// other repository.
	trust, err := e.st.CreateCITrust(ws, store.CITrust{Name: "ci", Provider: "github", Issuer: api.GitHubIssuer, Repository: "acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	_, ciTok, err := e.st.IssueCIToken(ctx, *trust, store.CIToken{Name: "job", RepositoryURL: "https://github.com/acme/app", TTL: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	code, resp := bearerBody(e, ciTok, "POST", "/api/v1/ingest", repoBatch("app", gitURL("https://github.com/acme/app")))
	if code != 201 {
		t.Fatalf("CI upload: %d %s", code, resp)
	}
	var up store.IngestResult
	_ = json.Unmarshal([]byte(resp), &up)
	if code, _, resp := tokenCheck(t, e, ciTok, map[string]any{"repository_url": "https://github.com/Acme/app.git", "source": "ci", "commit": "def"}); code != 200 {
		t.Errorf("CI token, own repository: %d %s", code, resp)
	}
	if code, a, resp := tokenCheck(t, e, ciTok, map[string]any{"collection_id": up.CollectionID, "source": "ci"}); code != 200 || a.AssetID != up.AssetID {
		t.Errorf("CI token, own upload: %d %s", code, resp)
	}
	if code, _ := bearerBody(e, o.collector, "POST", "/api/v1/ingest", repoBatch("lib", gitURL("https://github.com/acme/lib"))); code != 201 {
		t.Fatalf("lib upload: %d", code)
	}
	for _, body := range []map[string]any{{"repository_url": "https://github.com/acme/lib"}, {"asset_id": alpha}} {
		if code, _, resp := tokenCheck(t, e, ciTok, body); code != 403 {
			t.Errorf("CI token, %v: %d %s", body, code, resp)
		}
	}
	last, _ := e.st.GatePolicyChecks(ws, up.AssetID, 10)
	if len(last) != 2 || !strings.EqualFold(last[1].Repository, "https://github.com/acme/app") || last[1].Commit != "def" || last[1].ActorType != "token" {
		t.Errorf("CI checks recorded: %+v", last)
	}

	// An image by its digest.
	digest := "sha256:" + strings.Repeat("c0", 32)
	ib := model.NewBatch(model.Collector{ID: "image-scanner", Method: "scanner"}, model.AssetRef{Kind: model.AssetImage, Name: "ghcr.io/acme/app:1",
		Identifiers: []model.Identifier{{Scheme: "image-ref", Value: "ghcr.io/acme/app:1"}}, Attributes: map[string]string{"digest": digest}})
	ib.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed}}
	raw, _ := json.Marshal(ib)
	code, resp = bearerBody(e, o.collector, "POST", "/api/v1/ingest", raw)
	if code != 201 {
		t.Fatalf("image upload: %d %s", code, resp)
	}
	var img store.IngestResult
	_ = json.Unmarshal([]byte(resp), &img)
	if code, a = check(o.admin, map[string]any{"image_digest": "ghcr.io/acme/app@" + digest, "source": "deploy"}); code != 200 || a.AssetID != img.AssetID {
		t.Errorf("by digest: %d %+v", code, a)
	}
	if code, _ = check(o.admin, map[string]any{"image_digest": "sha256:" + strings.Repeat("d1", 32)}); code != 404 {
		t.Errorf("unknown digest: %d", code)
	}
}
