package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

const clusterUID = "0f6c2a8e-5b8d-4a51-9c5e-0d7a5e1b9a11"

// k8sReport builds a small report as the reporter sends it: the cluster,
// two images (one already pinned) and a workload running both.
func k8sReport() []*model.ObservationBatch {
	c := model.Collector{ID: "plugin:kubernetes", Version: "0.1.0", Method: "agent"}
	cluster := model.NewBatch(c, model.AssetRef{Kind: model.AssetCluster, Name: "prod-eu",
		Identifiers: []model.Identifier{{Scheme: "k8s-cluster", Value: clusterUID}}})
	cluster.Observations = []model.Observation{{Purl: "pkg:generic/kubernetes@1.32.2", Version: "1.32.2", Location: "control-plane", Confidence: model.ConfidenceConfirmed}}
	cluster.Complete = true
	var bs []*model.ObservationBatch
	bs = append(bs, cluster)
	refs := []string{"docker.io/library/nginx@sha256:" + strings.Repeat("a", 64), "docker.io/library/redis:7"}
	for _, ref := range refs {
		bs = append(bs, model.NewBatch(c, model.AssetRef{Kind: model.AssetImage, Name: ref,
			Identifiers: []model.Identifier{{Scheme: "image-ref", Value: ref}}, Attributes: map[string]string{"platform": "linux/amd64"}}))
	}
	w := model.NewBatch(c, model.AssetRef{Kind: model.AssetWorkload, Name: "prod-eu/shop/deployment/web",
		Identifiers: []model.Identifier{{Scheme: "k8s-workload", Value: clusterUID + "/shop/Deployment/web"}}})
	w.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "k8s-cluster", Value: clusterUID}}}}
	for _, ref := range refs {
		w.Relations = append(w.Relations, model.RelationRef{Kind: "deployed_as", To: []model.Identifier{{Scheme: "image-ref", Value: ref}}})
	}
	return append(bs, w)
}

func postReport(t *testing.T, e *env, token string, body any) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/kubernetes/report", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// A collector token reports a whole cluster in one request: everything is
// stored under the kubernetes collector, as an agent's report, and the
// images are queued for the image scanner up to the report's limit.
func TestKubernetesReport(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, tok, err := e.st.CreateToken(ctx, "cluster", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bs := k8sReport()
	bs[1].Collector.ID = "claims-to-be-something-else"
	one := 1
	code, body := postReport(t, e, tok, map[string]any{"batches": bs, "image_scans": one})
	if code != 200 {
		t.Fatalf("report: %d %s", code, body)
	}
	var res struct {
		ClusterAssetID int64 `json:"cluster_asset_id"`
		Assets, Images int
		NewAssets      int                            `json:"new_assets"`
		ImageScans     struct{ Queued, Deferred int } `json:"image_scans"`
		Refused        []string
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.ClusterAssetID == 0 || res.Assets != 4 || res.NewAssets != 4 || res.Images != 2 || res.ImageScans.Queued != 1 || res.ImageScans.Deferred != 1 || res.Refused == nil {
		t.Errorf("result = %s", body)
	}
	count := func(q string) int {
		t.Helper()
		var n int
		if err := e.st.Pool.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM collections WHERE collector_id = 'plugin:kubernetes' AND method = 'agent'`); n != 4 {
		t.Errorf("%d collections under the kubernetes collector, want 4", n)
	}
	if n := count(`SELECT count(*) FROM jobs WHERE kind = 'image.scan'`); n != 1 {
		t.Errorf("%d image scans queued", n)
	}
	if n := count(`SELECT count(*) FROM assets WHERE report_source = 'agent'`); n != 4 {
		t.Errorf("%d assets report as an agent's, want 4 (they go stale when the reporter stops)", n)
	}
	if n := count(`SELECT count(*) FROM asset_relations`); n < 3 {
		t.Errorf("%d relations", n)
	}

	// image_scans 0 queues nothing; the default queues the rest.
	zero := 0
	if code, body := postReport(t, e, tok, map[string]any{"batches": k8sReport(), "image_scans": zero}); code != 200 || !strings.Contains(body, `"queued":0`) {
		t.Errorf("image_scans 0: %d %s", code, body)
	}
	if code, body := postReport(t, e, tok, map[string]any{"batches": k8sReport()}); code != 200 || !strings.Contains(body, `"queued":1`) {
		t.Errorf("default image_scans: %d %s", code, body)
	}
}

// Only what a cluster reports is taken: its three asset kinds with their
// identity schemes, the cluster first. Nothing of a refused report is
// stored.
func TestKubernetesReportRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, tok, err := e.st.CreateToken(ctx, "cluster", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(bs []*model.ObservationBatch) any
		msg    string
	}{
		{"a host", func(bs []*model.ObservationBatch) any {
			bs[3].Asset.Kind = model.AssetHost
			return map[string]any{"batches": bs}
		}, "not reported from a cluster"},
		{"another identity", func(bs []*model.ObservationBatch) any {
			bs[0].Asset.Identifiers = []model.Identifier{{Scheme: "machine-id", Value: "abc"}}
			return map[string]any{"batches": bs}
		}, "machine-id"},
		{"an application path", func(bs []*model.ObservationBatch) any {
			bs[3].Asset.Identifiers = append(bs[3].Asset.Identifiers, model.Identifier{Scheme: model.AppPathScheme, Value: "/srv/x"})
			return map[string]any{"batches": bs}
		}, model.AppPathScheme},
		{"the cluster not first", func(bs []*model.ObservationBatch) any {
			return map[string]any{"batches": append(bs[1:], bs[0])}
		}, "first batch must be the cluster"},
		{"too many scans", func(bs []*model.ObservationBatch) any {
			return map[string]any{"batches": bs, "image_scans": 501}
		}, "image_scans"},
		{"no batches", func([]*model.ObservationBatch) any { return map[string]any{"batches": []any{}} }, "at least"},
		{"an unknown field", func(bs []*model.ObservationBatch) any { return map[string]any{"batches": bs, "integration_id": 1} }, "unknown field"},
	} {
		code, body := postReport(t, e, tok, tc.mutate(k8sReport()))
		if code != 400 || !strings.Contains(body, tc.msg) {
			t.Errorf("%s: %d %s, want 400 %q", tc.name, code, body, tc.msg)
		}
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM assets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("refused reports stored %d assets (%v)", n, err)
	}

	// A token bound to a host cannot report a cluster; a viewer cannot
	// report at all.
	host := uploadHost(t, e, tok)
	_, bound, err := e.st.CreateAssetToken(ctx, host, "host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := postReport(t, e, bound, map[string]any{"batches": k8sReport()}); code != 403 || !strings.Contains(body, "bound to a host") {
		t.Errorf("host-bound token: %d %s", code, body)
	}
	_, viewer, err := e.st.CreateToken(ctx, "viewer", auth.RoleViewer, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postReport(t, e, viewer, map[string]any{"batches": k8sReport()}); code != 403 {
		t.Errorf("viewer token: %d", code)
	}
}

func uploadHost(t *testing.T, e *env, tok string) int64 {
	t.Helper()
	code, res, body := uploadAs(t, e, tok, "web-1", "", nil)
	if code != 201 {
		t.Fatalf("host: %d %s", code, body)
	}
	return res.AssetID
}

// Reports are limited per token: each may queue registry pulls.
func TestKubernetesReportRateLimit(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, tok, err := e.st.CreateToken(ctx, "cluster", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := e.st.CreateToken(ctx, "other cluster", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	small := func() any { return map[string]any{"batches": k8sReport()[:1]} }
	for i := 0; i < 30; i++ {
		if code, body := postReport(t, e, tok, small()); code != 200 {
			t.Fatalf("report %d: %d %s", i, code, body)
		}
	}
	if code, _ := postReport(t, e, tok, small()); code != 429 {
		t.Errorf("31st report in an hour: %d", code)
	}
	if code, _ := postReport(t, e, other, small()); code != 200 {
		t.Errorf("another token is limited separately: %d", code)
	}
}

// The manifest the kubectl install command applies: this server's URL and
// release, no secret, and only the parameters it knows (an enrollment code
// in the URL would end up in access logs).
func TestInstallKubernetesManifest(t *testing.T) {
	e := newEnv(t)
	get := func(q string) (int, string) {
		resp, err := http.Get(e.srv.URL + "/install/kubernetes.yaml" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := get("?cluster=prod-eu")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	docs := yamlDocs(t, body)
	kinds := map[string]int{}
	var env []any
	for _, d := range docs {
		kinds[d["kind"].(string)]++
		if d["kind"] == "Deployment" {
			c := dig(d, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)
			env = c["env"].([]any)
			if c["image"] != "ghcr.io/stackurity/stackurity:latest" { // the test server's version is "test"
				t.Errorf("image %v", c["image"])
			}
		}
	}
	for k, n := range map[string]int{"Namespace": 1, "ServiceAccount": 1, "Role": 1, "RoleBinding": 1, "ClusterRole": 1, "ClusterRoleBinding": 1, "Deployment": 1} {
		if kinds[k] != n {
			t.Errorf("%d %s, want %d (%v)", kinds[k], k, n, kinds)
		}
	}
	if kinds["Secret"] != 0 || strings.Contains(body, "enr_") && !strings.Contains(body, "enroll-code=enr_...") {
		t.Error("the manifest must not carry a Secret or a code")
	}
	envs := map[string]string{}
	for _, v := range env {
		m := v.(map[string]any)
		envs[m["name"].(string)] = m["value"].(string)
	}
	if envs["STACKURITY_SERVER"] != e.srv.URL || envs["STACKURITY_CLUSTER_NAME"] != "prod-eu" || envs["STACKURITY_ALLOW_HTTP"] != "1" {
		t.Errorf("env = %v", envs)
	}

	// Namespace-scoped: a Role in each namespace and only the identity
	// cluster-wide.
	code, body = get("?cluster=prod-eu&namespaces=shop,%20blog,shop")
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	roles := map[string]bool{}
	for _, d := range yamlDocs(t, body) {
		md := d["metadata"].(map[string]any)
		switch d["kind"] {
		case "Role":
			roles[md["namespace"].(string)+"/"+md["name"].(string)] = true
		case "ClusterRole":
			if md["name"] != "stackurity-reporter-identity" {
				t.Errorf("cluster role %v in a namespace-scoped manifest", md["name"])
			}
		}
	}
	if len(roles) != 3 || !roles["shop/stackurity-reporter"] || !roles["blog/stackurity-reporter"] || !roles["stackurity/stackurity-reporter-token"] {
		t.Errorf("roles = %v", roles)
	}
	if !strings.Contains(body, `value: "shop,blog"`) {
		t.Error("STACKURITY_NAMESPACES not set")
	}

	for _, q := range []string{"?code=enr_secret123", "?enroll_code=enr_secret123", "?cluster=a%20b", "?cluster=x%0Akind:%20Secret", "?namespaces=Bad_NS", "?namespaces=a,%22b"} {
		code, body := get(q)
		if code != 400 || strings.Contains(body, "secret123") {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
}

func yamlDocs(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := yaml.NewDecoder(strings.NewReader(body))
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("manifest is not YAML: %v\n%s", err, body)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func dig(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		v = v.(map[string]any)[k]
	}
	return v
}
