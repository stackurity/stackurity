package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/pkg/plugin"
)

// The fixtures in testdata were recorded from a kind cluster (Kubernetes
// v1.32.2) with the read-only ClusterRole in deploy/kubernetes, after
// applying a few workloads: shop/web (NodePort Service), shop/api (ClusterIP
// only), shop/blog (Ingress), shop/lbapp (LoadBalancer), shop/report
// (CronJob), shop/private-thing (an image that cannot be pulled) and
// hidden/secretive (hostNetwork).

const kubeSystemUID = "45ba3e08-e154-4efb-bc5e-f7fd6eaea44a"

// fakeAPI serves the fixtures like an API server. Namespaced lists are the
// cluster-wide fixture filtered to the namespace.
type fakeAPI struct {
	t              *testing.T
	clusterWide403 bool            // every cluster-wide list is forbidden
	forbiddenNS    map[string]bool // every list in these namespaces is forbidden
	forbiddenRes   map[string]bool // these resources are forbidden everywhere
	calls          []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls = append(f.calls, r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, `{"message":"Unauthorized"}`, 401)
		return
	}
	if r.Method != http.MethodGet {
		f.t.Errorf("%s %s: the plugin must only read", r.Method, r.URL.Path)
	}
	forbid := func() {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"kind":"Status","message":"forbidden","reason":"Forbidden"}`)
	}
	p := r.URL.Path
	if p == "/version" {
		f.serve(w, "version", "")
		return
	}
	if p == "/api/v1/namespaces/kube-system" {
		f.serve(w, "api_v1_namespaces", "kube-system")
		return
	}
	// /api/v1/namespaces/<ns>/<res> or /apis/<g>/<v>/namespaces/<ns>/<res>
	parts := strings.Split(strings.Trim(p, "/"), "/")
	ns, res := "", parts[len(parts)-1]
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "namespaces" {
			ns = parts[i+1]
			parts = append(parts[:i], parts[i+2:]...)
			break
		}
	}
	if f.forbiddenRes[res] || ns != "" && f.forbiddenNS[ns] || ns == "" && f.clusterWide403 && res != "namespaces" && res != "nodes" {
		forbid()
		return
	}
	f.serve(w, strings.Join(parts, "_"), ns)
}

func (f *fakeAPI) serve(w http.ResponseWriter, name, ns string) {
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"message":"the server could not find the requested resource"}`)
		return
	}
	if ns != "" {
		var l struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(data, &l); err != nil {
			f.t.Fatal(err)
		}
		if strings.HasSuffix(name, "namespaces") {
			for _, it := range l.Items {
				if it["metadata"].(map[string]any)["name"] == ns {
					data, _ = json.Marshal(it)
				}
			}
		} else {
			var keep []map[string]any
			for _, it := range l.Items {
				if it["metadata"].(map[string]any)["namespace"] == ns {
					keep = append(keep, it)
				}
			}
			data, _ = json.Marshal(map[string]any{"items": keep, "metadata": map[string]any{}})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// start serves f over TLS and returns a kubeconfig for it.
func start(t *testing.T, f *fakeAPI) string {
	f.t = t
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: test
clusters:
- name: kind-e2e
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: reader
  user:
    token: test-token
contexts:
- name: test
  context: {cluster: kind-e2e, user: reader}
`, srv.URL, base64.StdEncoding.EncodeToString(ca))
}

func collect(t *testing.T, kubeconfig, cfg string) map[string]*plugin.ObservationBatch {
	t.Helper()
	p := k8sPlugin{connect: connect}
	if v := p.Validate(json.RawMessage(cfg)); !v.OK {
		t.Fatal(v.Problems)
	}
	batches, err := p.Collect(context.Background(), json.RawMessage(cfg), map[string]string{"kubeconfig": kubeconfig})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*plugin.ObservationBatch{}
	for i, b := range batches {
		b.Collector.Method = "plugin"
		if err := b.Validate(); err != nil {
			t.Fatalf("batch %d %s: %v", i, b.Asset.Name, err)
		}
		out[b.Asset.Name] = b
	}
	// The cluster comes first and images before workloads, so relation
	// targets exist when each batch is ingested.
	if batches[0].Asset.Kind != plugin.AssetCluster {
		t.Errorf("first batch is %s", batches[0].Asset.Kind)
	}
	seenWorkload := false
	for _, b := range batches {
		seenWorkload = seenWorkload || b.Asset.Kind == plugin.AssetWorkload
		if seenWorkload && b.Asset.Kind == plugin.AssetImage {
			t.Errorf("image %s after a workload", b.Asset.Name)
		}
	}
	return out
}

func coverage(b *plugin.ObservationBatch) map[string]plugin.CoverageItem {
	m := map[string]plugin.CoverageItem{}
	for _, c := range b.Coverage {
		m[c.Scope] = c
	}
	return m
}

func relations(b *plugin.ObservationBatch) []string {
	var out []string
	for _, r := range b.Relations {
		out = append(out, r.Kind+" "+r.To[0].Value)
	}
	return out
}

const (
	nginx  = "docker.io/library/nginx@sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
	redis  = "docker.io/library/redis@sha256:c8bb255c3559b3e458766db810aa7b3c7af1235b204cfdb304e79ff388fe1a5a"
	busy   = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	httpd  = "docker.io/library/httpd@sha256:92535cf7f151901ba91b04186292c3bd5bf82aa6ffa6eb7bc405fefbffedd480"
	prefix = "kind-e2e/shop/"
)

func TestCollectKindCluster(t *testing.T) {
	bs := collect(t, start(t, &fakeAPI{}), `{"environment": "dev", "environment_label": "environment"}`)

	cl := bs["kind-e2e"]
	if cl == nil || cl.Asset.Identifiers[0] != (plugin.Identifier{Scheme: "k8s-cluster", Value: kubeSystemUID}) {
		t.Fatalf("cluster = %+v", cl)
	}
	if cl.Asset.Attributes["distribution"] != "kind" || cl.Asset.Attributes["kubernetes_version"] != "v1.32.2" || cl.Asset.Attributes["nodes"] != "1" {
		t.Errorf("cluster attributes = %v", cl.Asset.Attributes)
	}
	obs := map[string]plugin.Observation{}
	for _, o := range cl.Observations {
		obs[o.Location] = o
	}
	for loc, want := range map[string]string{
		"control-plane": "pkg:generic/kubernetes@1.32.2", "kubelet": "pkg:generic/kubernetes@1.32.2",
		"container-runtime": "pkg:generic/containerd@2.0.2", "node-os": "pkg:generic/debian@12",
	} {
		if obs[loc].Purl != want {
			t.Errorf("%s = %q, want %q", loc, obs[loc].Purl, want)
		}
	}
	if o := obs["node-os"]; o.Evidence["kind"] != "operating-system" || o.Evidence["nodes"] != "stk-k8s-e2e-control-plane" {
		t.Errorf("node OS evidence = %v", o.Evidence)
	}
	cov := coverage(cl)
	if cov["pods"].Status != "checked" || cov["namespace:shop"].Status != "checked" || cov["nodes"].Status != "checked" {
		t.Errorf("cluster coverage = %v", cl.Coverage)
	}

	for name, want := range map[string]struct{ exposure, via, image string }{
		"deployment/web":    {"external", "Service web (NodePort 30080)", nginx},
		"deployment/blog":   {"external", "Ingress blog (blog.example.com)", nginx},
		"statefulset/lbapp": {"external", "Service shop-lb (LoadBalancer)", httpd},
		"deployment/api":    {"internal", "", redis},
		"cronjob/report":    {"internal", "", busy}, // digest from the Job's pod
	} {
		w := bs[prefix+name]
		if w == nil {
			t.Errorf("workload %s missing", name)
			continue
		}
		at := w.Asset.Attributes
		if at["exposure"] != want.exposure || at["exposed_via"] != want.via || at["images"] != want.image {
			t.Errorf("%s attributes = %v", name, at)
		}
		if w.Asset.Environment != "production" {
			t.Errorf("%s environment = %q (namespace label)", name, w.Asset.Environment)
		}
		rels := relations(w)
		if len(rels) != 2 || rels[0] != "runs_on "+kubeSystemUID || rels[1] != "deployed_as "+want.image {
			t.Errorf("%s relations = %v", name, rels)
		}
	}
	if w := bs[prefix+"deployment/api"]; w.Asset.Attributes["services"] != "api" || w.Asset.Attributes["replicas"] != "1" {
		t.Errorf("api = %v", w.Asset.Attributes)
	}
	if w := bs["kind-e2e/hidden/deployment/secretive"]; w.Asset.Attributes["exposed_via"] != "hostNetwork" || w.Asset.Environment != "dev" {
		t.Errorf("secretive = %+v", w.Asset)
	}

	// An image that never pulled is recorded by tag, and the gap is visible.
	pt := bs[prefix+"pod/private-thing"]
	if c := coverage(pt)["image:app"]; c.Status != "partial" || !strings.Contains(c.Reason, "ImagePullBackOff") {
		t.Errorf("private-thing coverage = %v", pt.Coverage)
	}
	if pt.Asset.Attributes["image_pull_secrets"] != "regcred" {
		t.Errorf("private-thing = %v", pt.Asset.Attributes)
	}
	img := bs["ghcr.io/stackurity/does-not-exist:1.0"]
	if img == nil || img.Asset.Attributes["pinned"] != "false" || img.Asset.Attributes["pull_secret"] != "true" {
		t.Errorf("private image = %+v", img)
	}
	if n := bs[nginx]; n == nil || n.Asset.Kind != plugin.AssetImage || n.Asset.Identifiers[0].Scheme != "image-ref" ||
		n.Asset.Attributes["platform"] != "linux/arm64" || len(n.Observations) != 0 {
		t.Errorf("nginx image = %+v", n)
	}
}

func TestImagesExposedFirstAndCapped(t *testing.T) {
	p := k8sPlugin{connect: connect}
	kc := start(t, &fakeAPI{})
	batches, err := p.Collect(context.Background(), json.RawMessage(`{"max_images": 2}`), map[string]string{"kubeconfig": kc})
	if err != nil {
		t.Fatal(err)
	}
	var images []string
	for _, b := range batches {
		if b.Asset.Kind == plugin.AssetImage {
			images = append(images, b.Asset.Name)
		}
	}
	// Exposed and pinned first, then the most used: busybox (hostNetwork
	// and the CronJob) and nginx (web and blog) before httpd.
	if len(images) != 2 || images[0] != busy || images[1] != nginx {
		t.Errorf("images = %v", images)
	}
	if c := coverage(batches[0])["images"]; c.Status != "partial" || !strings.Contains(c.Reason, "max_images") {
		t.Errorf("cap not reported: %v", c)
	}
}

// With namespace-scoped RBAC, cluster-wide lists are forbidden and the
// plugin reads namespace by namespace; a namespace it cannot read is
// reported, never treated as empty.
func TestForbiddenNamespaceIsCoverage(t *testing.T) {
	f := &fakeAPI{clusterWide403: true, forbiddenNS: map[string]bool{"hidden": true}}
	bs := collect(t, start(t, f), `{}`)
	cl := bs["kind-e2e"]
	cov := coverage(cl)
	if c := cov["namespace:hidden"]; c.Status != "failed" {
		t.Errorf("hidden namespace coverage = %+v", c)
	}
	if c := cov["pods"]; c.Status != "partial" || !strings.Contains(c.Reason, "hidden") {
		t.Errorf("pods coverage = %+v", c)
	}
	if cov["namespace:shop"].Status != "checked" {
		t.Errorf("shop = %+v", cov["namespace:shop"])
	}
	if bs["kind-e2e/hidden/deployment/secretive"] != nil {
		t.Error("a workload in a forbidden namespace cannot be known")
	}
	if w := bs[prefix+"deployment/web"]; w == nil || w.Asset.Attributes["exposure"] != "external" {
		t.Errorf("web = %+v", w)
	}
	// Per-namespace fallback, not one call per namespace for every resource
	// when the cluster-wide call works.
	perNS := 0
	for _, c := range f.calls {
		if strings.Contains(c, "/namespaces/shop/") {
			perNS++
		}
	}
	if perNS != 8 {
		t.Errorf("%d per-namespace calls in shop, want 8 (one per resource)", perNS)
	}
}

func TestUnreadableServicesMakeExposureUnknown(t *testing.T) {
	bs := collect(t, start(t, &fakeAPI{forbiddenRes: map[string]bool{"services": true}}), `{}`)
	w := bs[prefix+"deployment/api"]
	if w.Asset.Attributes["exposure"] != "unknown" || coverage(w)["exposure"].Status != "partial" {
		t.Errorf("api with unreadable Services = %v %v", w.Asset.Attributes["exposure"], w.Coverage)
	}
	// Host networking is still known to be external.
	if w := bs["kind-e2e/hidden/deployment/secretive"]; w.Asset.Attributes["exposure"] != "external" {
		t.Errorf("secretive = %v", w.Asset.Attributes)
	}
	if c := coverage(bs["kind-e2e"])["services"]; c.Status != "failed" {
		t.Errorf("services coverage = %+v", c)
	}
}

func TestNodesForbidden(t *testing.T) {
	bs := collect(t, start(t, &fakeAPI{forbiddenRes: map[string]bool{"nodes": true}}), `{}`)
	cl := bs["kind-e2e"]
	if cl.Complete || coverage(cl)["nodes"].Status != "failed" || len(cl.Observations) != 1 {
		t.Errorf("cluster without nodes: complete=%v obs=%v cov=%v", cl.Complete, cl.Observations, cl.Coverage)
	}
}

func TestNamespaceFilters(t *testing.T) {
	f := &fakeAPI{}
	bs := collect(t, start(t, f), `{"namespaces": ["shop", "hidden"], "exclude_namespaces": ["hidden"], "cluster_name": "lab"}`)
	for name, b := range bs {
		if b.Asset.Kind == plugin.AssetWorkload && !strings.HasPrefix(name, "lab/shop/") {
			t.Errorf("unexpected workload %s", name)
		}
	}
	if bs["lab/shop/deployment/web"] == nil {
		t.Error("shop/web missing")
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/namespaces/hidden/") {
			t.Errorf("excluded namespace read: %s", c)
		}
	}
}

func TestNetworkPolicyIsEnforced(t *testing.T) {
	kc := start(t, &fakeAPI{})
	ctx := plugin.WithNetwork(context.Background(), netguard.Policy{AllowPrivate: false})
	_, err := (k8sPlugin{connect: connect}).Collect(ctx, json.RawMessage(`{}`), map[string]string{"kubeconfig": kc})
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("loopback API server reached from a workspace without private access: %v", err)
	}
	// in_cluster is the server's own identity.
	_, err = (k8sPlugin{connect: connect}).Collect(ctx, json.RawMessage(`{"in_cluster": true}`), nil)
	if err == nil || !strings.Contains(err.Error(), "may not use") {
		t.Errorf("in_cluster allowed: %v", err)
	}
}

func TestHealth(t *testing.T) {
	h := (k8sPlugin{connect: connect}).Health(context.Background(), json.RawMessage(`{}`), map[string]string{"kubeconfig": start(t, &fakeAPI{})})
	if !h.OK || !strings.Contains(h.Message, "v1.32.2") {
		t.Errorf("health = %+v", h)
	}
	h = (k8sPlugin{connect: connect}).Health(context.Background(), json.RawMessage(`{}`), map[string]string{"kubeconfig": start(t, &fakeAPI{clusterWide403: true})})
	if h.OK {
		t.Errorf("health with pods forbidden = %+v", h)
	}
}

func TestTLSIsVerified(t *testing.T) {
	kc := start(t, &fakeAPI{})
	// A kubeconfig without the cluster CA must not connect to a server with
	// a self-signed certificate.
	var cfg strings.Builder
	for _, line := range strings.Split(kc, "\n") {
		if !strings.Contains(line, "certificate-authority-data") {
			cfg.WriteString(line + "\n")
		}
	}
	_, err := (k8sPlugin{connect: connect}).Collect(context.Background(), json.RawMessage(`{}`), map[string]string{"kubeconfig": cfg.String()})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unverified TLS accepted: %v", err)
	}
}

func TestKubeconfigCredentials(t *testing.T) {
	base := `apiVersion: v1
clusters: [{name: c, cluster: {server: "https://10.0.0.1:6443"%s}}]
users: [{name: u, user: {%s}}]
contexts: [{name: x, context: {cluster: c, user: u}}]
`
	for _, tc := range []struct{ cluster, user, want string }{
		{"", `token: abc`, ""},
		{"", `exec: {command: aws}`, "exec"},
		{"", `auth-provider: {name: gcp}`, "exec"},
		{"", `tokenFile: /etc/token`, "files"},
		{"", `username: admin, password: x`, "basic"},
		{", insecure-skip-tls-verify: true", `token: abc`, "insecure"},
		{", certificate-authority: /etc/ca.pem", `token: abc`, "file"},
		{"", ``, "no token"},
	} {
		conn, err := fromKubeconfig(fmt.Sprintf(base, tc.cluster, tc.user), "")
		switch {
		case tc.want == "" && (err != nil || conn.token != "abc" || conn.server != "https://10.0.0.1:6443"):
			t.Errorf("%s: %v %+v", tc.user, err, conn)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s%s: err = %v, want %q", tc.cluster, tc.user, err, tc.want)
		}
	}
	if _, err := fromKubeconfig(fmt.Sprintf(base, "", "token: abc"), "missing"); err == nil {
		t.Error("unknown context accepted")
	}
}

func TestResolveRef(t *testing.T) {
	for _, tc := range []struct{ spec, imageID, want string }{
		{"nginx:1.25", "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64), "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)},
		{"nginx:1.25", "docker-pullable://nginx@sha256:" + strings.Repeat("b", 64), "docker.io/library/nginx@sha256:" + strings.Repeat("b", 64)},
		{"nginx:1.25", "sha256:" + strings.Repeat("c", 64), "docker.io/library/nginx:1.25"}, // a local image id, not a registry digest
		{"nginx", "", "docker.io/library/nginx:latest"},
		{"bitnami/redis:7", "", "docker.io/bitnami/redis:7"},
		{"localhost:5000/app:1", "", "localhost:5000/app:1"},
		{"ghcr.io/acme/app@sha256:" + strings.Repeat("d", 64), "", "ghcr.io/acme/app@sha256:" + strings.Repeat("d", 64)},
		{"index.docker.io/nginx:1", "", "docker.io/library/nginx:1"},
	} {
		if got, _ := resolveRef(tc.spec, tc.imageID); got != tc.want {
			t.Errorf("resolveRef(%q, %q) = %q, want %q", tc.spec, tc.imageID, got, tc.want)
		}
	}
}

func TestVersionsAndOS(t *testing.T) {
	for in, want := range map[string]string{"v1.31.2-eks-7f9249a": "1.31.2", "v1.30.4+k3s1": "1.30.4", "v1.29.8-gke.1211000": "1.29.8"} {
		if got := cleanVersion(in); got != want {
			t.Errorf("cleanVersion(%q) = %q", in, got)
		}
	}
	if _, p, prov := distribution("v1.31.2-eks-7f9249a", nil); p != "amazon-eks" || prov != "aws" {
		t.Errorf("eks = %s %s", p, prov)
	}
	if _, p, _ := distribution("v1.29.8-gke.1211000", nil); p != "google-kubernetes-engine" {
		t.Errorf("gke = %s", p)
	}
	for img, want := range map[string]string{
		"Ubuntu 22.04.4 LTS": "ubuntu 22.04", "Debian GNU/Linux 12 (bookworm)": "debian 12", "Amazon Linux 2": "amzn 2",
		"Amazon Linux 2023.5.20240722": "amzn 2023", "Red Hat Enterprise Linux CoreOS 415.92": "rhel 415.92",
		"SUSE Linux Enterprise Server 15 SP5": "sles 15.5", "Bottlerocket OS 1.20.3 (aws-k8s-1.29)": " ",
		"Container-Optimized OS from Google": " ",
	} {
		id, v := osOf(img)
		if id+" "+v != want {
			t.Errorf("osOf(%q) = %q %q", img, id, v)
		}
	}
	if p, v := runtimeProduct("containerd://1.7.24-0ubuntu1"); p != "containerd" || v != "1.7.24" {
		t.Errorf("runtime = %s %s", p, v)
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{
		`{"server": "http://10.0.0.1"}`, `{"server": "https://10.0.0.1", "in_cluster": true}`,
		`{"namespaces": ["Bad_NS"]}`, `{"max_images": 5000}`, `{"environment_label": "not a label"}`,
		`{"cluster_name": "a b"}`, `{"kubeconfig": "..."}`,
	} {
		if (k8sPlugin{}).Validate(json.RawMessage(bad)).OK {
			t.Errorf("%s accepted", bad)
		}
	}
	if !(k8sPlugin{}).Validate(json.RawMessage(`{"cluster_name": "prod-eu", "namespaces": ["shop"], "environment_label": "example.com/env", "max_images": 50}`)).OK {
		t.Error("valid config rejected")
	}
}
