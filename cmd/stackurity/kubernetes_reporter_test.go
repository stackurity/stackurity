package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/plugins/kubernetes/kube"
)

// The fixtures recorded from a kind cluster for the kubernetes plugin.
const k8sFixtures = "../../plugins/kubernetes/kube/testdata"

// fakeCluster serves the plugin's fixtures as a Kubernetes API server, and
// the reporter's Secret (stackurity/stackurity-reporter) with get and
// update and the API server's optimistic concurrency.
type fakeCluster struct {
	t  *testing.T
	mu sync.Mutex
	// secret is the stored Secret; nil: it does not exist.
	secret map[string]any
	rv     int
	// readOnly refuses updates of the Secret (a Role without update).
	readOnly bool
	// puts counts updates of the Secret.
	puts int
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer sa-token" {
		http.Error(w, `{"message":"Unauthorized"}`, 401)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/v1/namespaces/stackurity/secrets/stackurity-reporter" {
		f.serveSecret(w, r)
		return
	}
	if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "/secrets") {
		f.t.Errorf("%s %s: not something the reporter may do", r.Method, r.URL.Path)
		w.WriteHeader(403)
		return
	}
	name := strings.ReplaceAll(strings.Trim(r.URL.Path, "/"), "/", "_")
	data, err := os.ReadFile(filepath.Join(k8sFixtures, name+".json"))
	if err != nil {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
		return
	}
	_, _ = w.Write(data)
}

func (f *fakeCluster) serveSecret(w http.ResponseWriter, r *http.Request) {
	switch {
	case f.secret == nil:
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"secrets \"stackurity-reporter\" not found"}`))
		return
	case r.Method == http.MethodPut && f.readOnly:
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"message":"forbidden: cannot update secrets"}`))
		return
	case r.Method == http.MethodPut:
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			f.t.Error(err)
		}
		md, _ := in["metadata"].(map[string]any)
		if md["resourceVersion"] != strconv.Itoa(f.rv) {
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"message":"the object has been modified"}`))
			return
		}
		f.puts++
		f.rv++
		md["resourceVersion"] = strconv.Itoa(f.rv)
		f.secret = in
	case r.Method != http.MethodGet:
		w.WriteHeader(405)
		return
	}
	_ = json.NewEncoder(w).Encode(f.secret)
}

// setSecret stores the Secret with these keys, as kubectl or Helm would.
func (f *fakeCluster) setSecret(data map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	enc := map[string]any{}
	for k, v := range data {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	f.rv++
	f.secret = map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "data": enc,
		"metadata": map[string]any{"name": "stackurity-reporter", "namespace": "stackurity", "resourceVersion": strconv.Itoa(f.rv),
			"labels":      map[string]any{"app.kubernetes.io/managed-by": "Helm"},
			"annotations": map[string]any{"meta.helm.sh/release-name": "stackurity-reporter"}}}
}

// key returns one key of the stored Secret, decoded ("" when absent).
func (f *fakeCluster) key(k string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, _ := f.secret["data"].(map[string]any)
	v, _ := data[k].(string)
	b, _ := base64.StdEncoding.DecodeString(v)
	return string(b)
}

// newReporter returns a reporter for server, reading the fake cluster.
func newReporter(t *testing.T, server string, f *fakeCluster) *k8sReporter {
	t.Helper()
	f.t = t
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	settings, p := kube.ParseSettings(json.RawMessage(`{"cluster_name": "kind-e2e", "environment_label": "environment"}`))
	if len(p) > 0 {
		t.Fatal(p)
	}
	return &k8sReporter{server: server, secret: "stackurity-reporter", namespace: "stackurity", settings: settings, imageScans: 2,
		connect: func(ctx context.Context) (*kube.Client, error) {
			return kube.NewClient(ctx, srv.URL, "sa-token", ca, "test")
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// The whole push path against the real server and database: the pod
// redeems the code from its Secret, stores the token there (keeping the
// Secret's labels and annotations), and the cluster, its workloads and
// images arrive under the kubernetes collector, with scans queued for the
// images. A revoked token stops the reports until a new code is put in
// the Secret.
func TestKubernetesReporterEnrollsAndReports(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	holder := &license.Holder{}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", Licence: holder,
		Gate: &license.Gate{Licence: holder}, Health: &health.Checker{Store: st, FeedsEnabled: true}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	enr, code, err := st.CreateEnrollment(ctx, store.Enrollment{Label: "kind-e2e", Environment: "staging", UsesLeft: 1}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCluster{}
	r := newReporter(t, srv.URL, f)

	// Before the Secret exists the reporter waits, and uses nothing up.
	if err := r.runOnce(context.Background()); !errors.Is(err, errNotEnrolled) || !strings.Contains(err.Error(), "kubectl -n stackurity create secret") {
		t.Fatalf("no Secret: %v", err)
	}
	f.setSecret(map[string]string{"enroll-code": code})
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok := f.key("token")
	if !strings.HasPrefix(tok, "stk_") || f.key("enroll-code") != "" || f.key("environment") != "staging" {
		t.Fatalf("Secret after enrolling: token %q, code %q, environment %q", tok, f.key("enroll-code"), f.key("environment"))
	}
	md := f.secret["metadata"].(map[string]any)
	if md["labels"].(map[string]any)["app.kubernetes.io/managed-by"] != "Helm" || md["annotations"].(map[string]any)["meta.helm.sh/release-name"] == nil {
		t.Errorf("the update dropped the Secret's labels or annotations: %v", md)
	}
	var left int
	if err := st.Pool.QueryRow(tenant.System(ctx), `SELECT uses_left FROM enrollments WHERE id = $1`, enr.ID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("enrollment uses left %d (%v)", left, err)
	}

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := st.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM assets a JOIN asset_identifiers i ON i.asset_id = a.id
		WHERE a.kind = 'cluster' AND a.name = 'kind-e2e' AND a.environment = 'staging' AND i.scheme = 'k8s-cluster' AND i.value = '45ba3e08-e154-4efb-bc5e-f7fd6eaea44a'`); n != 1 {
		t.Errorf("%d cluster assets identified by the kube-system UID", n)
	}
	workloads := count(`SELECT count(*) FROM assets WHERE kind = 'workload'`)
	images := count(`SELECT count(*) FROM assets WHERE kind = 'image'`)
	if workloads < 5 || images < 4 {
		t.Errorf("%d workloads, %d images", workloads, images)
	}
	if n := count(`SELECT count(*) FROM collections WHERE collector_id <> 'plugin:kubernetes' OR method <> 'agent'`); n != 0 {
		t.Errorf("%d collections not under the kubernetes collector", n)
	}
	if n := count(`SELECT count(*) FROM assets WHERE name = 'kind-e2e/shop/deployment/web' AND environment = 'production'`); n != 1 {
		t.Error("the namespace label's environment was not applied to shop/web")
	}
	// Two image scans (imageScans), for exposed images first.
	if n := count(`SELECT count(*) FROM jobs WHERE kind = 'image.scan'`); n != 2 {
		t.Errorf("%d image scans queued, want 2", n)
	}
	if n := count(`SELECT count(*) FROM coverage c JOIN assets a ON a.id = c.asset_id WHERE a.kind = 'image' AND c.collector_id = 'image-scanner' AND c.status = 'skipped'`); n != images {
		t.Errorf("%d of %d images say they are waiting for a scan", n, images)
	}

	// The next run uses the stored token: no new token is made.
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM api_tokens WHERE role = 'collector'`); n != 1 {
		t.Errorf("%d collector tokens after two runs", n)
	}

	// Revoked: refused, and the reporter asks for a new code.
	if _, err := st.Pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE role = 'collector'`); err != nil {
		t.Fatal(err)
	}
	if err := r.runOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "refused this cluster's token") {
		t.Fatalf("revoked token: %v", err)
	}
	if err := r.runOnce(context.Background()); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("revoked token, no new code: %v", err)
	}
	_, code2, err := st.CreateEnrollment(ctx, store.Enrollment{UsesLeft: 1}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.secret["data"].(map[string]any)["enroll-code"] = base64.StdEncoding.EncodeToString([]byte(code2))
	f.rv++
	f.secret["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.rv)
	f.mu.Unlock()
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatalf("re-enrolling with a new code: %v", err)
	}
	if f.key("token") == tok || f.key("enroll-code") != "" {
		t.Error("the new token was not stored")
	}
}

// fakeStackurity is a Stackurity server that records what it is sent.
type fakeStackurity struct {
	mu       sync.Mutex
	enrolls  int
	reports  int
	ingests  int
	features []string
	// enrollStatus, when set, answers /enroll with it.
	enrollStatus int
}

func (f *fakeStackurity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/enroll":
		f.enrolls++
		if f.enrollStatus != 0 {
			w.WriteHeader(f.enrollStatus)
			_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"enrollment code is invalid or expired"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"stk_fake","environment":""}`))
	case "/api/v1/meta":
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "0.13.0", "features": f.features})
	case "/api/v1/kubernetes/report":
		f.reports++
		_, _ = w.Write([]byte(`{"assets":1}`))
	case "/api/v1/ingest":
		f.ingests++
		gz, err := gzip.NewReader(r.Body)
		if err == nil {
			_, _ = io.Copy(io.Discard, gz)
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"asset_id":1}`))
	default:
		w.WriteHeader(404)
	}
}

// The code is used once, so it is redeemed only when the token can be
// stored: with a Role that cannot update the Secret, nothing is redeemed.
func TestKubernetesReporterKeepsCodeWhenSecretIsReadOnly(t *testing.T) {
	fs := &fakeStackurity{features: []string{"kubernetes_report"}}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	f := &fakeCluster{readOnly: true}
	r := newReporter(t, srv.URL, f)
	f.setSecret(map[string]string{"enroll-code": "enr_abc"})
	err := r.runOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "code was not used") || fs.enrolls != 0 {
		t.Errorf("read-only Secret: err %v, %d enroll calls", err, fs.enrolls)
	}
}

// A refused code is not sent again (enrollment is rate limited per
// address) until the Secret holds another one.
func TestKubernetesReporterRefusedCode(t *testing.T) {
	fs := &fakeStackurity{features: []string{"kubernetes_report"}, enrollStatus: 403}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	f := &fakeCluster{}
	r := newReporter(t, srv.URL, f)
	f.setSecret(map[string]string{"enroll-code": "enr_used"})
	for i := 0; i < 3; i++ {
		if err := r.runOnce(context.Background()); !errors.Is(err, errNotEnrolled) || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if fs.enrolls != 1 {
		t.Errorf("the refused code was sent %d times", fs.enrolls)
	}
	fs.enrollStatus = 0
	f.setSecret(map[string]string{"enroll-code": "enr_new"})
	if err := r.runOnce(context.Background()); err != nil || fs.enrolls != 2 || f.key("token") != "stk_fake" {
		t.Errorf("new code: %v, %d enroll calls, token %q", err, fs.enrolls, f.key("token"))
	}
}

// A server without POST /kubernetes/report gets the batches one by one.
func TestKubernetesReporterOlderServer(t *testing.T) {
	fs := &fakeStackurity{features: []string{"upload_project"}}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	f := &fakeCluster{}
	r := newReporter(t, srv.URL, f)
	f.setSecret(map[string]string{"token": "stk_old"})
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fs.reports != 0 || fs.ingests < 10 || fs.enrolls != 0 {
		t.Errorf("older server: %d reports, %d ingests, %d enrolls", fs.reports, fs.ingests, fs.enrolls)
	}
}

func TestKubernetesReporterRefusesPlainHTTP(t *testing.T) {
	t.Setenv("STACKURITY_ALLOW_HTTP", "")
	cmd := kubernetesReporterCmd()
	cmd.SetArgs([]string{"--server", "http://stackurity.example.com", "--once"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("plain HTTP: %v", err)
	}
}
