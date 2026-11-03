package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/pkg/plugin"
)

// Google's documented permission for each call, written down here
// independently of the plugin's catalogue: a call missing from this table,
// or needing a permission the generated role lacks, fails the test.
var googlePermission = []struct {
	re   *regexp.Regexp
	perm string
}{
	{regexp.MustCompile(`^GET /crm/v3/projects/[^/]+$`), "resourcemanager.projects.get"},
	{regexp.MustCompile(`^GET /sqladmin/v1/projects/[^/]+/instances$`), "cloudsql.instances.list"},
	{regexp.MustCompile(`^GET /redis/v1/projects/[^/]+/locations/-/instances$`), "redis.instances.list"},
	{regexp.MustCompile(`^GET /memcache/v1/projects/[^/]+/locations/-/instances$`), "memcache.instances.list"},
	{regexp.MustCompile(`^GET /container/v1/projects/[^/]+/locations/-/clusters$`), "container.clusters.list"},
	{regexp.MustCompile(`^GET /functions/v2/projects/[^/]+/locations/-/functions$`), "cloudfunctions.functions.list"},
	{regexp.MustCompile(`^GET /run/v2/projects/[^/]+/locations/-/services$`), "run.services.list"},
	{regexp.MustCompile(`^GET /appengine/v1/apps/[^/]+/services$`), "appengine.services.list"},
	{regexp.MustCompile(`^GET /appengine/v1/apps/[^/]+/services/[^/]+/versions$`), "appengine.versions.list"},
}

const (
	project   = "acme-prod"
	projNum   = "123456789012"
	workspace = 42
)

// fakeGoogle is Google's STS, IAM credentials, OAuth and inventory APIs.
type fakeGoogle struct {
	t        *testing.T
	jwks     jose.JSONWebKeySet
	keyPub   *rsa.PublicKey
	denied   map[string]bool // permissions the role lacks
	disabled map[string]bool // permissions whose API is not enabled
	noApp    bool            // the project has no App Engine app

	mu    sync.Mutex
	calls []string
	perms map[string]bool
	stray []string // requests to hosts the plugin must never call
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "POST" && r.URL.Path == "/sts/v1/token":
		f.sts(w, body)
		return
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/iamcred/v1/projects/-/serviceAccounts/"):
		if r.Header.Get("Authorization") != "Bearer federated-token" || r.URL.Path != "/iamcred/v1/projects/-/serviceAccounts/stackurity-reader@acme-prod.iam.gserviceaccount.com:generateAccessToken" {
			gerr(w, 403, "PERMISSION_DENIED", "", "iam.serviceAccounts.getAccessToken denied")
			return
		}
		writeJSON(w, map[string]any{"accessToken": "sa-token", "expireTime": time.Now().Add(time.Hour).Format(time.RFC3339)})
		return
	case r.Method == "POST" && r.URL.Path == "/oauth/token":
		f.oauth(w, body)
		return
	case strings.HasPrefix(r.URL.Path, "/evil"):
		f.mu.Lock()
		f.stray = append(f.stray, r.URL.Path)
		f.mu.Unlock()
		return
	}
	if a := r.Header.Get("Authorization"); a != "Bearer sa-token" && a != "Bearer key-token" {
		gerr(w, 401, "UNAUTHENTICATED", "", "no token")
		return
	}
	perm := ""
	for _, p := range googlePermission {
		if p.re.MatchString(r.Method + " " + r.URL.Path) {
			perm = p.perm
		}
	}
	if perm == "" {
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		gerr(w, 404, "NOT_FOUND", "", "no such method")
		return
	}
	f.mu.Lock()
	f.perms[perm] = true
	f.mu.Unlock()
	if !slices.Contains(cloudconnect.GCPPermissions(), perm) {
		f.t.Errorf("%s %s needs %s, which the generated role does not grant", r.Method, r.URL.Path, perm)
	}
	if f.disabled[perm] {
		gerr(w, 403, "PERMISSION_DENIED", "SERVICE_DISABLED", "API has not been used in project 123456789012 before or it is disabled.")
		return
	}
	if f.denied[perm] {
		gerr(w, 403, "PERMISSION_DENIED", "IAM_PERMISSION_DENIED", "Permission '"+perm+"' denied on resource")
		return
	}
	page := r.URL.Query().Get("pageToken")
	switch perm {
	case "resourcemanager.projects.get":
		writeJSON(w, map[string]any{"name": "projects/" + projNum, "projectId": project, "displayName": "Acme production"})
	case "cloudsql.instances.list":
		if page == "" {
			writeJSON(w, map[string]any{"items": []any{
				map[string]any{"name": "orders", "region": "europe-west1", "databaseVersion": "POSTGRES_13", "databaseInstalledVersion": "POSTGRES_13_14",
					"settings": map[string]any{"tier": "db-custom-2-7680", "userLabels": map[string]string{"env": "production"}}},
			}, "nextPageToken": "p2"})
		} else {
			writeJSON(w, map[string]any{"items": []any{
				map[string]any{"name": "legacy", "region": "us-central1", "databaseVersion": "MYSQL_5_7"},
				map[string]any{"name": "erp", "region": "us-central1", "databaseVersion": "SQLSERVER_2019_STANDARD"},
			}})
		}
	case "redis.instances.list":
		writeJSON(w, map[string]any{"instances": []any{map[string]any{"name": "projects/acme-prod/locations/europe-west1/instances/cache", "redisVersion": "REDIS_7_2"}},
			"unreachable": []string{"asia-east2"}})
	case "memcache.instances.list":
		writeJSON(w, map[string]any{"instances": []any{map[string]any{"name": "projects/acme-prod/locations/europe-west1/instances/sessions",
			"memcacheVersion": "MEMCACHE_1_6_15", "memcacheFullVersion": "memcached-1.6.15"}}})
	case "container.clusters.list":
		writeJSON(w, map[string]any{"clusters": []any{map[string]any{"name": "main", "location": "europe-west1", "currentMasterVersion": "1.29.8-gke.1031000",
			"resourceLabels": map[string]string{"env": "production"}, "releaseChannel": map[string]string{"channel": "REGULAR"},
			"nodePools": []any{map[string]any{"name": "default", "version": "1.28.9-gke.1000000"}}}}})
	case "cloudfunctions.functions.list":
		if page == "" {
			writeJSON(w, map[string]any{"functions": []any{map[string]any{"name": "projects/acme-prod/locations/us-central1/functions/resize",
				"environment": "GEN_2", "buildConfig": map[string]string{"runtime": "python38"}}}, "nextPageToken": "f2"})
		} else {
			writeJSON(w, map[string]any{"functions": []any{map[string]any{"name": "projects/acme-prod/locations/us-central1/functions/hook",
				"environment": "GEN_1", "buildConfig": map[string]string{"runtime": "nodejs18"}}}})
		}
	case "run.services.list":
		writeJSON(w, map[string]any{"services": []any{
			map[string]any{"name": "projects/acme-prod/locations/europe-west1/services/api", "template": map[string]any{"containers": []any{
				map[string]any{"image": "europe-docker.pkg.dev/acme/api@sha256:00", "baseImageUri": "europe-west1-docker.pkg.dev/serverless-runtimes/google-22-full/runtimes/go122"}}}},
			map[string]any{"name": "projects/acme-prod/locations/europe-west1/services/web", "template": map[string]any{"containers": []any{map[string]any{"image": "nginx:1.27"}}}},
			map[string]any{"name": "projects/acme-prod/locations/us-central1/services/resize", "labels": map[string]string{"goog-managed-by": "cloudfunctions"},
				"template": map[string]any{"containers": []any{map[string]any{"baseImageUri": "x/runtimes/python38"}}}},
		}})
	case "appengine.services.list":
		if f.noApp {
			gerr(w, 404, "NOT_FOUND", "", "Could not find Application")
			return
		}
		writeJSON(w, map[string]any{"services": []any{map[string]any{"id": "default"}}})
	case "appengine.versions.list":
		writeJSON(w, map[string]any{"versions": []any{
			map[string]any{"id": "v2", "runtime": "php82", "env": "standard", "servingStatus": "SERVING"},
			map[string]any{"id": "v1", "runtime": "php74", "env": "standard", "servingStatus": "STOPPED"},
		}})
	}
}

// sts checks the exchange like a pool whose provider trusts this server's
// key, for workspace 42 only.
func (f *fakeGoogle) sts(w http.ResponseWriter, body []byte) {
	var req map[string]string
	_ = json.Unmarshal(body, &req)
	want := "//iam.googleapis.com/projects/" + projNum + "/locations/global/workloadIdentityPools/stackurity/providers/stackurity"
	if req["grant_type"] != "urn:ietf:params:oauth:grant-type:token-exchange" || req["audience"] != want ||
		req["subject_token_type"] != "urn:ietf:params:oauth:token-type:jwt" {
		gerr(w, 400, "invalid_request", "", "bad exchange "+string(body))
		return
	}
	tok, err := jwt.ParseSigned(req["subject_token"], []jose.SignatureAlgorithm{jose.ES256})
	var c jwt.Claims
	if err == nil {
		err = tok.Claims(f.jwks.Keys[0].Key, &c)
	}
	if err == nil {
		err = c.ValidateWithLeeway(jwt.Expected{Issuer: "https://app.stackurity.dev", AnyAudience: jwt.Audience{cloudconnect.GCPAudience}, Time: time.Now()}, 0)
	}
	if err != nil || c.Subject != "workspace:42" {
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "unauthorized_client", "error_description": "The given credential is rejected by the attribute condition."})
		return
	}
	writeJSON(w, map[string]any{"access_token": "federated-token", "token_type": "Bearer", "expires_in": 3600})
}

func (f *fakeGoogle) oauth(w http.ResponseWriter, body []byte) {
	form, _ := url.ParseQuery(string(body))
	tok, err := jwt.ParseSigned(form.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
	var c jwt.Claims
	if err == nil {
		err = tok.Claims(f.keyPub, &c)
	}
	if err != nil || form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || c.Issuer != "reader@acme-prod.iam.gserviceaccount.com" {
		w.WriteHeader(400)
		writeJSON(w, map[string]string{"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
		return
	}
	writeJSON(w, map[string]any{"access_token": "key-token", "expires_in": 3600})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func gerr(w http.ResponseWriter, code int, status, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	e := map[string]any{"code": code, "status": status, "message": msg}
	if reason != "" {
		e["details"] = []any{map[string]string{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": e})
}

type env struct {
	f       *fakeGoogle
	p       gcpPlugin
	plat    *cloudconnect.Platform
	keyPEM  string
	secrets map[string]string
}

func setup(t *testing.T) *env {
	t.Helper()
	plat, err := cloudconnect.New("https://app.stackurity.dev", bytes.Repeat([]byte{3}, 32), "", "")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{t: t, denied: map[string]bool{}, disabled: map[string]bool{}, perms: map[string]bool{}}
	if err := json.Unmarshal([]byte(plat.JWKS()), &f.jwks); err != nil {
		t.Fatal(err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.keyPub = &rk.PublicKey
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u := srv.URL
	ep := endpoints{STS: u + "/sts", IAMCredentials: u + "/iamcred", OAuthToken: u + "/oauth/token", ResourceManager: u + "/crm",
		SQLAdmin: u + "/sqladmin", Redis: u + "/redis", Memcache: u + "/memcache", Container: u + "/container",
		Functions: u + "/functions", Run: u + "/run", AppEngine: u + "/appengine"}
	return &env{f: f, p: gcpPlugin{ep: ep, now: time.Now}, plat: plat,
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		secrets: plat.PluginCredentials(gcpPlugin{}.Metadata().Credentials, workspace, time.Now())}
}

var keylessCfg = json.RawMessage(`{"project_id": "acme-prod", "project_number": "123456789012", "environment_label": "env"}`)

func collect(t *testing.T, e *env, cfg json.RawMessage, secrets map[string]string) map[string]*plugin.ObservationBatch {
	t.Helper()
	if v := e.p.Validate(cfg); !v.OK {
		t.Fatal(v.Problems)
	}
	batches, err := e.p.Collect(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*plugin.ObservationBatch{}
	for _, b := range batches {
		b.Collector.Method = "plugin"
		if err := b.Validate(); err != nil {
			t.Fatalf("batch %s: %v", b.Asset.Name, err)
		}
		out[b.Asset.Name] = b
	}
	return out
}

func purl(b *plugin.ObservationBatch) string {
	if b == nil || len(b.Observations) != 1 {
		return fmt.Sprintf("%v", b)
	}
	return b.Observations[0].Purl
}

func TestCollectKeyless(t *testing.T) {
	e := setup(t)
	if e.secrets[cloudconnect.CredIdentityToken] == "" {
		t.Fatal("server provided no identity token")
	}
	got := collect(t, e, keylessCfg, e.secrets)
	want := map[string]string{
		"orders":               "pkg:generic/postgresql@13.14",
		"legacy":               "pkg:generic/mysql@5.7",
		"erp":                  "pkg:generic/mssqlserver@15.0",
		"cache":                "pkg:generic/google-cloud-memorystore-redis@7.2",
		"sessions":             "pkg:generic/memcached@1.6.15",
		"main":                 "pkg:generic/google-kubernetes-engine@1.29.8-gke.1031000",
		"main/default":         "pkg:generic/google-kubernetes-engine@1.28.9-gke.1000000",
		"resize":               "pkg:generic/python@3.8",
		"hook":                 "pkg:generic/nodejs@18",
		"api":                  "pkg:generic/go@1.22",
		"acme-prod/default/v2": "pkg:generic/php@8.2",
	}
	for name, p := range want {
		if purl(got[name]) != p {
			t.Errorf("%s = %s, want %s", name, purl(got[name]), p)
		}
	}
	if _, ok := got["web"]; ok {
		t.Error("a container-image Cloud Run service has no runtime and is left to image scanning")
	}
	if _, ok := got["acme-prod/default/v1"]; ok {
		t.Error("stopped App Engine version reported")
	}
	o := got["orders"]
	if o.Asset.Environment != "production" || o.Asset.Provider != "gcp" || o.Asset.Region != "europe-west1" ||
		o.Asset.Identifiers[0].Value != "//sqladmin.googleapis.com/projects/acme-prod/instances/orders" || o.Asset.Attributes["project"] != project {
		t.Errorf("orders asset = %+v", o.Asset)
	}
	// One location of Memorystore did not answer: shown, not hidden.
	proj := got["gcp project acme-prod"]
	if proj == nil {
		t.Fatal("unreachable location not reported")
	}
	cov := map[string]string{}
	for _, c := range proj.Coverage {
		cov[c.Scope] = c.Status + " " + c.Reason
	}
	if !strings.HasPrefix(cov["memorystore"], "partial") || !strings.Contains(cov["memorystore"], "asia-east2") || !strings.HasPrefix(cov["gke"], "checked") {
		t.Errorf("coverage = %v", cov)
	}
	// Every permission of the role was needed, and no other.
	var used []string
	for p := range e.f.perms {
		used = append(used, p)
	}
	sort.Strings(used)
	if !slices.Equal(used, cloudconnect.GCPPermissions()) {
		t.Errorf("calls needed %v; the role grants %v", used, cloudconnect.GCPPermissions())
	}
}

func TestPermissionDeniedIsCoverageNotZero(t *testing.T) {
	e := setup(t)
	e.f.denied["cloudsql.instances.list"] = true
	e.f.disabled["appengine.services.list"] = true
	got := collect(t, e, keylessCfg, e.secrets)
	proj := got["gcp project acme-prod"]
	if proj == nil {
		t.Fatal("denied service not reported")
	}
	cov := map[string][2]string{}
	for _, c := range proj.Coverage {
		cov[c.Scope] = [2]string{c.Status, c.Reason}
	}
	if c := cov["cloudsql"]; c[0] != "failed" || !strings.Contains(c[1], "permission denied (needs cloudsql.instances.list)") {
		t.Errorf("cloudsql coverage = %v", c)
	}
	if c := cov["appengine"]; c[0] != "skipped" || !strings.Contains(c[1], "not enabled") {
		t.Errorf("appengine coverage = %v", c)
	}
	if _, ok := got["orders"]; ok {
		t.Error("denied service reported resources")
	}
	if purl(got["main"]) == "" {
		t.Error("other services stopped after a denial")
	}
	// A project with no App Engine app is checked and empty, not an error.
	e2 := setup(t)
	e2.f.noApp = true
	got = collect(t, e2, json.RawMessage(`{"project_id": "acme-prod", "project_number": "123456789012", "services": ["appengine"]}`), e2.secrets)
	if len(got) != 0 {
		t.Errorf("no App Engine app: %v", got)
	}
}

// Another workspace's token is refused by the pool's attribute condition,
// and a run without a token says how to fix it.
func TestFederationIsBoundToTheWorkspace(t *testing.T) {
	e := setup(t)
	other := e.plat.PluginCredentials([]string{cloudconnect.CredIdentityToken}, 43, time.Now())
	_, err := e.p.Collect(context.Background(), keylessCfg, other)
	if err == nil || !strings.Contains(err.Error(), "attribute condition") {
		t.Errorf("workspace 43 against workspace 42's pool: %v", err)
	}
	_, err = e.p.Collect(context.Background(), keylessCfg, nil)
	if err == nil || !strings.Contains(err.Error(), "keyless access is not available") {
		t.Errorf("no token: %v", err)
	}
	for _, c := range e.f.calls {
		if !strings.HasPrefix(c, "POST /sts/") {
			t.Errorf("a failed exchange went on to call %s", c)
		}
	}
}

func TestServiceAccountKeyFallback(t *testing.T) {
	e := setup(t)
	// The key file's token_uri is ignored: the assertion goes to Google only.
	secrets := map[string]string{"type": "service_account", "client_email": "reader@acme-prod.iam.gserviceaccount.com", "private_key": e.keyPEM,
		"private_key_id": "abc", "token_uri": "http://127.0.0.1:1/evil"}
	got := collect(t, e, json.RawMessage(`{"project_id": "acme-prod", "auth": "service_account_key", "services": ["gke"]}`), secrets)
	if purl(got["main"]) != "pkg:generic/google-kubernetes-engine@1.29.8-gke.1031000" {
		t.Errorf("key fallback: %v", got)
	}
	h := e.p.Health(context.Background(), json.RawMessage(`{"project_id": "acme-prod", "auth": "service_account_key"}`), secrets)
	if !h.OK || !strings.Contains(h.Message, "reader@acme-prod.iam.gserviceaccount.com") {
		t.Errorf("health = %+v", h)
	}
	// A wrong key is refused by Google, and the error says so.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	secrets["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := e.p.Collect(context.Background(), json.RawMessage(`{"project_id": "acme-prod", "auth": "service_account_key"}`), secrets); err == nil ||
		!strings.Contains(err.Error(), "Invalid JWT Signature") {
		t.Errorf("wrong key: %v", err)
	}
}

func TestProjectNumberMismatch(t *testing.T) {
	e := setup(t)
	cfg := json.RawMessage(`{"project_id": "acme-prod", "project_number": "999", "auth": "service_account_key"}`)
	secrets := map[string]string{"client_email": "reader@acme-prod.iam.gserviceaccount.com", "private_key": e.keyPEM}
	if _, err := e.p.Collect(context.Background(), cfg, secrets); err == nil || !strings.Contains(err.Error(), "not the configured 999") {
		t.Errorf("mismatched project number: %v", err)
	}
}

// The fake APIs are on loopback: a workspace without private-network
// access may not reach them.
func TestNetworkPolicyIsEnforced(t *testing.T) {
	e := setup(t)
	ctx := plugin.WithNetwork(context.Background(), netguard.Policy{AllowPrivate: false})
	_, err := e.p.Collect(ctx, keylessCfg, e.secrets)
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("loopback reached from a workspace without private access: %v", err)
	}
	if len(e.f.calls) != 0 {
		t.Errorf("calls made: %v", e.f.calls)
	}
}

func TestVersionMapping(t *testing.T) {
	for in, want := range map[string][2]string{
		"POSTGRES_16": {"postgresql", "16"}, "POSTGRES_15_7": {"postgresql", "15.7"}, "MYSQL_8_0_31": {"mysql", "8.0.31"},
		"MYSQL_8_4": {"mysql", "8.4"}, "SQLSERVER_2022_ENTERPRISE": {"mssqlserver", "16.0"}, "SQLSERVER_2016_WEB": {"", ""}, "": {"", ""},
	} {
		if p, v := cloudSQLVersion(in); p != want[0] || v != want[1] {
			t.Errorf("cloudSQLVersion(%q) = %s %s", in, p, v)
		}
	}
	for in, want := range map[string][2]string{
		"python312": {"python", "3.12"}, "python39": {"python", "3.9"}, "nodejs22": {"nodejs", "22"}, "go121": {"go", "1.21"},
		"ruby33": {"ruby", "3.3"}, "php83": {"php", "8.3"}, "dotnet8": {"dotnet", "8.0"}, "dotnet3": {"dotnet", "3.1"},
		"java17": {"google-cloud-runtime", "java17"}, "custom": {"google-cloud-runtime", "custom"},
	} {
		if p, v := runtimeVersion(in); p != want[0] || v != want[1] {
			t.Errorf("runtimeVersion(%q) = %s %s", in, p, v)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{`{}`, `{"project_id": "acme-prod"}`, `{"project_id": "Acme", "auth": "service_account_key"}`,
		`{"project_id": "acme-prod", "auth": "service_account_key", "services": ["bigquery"]}`,
		`{"project_id": "acme-prod", "auth": "oauth"}`, `{"project_id": "acme-prod", "auth": "service_account_key", "token_url": "http://x"}`,
		`{"project_id": "acme-prod", "project_number": "1", "service_account": "x@evil.com"}`} {
		if (gcpPlugin{}).Validate(json.RawMessage(bad)).OK {
			t.Errorf("%s accepted", bad)
		}
	}
	if !(gcpPlugin{}).Validate(keylessCfg).OK {
		t.Error("valid config rejected")
	}
}
