package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/pkg/plugin"
)

const (
	tenant    = "aaaaaaaa-0000-0000-0000-000000000001"
	sub       = "bbbbbbbb-0000-0000-0000-000000000002"
	appID     = "11111111-2222-3333-4444-555555555555"
	appSecret = "platform-app-secret"
	appOID    = "cccccccc-0000-0000-0000-000000000003" // the app's service principal in the customer's tenant
	custID    = "dddddddd-0000-0000-0000-000000000004"
	custOID   = "eeeeeeee-0000-0000-0000-000000000005"
)

// Azure's documented RBAC action for each call, written down here
// independently of the plugin's catalogue.
var azureAction = []struct {
	re     *regexp.Regexp
	action string
}{
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+$`), "Microsoft.Resources/subscriptions/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.Authorization/roleAssignments$`), "Microsoft.Authorization/roleAssignments/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.DBforMySQL/flexibleServers$`), "Microsoft.DBforMySQL/flexibleServers/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.DBforPostgreSQL/flexibleServers$`), "Microsoft.DBforPostgreSQL/flexibleServers/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.Cache/redis$`), "Microsoft.Cache/redis/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.ContainerService/managedClusters$`), "Microsoft.ContainerService/managedClusters/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/providers/Microsoft.Web/sites$`), "Microsoft.Web/sites/read"},
	{regexp.MustCompile(`^GET /arm/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Web/sites/[^/]+/config/web$`), "Microsoft.Web/sites/config/read"},
}

type fakeAzure struct {
	t          *testing.T
	url        string
	proof      string          // the description proof on the app's assignment
	appInTen   bool            // the customer added the app to the tenant
	denied     map[string]bool // actions the role lacks
	unregister map[string]bool // actions whose resource provider is not registered
	evilNext   bool            // the sites list answers with a nextLink to another host

	mu      sync.Mutex
	calls   []string
	actions map[string]bool
}

func fakeToken(oid string) string {
	p, _ := json.Marshal(map[string]string{"oid": oid, "tid": tenant})
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if r.URL.Path == "/login/"+tenant+"/oauth2/v2.0/token" && r.Method == "POST" {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "https://management.azure.com/.default" {
			oauthErr(w, 400, "invalid_request", "bad grant")
			return
		}
		switch id, secret := form.Get("client_id"), form.Get("client_secret"); {
		case id == appID && secret == appSecret && f.appInTen:
			writeJSON(w, map[string]any{"access_token": fakeToken(appOID), "token_type": "Bearer", "expires_in": 3599})
		case id == appID && secret == appSecret:
			oauthErr(w, 400, "unauthorized_client", "AADSTS700016: Application with identifier '"+appID+"' was not found in the directory.\r\nTrace ID: 1")
		case id == custID && secret == "customer-secret":
			writeJSON(w, map[string]any{"access_token": fakeToken(custOID), "token_type": "Bearer", "expires_in": 3599})
		default:
			oauthErr(w, 401, "invalid_client", "AADSTS7000215: Invalid client secret provided.")
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/arm/") {
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
		return
	}
	auth := r.Header.Get("Authorization")
	oid := tokenClaim(strings.TrimPrefix(auth, "Bearer "), "oid")
	if oid != appOID && oid != custOID {
		armErr(w, 401, "InvalidAuthenticationToken", "no token")
		return
	}
	action := ""
	for _, a := range azureAction {
		if a.re.MatchString(r.Method + " " + r.URL.Path) {
			action = a.action
		}
	}
	if action == "" {
		f.t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		armErr(w, 404, "NotFound", "")
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		f.t.Errorf("%s without api-version", r.URL.Path)
	}
	f.mu.Lock()
	f.actions[action] = true
	f.mu.Unlock()
	if !slices.Contains(cloudconnect.AzureActions(), action) {
		f.t.Errorf("%s needs %s, which the generated role does not grant", r.URL.Path, action)
	}
	if f.unregister[action] {
		armErr(w, 409, "MissingSubscriptionRegistration", "The subscription is not registered to use namespace 'Microsoft.Cache'.")
		return
	}
	if f.denied[action] {
		armErr(w, 403, "AuthorizationFailed", "The client '"+oid+"' does not have authorization to perform action '"+action+"'")
		return
	}
	rg := "/subscriptions/" + sub + "/resourceGroups/prod-rg/providers/"
	next := r.URL.Query().Get("$skiptoken")
	switch action {
	case "Microsoft.Resources/subscriptions/read":
		writeJSON(w, map[string]any{"subscriptionId": sub, "displayName": "Acme Production", "tenantId": tenant, "state": "Enabled"})
	case "Microsoft.Authorization/roleAssignments/read":
		if r.URL.Query().Get("$filter") != "principalId eq '"+oid+"'" {
			f.t.Errorf("role assignment filter %q", r.URL.Query().Get("$filter"))
		}
		var v []any
		if oid == appOID {
			v = append(v, map[string]any{"properties": map[string]string{"description": "unrelated"}})
			if f.proof != "" {
				v = append(v, map[string]any{"properties": map[string]string{"description": cloudconnect.ProofPrefix + f.proof}})
			}
		}
		writeJSON(w, map[string]any{"value": v})
	case "Microsoft.DBforMySQL/flexibleServers/read":
		writeJSON(w, map[string]any{"value": []any{map[string]any{"id": rg + "Microsoft.DBforMySQL/flexibleServers/shop", "name": "shop", "location": "westeurope",
			"tags": map[string]string{"Environment": "production"}, "properties": map[string]string{"version": "8.0.21", "fullVersion": "8.0.21"}}}})
	case "Microsoft.DBforPostgreSQL/flexibleServers/read":
		if next == "" {
			writeJSON(w, map[string]any{"value": []any{map[string]any{"id": rg + "Microsoft.DBforPostgreSQL/flexibleServers/orders", "name": "orders", "location": "westeurope",
				"properties": map[string]string{"version": "13", "minorVersion": "13.14"}}},
				"nextLink": f.url + r.URL.Path + "?api-version=2024-08-01&$skiptoken=p2"})
		} else {
			writeJSON(w, map[string]any{"value": []any{map[string]any{"id": rg + "Microsoft.DBforPostgreSQL/flexibleServers/billing", "name": "billing", "location": "northeurope",
				"properties": map[string]string{"version": "16"}}}})
		}
	case "Microsoft.Cache/redis/read":
		writeJSON(w, map[string]any{"value": []any{map[string]any{"id": rg + "Microsoft.Cache/Redis/sessions", "name": "sessions", "location": "westeurope",
			"properties": map[string]string{"redisVersion": "6.0.14"}}}})
	case "Microsoft.ContainerService/managedClusters/read":
		writeJSON(w, map[string]any{"value": []any{map[string]any{"id": rg + "Microsoft.ContainerService/managedClusters/aks-main", "name": "aks-main", "location": "westeurope",
			"properties": map[string]any{"kubernetesVersion": "1.29", "currentKubernetesVersion": "1.29.7",
				"agentPoolProfiles": []any{map[string]string{"name": "system", "currentOrchestratorVersion": "1.28.5", "osType": "Linux", "mode": "System"}}}}}})
	case "Microsoft.Web/sites/read":
		page := map[string]any{"value": []any{
			map[string]any{"id": rg + "Microsoft.Web/sites/api", "name": "api", "kind": "app,linux", "location": "westeurope",
				"properties": map[string]any{"siteConfig": map[string]string{"linuxFxVersion": "PYTHON|3.8"}}},
			map[string]any{"id": rg + "Microsoft.Web/sites/fn", "name": "fn", "kind": "functionapp,linux", "location": "westeurope",
				"properties": map[string]any{"siteConfig": nil}},
			map[string]any{"id": rg + "Microsoft.Web/sites/legacy", "name": "legacy", "kind": "app", "location": "westeurope", "properties": map[string]any{}},
			map[string]any{"id": rg + "Microsoft.Web/sites/box", "name": "box", "kind": "app,linux,container", "location": "westeurope",
				"properties": map[string]any{"siteConfig": map[string]string{"linuxFxVersion": "DOCKER|nginx:1.27"}}},
		}}
		if f.evilNext {
			page["nextLink"] = "https://evil.example/steal?api-version=1"
		}
		writeJSON(w, page)
	case "Microsoft.Web/sites/config/read":
		switch {
		case strings.Contains(r.URL.Path, "/sites/fn/"):
			writeJSON(w, map[string]any{"properties": map[string]string{"linuxFxVersion": "Node|20"}})
		default:
			writeJSON(w, map[string]any{"properties": map[string]string{"netFrameworkVersion": "v4.0", "phpVersion": ""}})
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, e, d string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e, "error_description": d})
}

func armErr(w http.ResponseWriter, code int, c, m string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": c, "message": m}})
}

type env struct {
	f    *fakeAzure
	p    azurePlugin
	plat *cloudconnect.Platform
}

func setup(t *testing.T) *env {
	t.Helper()
	plat, err := cloudconnect.New("https://app.stackurity.dev", bytes.Repeat([]byte{5}, 32), appID, appSecret)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAzure{t: t, appInTen: true, proof: plat.WorkspaceProof(42), denied: map[string]bool{}, unregister: map[string]bool{}, actions: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return &env{f: f, p: azurePlugin{ep: endpoints{Login: srv.URL + "/login", ARM: srv.URL + "/arm"}}, plat: plat}
}

func (e *env) creds(ws int64) map[string]string {
	return e.plat.PluginCredentials(azurePlugin{}.Metadata().Credentials, ws, time.Now())
}

var appCfg = json.RawMessage(`{"tenant_id": "` + tenant + `", "subscription_id": "` + sub + `", "environment_tag": "environment"}`)

func collect(t *testing.T, e *env, cfg json.RawMessage, secrets map[string]string) map[string]*plugin.ObservationBatch {
	t.Helper()
	if v := e.p.Validate(cfg); !v.OK {
		t.Fatal(v.Problems)
	}
	bs, err := e.p.Collect(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*plugin.ObservationBatch{}
	for _, b := range bs {
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

func TestCollectWithStackurityApp(t *testing.T) {
	e := setup(t)
	got := collect(t, e, appCfg, e.creds(42))
	want := map[string]string{
		"shop":            "pkg:generic/azure-database-for-mysql@8.0.21",
		"orders":          "pkg:generic/azure-database-for-postgresql@13.14",
		"billing":         "pkg:generic/azure-database-for-postgresql@16",
		"sessions":        "pkg:generic/azure-cache-for-redis@6.0.14",
		"aks-main":        "pkg:generic/azure-kubernetes-service@1.29.7",
		"aks-main/system": "pkg:generic/azure-kubernetes-service@1.28.5",
		"api":             "pkg:generic/python@3.8",
		"fn":              "pkg:generic/nodejs@20",
	}
	for name, p := range want {
		if purl(got[name]) != p {
			t.Errorf("%s = %s, want %s", name, purl(got[name]), p)
		}
	}
	shop := got["shop"]
	if shop.Asset.Environment != "production" || shop.Asset.Provider != "azure" || shop.Asset.Region != "westeurope" ||
		shop.Asset.Attributes["resource_group"] != "prod-rg" || shop.Asset.Attributes["subscription"] != sub ||
		shop.Asset.Identifiers[0].Scheme != "azure-resource-id" {
		t.Errorf("shop = %+v", shop.Asset)
	}
	if got["fn"].Asset.Attributes["app_kind"] != "function" {
		t.Errorf("fn = %+v", got["fn"].Asset.Attributes)
	}
	// A Windows app whose runtime is not named is shown as partial, not clean.
	if l := got["legacy"]; l == nil || len(l.Observations) != 0 || l.Coverage[0].Status != "partial" || !strings.Contains(l.Coverage[0].Reason, "app settings") {
		t.Errorf("legacy = %+v", l)
	}
	if _, ok := got["box"]; ok {
		t.Error("container app reported as a runtime")
	}
	if _, ok := got["azure subscription Acme Production ("+sub+")"]; ok {
		t.Error("subscription gap asset without a gap")
	}
	var used []string
	for a := range e.f.actions {
		used = append(used, a)
	}
	sort.Strings(used)
	if !slices.Equal(used, cloudconnect.AzureActions()) {
		t.Errorf("calls needed %v; the role grants %v", used, cloudconnect.AzureActions())
	}
	h := e.p.Health(context.Background(), appCfg, e.creds(42))
	if !h.OK || !strings.Contains(h.Message, "Acme Production") {
		t.Errorf("health = %+v", h)
	}
}

// The app is shared by every workspace. A subscription granted to it from
// workspace 42 cannot be read from workspace 43.
func TestAnotherWorkspaceIsRefused(t *testing.T) {
	e := setup(t)
	_, err := e.p.Collect(context.Background(), appCfg, e.creds(43))
	if err == nil || !strings.Contains(err.Error(), "names this workspace") {
		t.Fatalf("workspace 43 read workspace 42's subscription: %v", err)
	}
	// An assignment without any proof is refused too.
	e2 := setup(t)
	e2.f.proof = ""
	if _, err := e2.p.Collect(context.Background(), appCfg, e2.creds(42)); err == nil {
		t.Error("assignment without a proof accepted")
	}
	for _, c := range append(e.f.calls, e2.f.calls...) {
		if strings.Contains(c, "/providers/Microsoft.") && !strings.Contains(c, "roleAssignments") {
			t.Errorf("inventory read before the proof was checked: %s", c)
		}
	}
	// A workspace's own stored secret cannot stand in for the server's proof
	// (the server strips stackurity_* names; see cloudconnect.StripPlatform).
}

func TestAppNotInTenant(t *testing.T) {
	e := setup(t)
	e.f.appInTen = false
	_, err := e.p.Collect(context.Background(), appCfg, e.creds(42))
	if err == nil || !strings.Contains(err.Error(), "admin consent link") || strings.Contains(err.Error(), appSecret) {
		t.Errorf("app not added: %v", err)
	}
	if _, err := e.p.Collect(context.Background(), appCfg, nil); err == nil || !strings.Contains(err.Error(), "not available on this server") {
		t.Errorf("server without app: %v", err)
	}
}

func TestPermissionDeniedIsCoverageNotZero(t *testing.T) {
	e := setup(t)
	e.f.denied["Microsoft.ContainerService/managedClusters/read"] = true
	e.f.unregister["Microsoft.Cache/redis/read"] = true
	got := collect(t, e, appCfg, e.creds(42))
	s := got["azure subscription Acme Production ("+sub+")"]
	if s == nil {
		t.Fatal("denied service not reported")
	}
	cov := map[string][2]string{}
	for _, c := range s.Coverage {
		cov[c.Scope] = [2]string{c.Status, c.Reason}
	}
	if c := cov["aks"]; c[0] != "failed" || !strings.Contains(c[1], "needs Microsoft.ContainerService/managedClusters/read") {
		t.Errorf("aks = %v", c)
	}
	if c := cov["redis"]; c[0] != "skipped" || !strings.Contains(c[1], "not registered") {
		t.Errorf("redis = %v", c)
	}
	if c := cov["mysql"]; c[0] != "checked" {
		t.Errorf("mysql = %v", c)
	}
	if _, ok := got["aks-main"]; ok {
		t.Error("denied service reported")
	}
}

func TestClientSecretFallback(t *testing.T) {
	e := setup(t)
	cfg := json.RawMessage(`{"tenant_id": "` + tenant + `", "subscription_id": "` + sub + `", "auth": "client_secret", "services": ["aks"]}`)
	got := collect(t, e, cfg, map[string]string{"azure_client_id": custID, "azure_client_secret": "customer-secret"})
	if purl(got["aks-main"]) != "pkg:generic/azure-kubernetes-service@1.29.7" {
		t.Errorf("fallback = %v", got)
	}
	for _, c := range e.f.calls {
		if strings.Contains(c, "roleAssignments") {
			t.Error("the customer's own service principal needs no workspace proof")
		}
	}
	_, err := e.p.Collect(context.Background(), cfg, map[string]string{"azure_client_id": custID, "azure_client_secret": "wrong"})
	if err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "wrong") {
		t.Errorf("wrong secret: %v", err)
	}
}

// A next page link elsewhere would carry the bearer token off Azure.
func TestNextLinkStaysOnResourceManager(t *testing.T) {
	e := setup(t)
	e.f.evilNext = true
	got := collect(t, e, json.RawMessage(`{"tenant_id": "`+tenant+`", "subscription_id": "`+sub+`", "services": ["appservice"]}`), e.creds(42))
	s := got["azure subscription Acme Production ("+sub+")"]
	if s == nil || s.Coverage[0].Status != "failed" || !strings.Contains(s.Coverage[0].Reason, "another host") {
		t.Errorf("foreign nextLink: %+v", s)
	}
}

func TestNetworkPolicyIsEnforced(t *testing.T) {
	e := setup(t)
	ctx := plugin.WithNetwork(context.Background(), netguard.Policy{AllowPrivate: false})
	_, err := e.p.Collect(ctx, appCfg, e.creds(42))
	if !errors.Is(err, netguard.ErrBlocked) || len(e.f.calls) != 0 {
		t.Errorf("loopback reached from a workspace without private access: %v %v", err, e.f.calls)
	}
}

func TestStackVersion(t *testing.T) {
	for _, c := range []struct {
		in   siteConfig
		want string
	}{
		{siteConfig{LinuxFxVersion: "PYTHON|3.12"}, "python 3.12"},
		{siteConfig{LinuxFxVersion: "NODE|20-lts"}, "nodejs 20"},
		{siteConfig{LinuxFxVersion: "DOTNETCORE|8.0"}, "dotnet 8.0"},
		{siteConfig{LinuxFxVersion: "DOTNET-ISOLATED|8"}, "dotnet 8.0"},
		{siteConfig{LinuxFxVersion: "PHP|8.2"}, "php 8.2"},
		{siteConfig{LinuxFxVersion: "JAVA|17-java17"}, "azure-app-service-stack java|17-java17"},
		{siteConfig{LinuxFxVersion: "DOCKER|nginx"}, " "},
		{siteConfig{NetFrameworkVersion: "v8.0"}, "dotnet 8.0"},
		{siteConfig{NetFrameworkVersion: "v4.0", PHPVersion: "8.1"}, "php 8.1"},
		{siteConfig{NetFrameworkVersion: "v4.0", NodeVersion: "~18"}, "nodejs 18"},
		{siteConfig{NetFrameworkVersion: "v4.0", PHPVersion: "Off"}, " "},
	} {
		p, v, _ := stackVersion(c.in)
		if got := p + " " + v; got != c.want {
			t.Errorf("%+v = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, bad := range []string{`{}`, `{"tenant_id": "x", "subscription_id": "` + sub + `"}`,
		`{"tenant_id": "` + tenant + `", "subscription_id": "` + sub + `", "services": ["cosmos"]}`,
		`{"tenant_id": "` + tenant + `", "subscription_id": "` + sub + `", "auth": "managed_identity"}`,
		`{"tenant_id": "` + tenant + `", "subscription_id": "` + sub + `", "login_url": "https://evil"}`} {
		if (azurePlugin{}).Validate(json.RawMessage(bad)).OK {
			t.Errorf("%s accepted", bad)
		}
	}
	if !(azurePlugin{}).Validate(appCfg).OK {
		t.Error("valid config rejected")
	}
}
