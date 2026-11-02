package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/awsconnect"
	"github.com/stackurity/stackurity/internal/awsconnect/awsfake"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const (
	awsPrincipal = "arn:aws:iam::111111111111:user/stackurity-cloud"
	awsRole      = "arn:aws:iam::222222222222:role/Stackurity-1-StackurityRole-ABC"
	awsTemplate  = "https://stackurity-templates.s3.eu-west-1.amazonaws.com/stackurity-aws-role-v1.json"
)

// awsClient talks to the fake directly: the fake is on a loopback address,
// which netguard keeps from every workspace but the default one
// (awsconnect.TestNetguardApplies covers the guard).
func awsClient(f *awsfake.Server) *awsconnect.Client {
	return &awsconnect.Client{Principal: awsPrincipal, TemplateURL: awsTemplate,
		Credentials: credentials.NewStaticCredentialsProvider("AKIASTACKURITY", "server-secret", ""),
		STSEndpoint: f.URL, SSMEndpoint: f.URL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func awsEnv(t *testing.T) (*env, *awsfake.Server, *session) {
	f := awsfake.New(t)
	e := newEnvWith(t, func(s *api.Server) {
		s.BaseURL = "https://stk.example.com"
		s.AWS = awsClient(f)
	})
	e.user("admin@x.io", auth.RoleAdmin)
	return e, f, e.login("admin@x.io")
}

type awsCreated struct {
	Connection struct {
		store.AWSConnection
		IntegrationRemoved bool `json:"integration_removed"`
	}
	Launch struct {
		QuickCreateURL string `json:"quick_create_url"`
		ExternalID     string `json:"external_id"`
		Principal      string `json:"principal"`
		Callback       bool   `json:"callback"`
		CLI            string `json:"cli"`
	}
}

func createAWS(t *testing.T, admin *session, body map[string]any) awsCreated {
	t.Helper()
	var out awsCreated
	if code := admin.do("POST", "/api/v1/aws/connections", body, &out); code != 201 {
		t.Fatalf("create connection: %d", code)
	}
	return out
}

// launchParams reads the quick-create link's parameters.
func launchParams(t *testing.T, link string) url.Values {
	t.Helper()
	_, q, ok := strings.Cut(link, "#/stacks/create/review?")
	if !ok {
		t.Fatalf("not a quick-create link: %s", link)
	}
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func postCallback(t *testing.T, e *env, token string, body map[string]string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/aws/callback", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func getAWS(t *testing.T, admin *session, id int64) store.AWSConnection {
	t.Helper()
	var out struct{ Connection store.AWSConnection }
	if code := admin.do("GET", "/api/v1/aws/connections/"+itoa(id), nil, &out); code != 200 {
		t.Fatalf("get connection %d: %d", id, code)
	}
	return out.Connection
}

var wsCtx = tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

// The Launch Stack flow: the link carries the connection's external ID,
// the server's principal and a signed single-use token; the stack's
// callback activates the connection once the role is verified, and the
// token cannot be used again, for another connection, or after it expired
// or was replaced.
func TestAWSLaunchStackCallback(t *testing.T) {
	e, f, admin := awsEnv(t)

	var setup struct {
		Enabled     bool
		Principal   string
		LaunchStack bool `json:"launch_stack"`
		Permissions []string
	}
	if code := admin.do("GET", "/api/v1/aws/connections", nil, &setup); code != 200 || !setup.Enabled || setup.Principal != awsPrincipal ||
		!setup.LaunchStack || len(setup.Permissions) != len(awsconnect.ReadOnlyActions) {
		t.Fatalf("setup: %d %+v", code, setup)
	}

	c := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1", "us-east-1", "eu-west-1"}, "stack_region": "eu-central-1", "agent_install": true})
	if c.Connection.Status != "pending" || len(c.Connection.Regions) != 2 || !c.Connection.AgentInstall || c.Launch.ExternalID != c.Connection.ExternalID ||
		!regexp.MustCompile(`^stk-[0-9a-f]{32}$`).MatchString(c.Launch.ExternalID) || !c.Launch.Callback {
		t.Fatalf("created %+v", c)
	}
	p := launchParams(t, c.Launch.QuickCreateURL)
	if !strings.HasPrefix(c.Launch.QuickCreateURL, "https://eu-central-1.console.aws.amazon.com/cloudformation/home?region=eu-central-1#") ||
		p.Get("templateURL") != awsTemplate || p.Get("param_ExternalId") != c.Connection.ExternalID || p.Get("param_StackurityPrincipal") != awsPrincipal ||
		p.Get("param_EnableAgentInstall") != "true" || p.Get("param_CallbackUrl") != "https://stk.example.com/api/v1/aws/callback" {
		t.Fatalf("link %s", c.Launch.QuickCreateURL)
	}
	token := p.Get("param_CallbackToken")
	if !strings.HasPrefix(token, "stkcb_") || !strings.Contains(c.Launch.CLI, "ParameterKey=CallbackToken,ParameterValue="+token) {
		t.Fatalf("token %q cli %q", token, c.Launch.CLI)
	}
	f.Roles[awsRole] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: c.Connection.ExternalID}
	body := map[string]string{"role_arn": awsRole, "external_id": c.Connection.ExternalID,
		"stack_id": "arn:aws:cloudformation:eu-central-1:222222222222:stack/Stackurity-1/abc"}

	// Refused before anything is used: no token, the stack in another
	// account, another connection's external ID.
	if code, _ := postCallback(t, e, "", body); code != 403 {
		t.Errorf("no token: %d", code)
	}
	wrongStack := map[string]string{"role_arn": awsRole, "external_id": c.Connection.ExternalID, "stack_id": "arn:aws:cloudformation:eu-central-1:333333333333:stack/x/y"}
	if code, _ := postCallback(t, e, token, wrongStack); code != 400 {
		t.Errorf("stack in another account: %d", code)
	}
	other := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1"}})
	if code, _ := postCallback(t, e, token, map[string]string{"role_arn": awsRole, "external_id": other.Connection.ExternalID}); code != 403 {
		t.Errorf("another connection's external ID: %d", code)
	}
	if got := getAWS(t, admin, c.Connection.ID); got.Status != "pending" || got.CallbackUsedAt != nil || got.RoleARN != "" {
		t.Fatalf("a refused callback changed the connection: %+v", got)
	}

	code, resp := postCallback(t, e, token, body)
	if code != 200 || !strings.Contains(resp, `"active"`) {
		t.Fatalf("callback: %d %s", code, resp)
	}
	got := getAWS(t, admin, c.Connection.ID)
	if got.Status != "active" || got.AccountID != "222222222222" || got.RoleARN != awsRole || got.IntegrationID == nil || got.CallbackUsedAt == nil {
		t.Fatalf("after callback %+v", got)
	}
	in, err := e.st.GetIntegration(wsCtx, *got.IntegrationID)
	if err != nil {
		t.Fatal(err)
	}
	if in.Kind != "plugin" || in.Name != "AWS 222222222222" || in.SecretRef != "" || strings.Contains(string(in.Config), "role") ||
		strings.Contains(string(in.Config), "external") || !strings.Contains(string(in.Config), `"aws-managed"`) {
		t.Errorf("integration %+v %s", in, in.Config)
	}
	var queued int
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM jobs WHERE kind = 'integration.run' AND payload->>'integration_id' = $1`,
		itoa(*got.IntegrationID)).Scan(&queued); err != nil || queued != 1 {
		t.Errorf("first run queued: %d %v", queued, err)
	}
	// The role was assumed with the external ID, and refused without it.
	if n := len(f.AssumeCalls); n != 2 || f.AssumeCalls[0].Get("ExternalId") != c.Connection.ExternalID || f.AssumeCalls[1].Has("ExternalId") {
		t.Errorf("assume calls %v", f.AssumeCalls)
	}

	// The token is single use.
	if code, _ := postCallback(t, e, token, body); code != 403 {
		t.Errorf("replayed token: %d", code)
	}

	// A token that was replaced by a new link stops working; the new one works.
	var re awsCreated
	if code := admin.do("POST", "/api/v1/aws/connections/"+itoa(other.Connection.ID)+"/launch", map[string]any{"stack_region": "eu-west-1"}, &re); code != 200 {
		t.Fatalf("new link: %d", code)
	}
	oldToken := launchParams(t, other.Launch.QuickCreateURL).Get("param_CallbackToken")
	newToken := launchParams(t, re.Launch.QuickCreateURL).Get("param_CallbackToken")
	role2 := "arn:aws:iam::222222222222:role/second"
	f.Roles[role2] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: other.Connection.ExternalID}
	body2 := map[string]string{"role_arn": role2, "external_id": other.Connection.ExternalID}
	if code, _ := postCallback(t, e, oldToken, body2); code != 403 {
		t.Errorf("replaced token: %d", code)
	}
	// Tampered: the signature no longer matches.
	if code, _ := postCallback(t, e, newToken[:len(newToken)-2]+"AA", body2); code != 403 {
		t.Errorf("tampered token: %d", code)
	}
	// Expired in the store (the signed expiry is still ahead).
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE aws_connections SET callback_expires_at = now() - interval '1 second' WHERE id = $1`,
		other.Connection.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := postCallback(t, e, newToken, body2); code != 403 {
		t.Errorf("expired token: %d", code)
	}
	// Used even when the role could not be verified: the stack reported
	// before the role existed, and the same token cannot try again (the
	// administrator verifies again instead, or makes a new link).
	third := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1"}})
	thirdToken := launchParams(t, third.Launch.QuickCreateURL).Get("param_CallbackToken")
	role3 := "arn:aws:iam::222222222222:role/third"
	body3 := map[string]string{"role_arn": role3, "external_id": third.Connection.ExternalID}
	if code, resp := postCallback(t, e, thirdToken, body3); code != 200 || !strings.Contains(resp, `"failed"`) {
		t.Fatalf("callback before the role exists: %d %s", code, resp)
	}
	f.Roles[role3] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: third.Connection.ExternalID}
	if code, _ := postCallback(t, e, thirdToken, body3); code != 403 {
		t.Errorf("token reused after a failed verification: %d", code)
	}
	var again struct{ Connection store.AWSConnection }
	if code := admin.do("POST", "/api/v1/aws/connections/"+itoa(third.Connection.ID)+"/verify", map[string]string{}, &again); code != 200 ||
		again.Connection.Status != "active" || again.Connection.RoleARN != role3 {
		t.Errorf("verify again with the reported role: %d %+v", code, again.Connection)
	}
	// An active connection makes no new links.
	if code := admin.do("POST", "/api/v1/aws/connections/"+itoa(c.Connection.ID)+"/launch", map[string]any{}, nil); code != 409 {
		t.Errorf("link for an active connection: %d", code)
	}
}

// A token is bound to its workspace: even a correctly signed token that
// names another workspace's connection changes nothing.
func TestAWSCallbackBoundToWorkspace(t *testing.T) {
	e, f, admin := awsEnv(t)
	ctx := context.Background()
	beta, _, err := e.st.CreateWorkspace(ctx, "Beta Corp", "", "admin-beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	betaAdmin := e.login("admin-beta@x.io")
	a := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1"}})
	b := createAWS(t, betaAdmin, map[string]any{"regions": []string{"eu-west-1"}})
	if b.Connection.WorkspaceID != beta.ID || a.Connection.WorkspaceID != tenant.DefaultWorkspace {
		t.Fatalf("workspaces %d %d", a.Connection.WorkspaceID, b.Connection.WorkspaceID)
	}
	// B's admin cannot see or use A's connection.
	for _, r := range [][2]string{{"GET", ""}, {"POST", "/verify"}, {"POST", "/launch"}, {"GET", "/installs"}, {"DELETE", ""}} {
		if code := betaAdmin.do(r[0], "/api/v1/aws/connections/"+itoa(a.Connection.ID)+r[1], map[string]any{}, nil); code != 404 {
			t.Errorf("B %s %s: %d", r[0], r[1], code)
		}
	}
	key, err := e.st.PlatformKey(tenant.System(ctx), "aws-callback")
	if err != nil {
		t.Fatal(err)
	}
	f.Roles[awsRole] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: a.Connection.ExternalID}
	// Signed with the real key, naming A's connection and external ID but
	// B's workspace (and so a nonce A's connection never stored).
	forged, _, err := awsconnect.NewCallbackToken(key, a.Connection.ID, beta.ID, a.Connection.ExternalID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postCallback(t, e, forged, map[string]string{"role_arn": awsRole, "external_id": a.Connection.ExternalID}); code != 403 {
		t.Errorf("token naming another workspace: %d", code)
	}
	// A's genuine token re-signed (with the real key, so only the store's
	// binding can catch it) to name B's workspace, or another external ID:
	// the nonce is A's, everything else must match too.
	aToken := launchParams(t, a.Launch.QuickCreateURL).Get("param_CallbackToken")
	claims, err := awsconnect.ParseCallbackToken(key, aToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(c *awsconnect.CallbackClaims){
		"workspace":   func(c *awsconnect.CallbackClaims) { c.Workspace = beta.ID },
		"external id": func(c *awsconnect.CallbackClaims) { c.ExternalID = b.Connection.ExternalID },
		"connection":  func(c *awsconnect.CallbackClaims) { c.Connection = b.Connection.ID },
	} {
		m := claims
		mutate(&m)
		if code, _ := postCallback(t, e, awsconnect.SignCallbackClaims(key, m), map[string]string{"role_arn": awsRole, "external_id": m.ExternalID}); code != 403 {
			t.Errorf("A's nonce with another %s: %d", name, code)
		}
	}
	// B's genuine token presented with A's external ID.
	bToken := launchParams(t, b.Launch.QuickCreateURL).Get("param_CallbackToken")
	if code, _ := postCallback(t, e, bToken, map[string]string{"role_arn": awsRole, "external_id": a.Connection.ExternalID}); code != 403 {
		t.Errorf("B's token with A's external ID: %d", code)
	}
	if got := getAWS(t, admin, a.Connection.ID); got.Status != "pending" || got.RoleARN != "" {
		t.Errorf("A's connection changed: %+v", got)
	}
	if len(f.AssumeCalls) != 0 {
		t.Errorf("AWS was called: %v", f.AssumeCalls)
	}
	// Control: A's own token, unchanged, still works.
	if code, resp := postCallback(t, e, aToken, map[string]string{"role_arn": awsRole, "external_id": a.Connection.ExternalID}); code != 200 ||
		!strings.Contains(resp, "active") {
		t.Errorf("A's token: %d %s", code, resp)
	}
}

// Pasting the role ARN (the fallback when the stack cannot call back), the
// checks on the role, and the integration the connection owns.
func TestAWSPasteRoleARN(t *testing.T) {
	e, f, admin := awsEnv(t)
	e.user("eng@x.io", auth.RoleEngineer)
	eng := e.login("eng@x.io")
	c := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1"}})
	path := "/api/v1/aws/connections/" + itoa(c.Connection.ID)
	verify := func(role string) store.AWSConnection {
		t.Helper()
		var out struct{ Connection store.AWSConnection }
		if code := admin.do("POST", path+"/verify", map[string]string{"role_arn": role}, &out); code != 200 {
			t.Fatalf("verify %s: %d", role, code)
		}
		return out.Connection
	}
	if code := eng.do("POST", path+"/verify", map[string]string{"role_arn": awsRole}, nil); code != 403 {
		t.Errorf("engineer verifies: %d", code)
	}
	if code := admin.do("POST", path+"/verify", map[string]string{"role_arn": "arn:aws:iam::222222222222:user/bob"}, nil); code != 400 {
		t.Errorf("a user ARN: %d", code)
	}
	// The stack is not there yet: AWS refuses.
	if got := verify(awsRole); got.Status != "failed" || !strings.Contains(got.LastError, "AccessDenied") || got.IntegrationID != nil {
		t.Errorf("no role: %+v", got)
	}
	// A role that does not require the external ID is refused.
	f.Roles[awsRole] = awsfake.Role{Mode: awsfake.RoleNoExternal}
	if got := verify(awsRole); got.Status != "failed" || !strings.Contains(got.LastError, "without the external ID") {
		t.Errorf("role without the condition: %+v", got)
	}
	f.Roles[awsRole] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: c.Connection.ExternalID}
	got := verify(awsRole)
	if got.Status != "active" || got.IntegrationID == nil || got.LastError != "" {
		t.Fatalf("verified: %+v", got)
	}
	if code := admin.do("POST", path+"/verify", map[string]string{"role_arn": "arn:aws:iam::222222222222:role/other"}, nil); code != 409 {
		t.Errorf("another role for an active connection: %d", code)
	}
	integ := *got.IntegrationID

	// The run gets a session of the role, never a role to assume.
	cfg := api.PluginConfig{Plugin: "aws-managed", Config: json.RawMessage(`{"regions":["eu-west-1"],"role_arn":"arn:aws:iam::999999999999:role/x","external_id":"x"}`)}
	out, creds, linked, err := api.AWSPluginRun(wsCtx, e.st, e.api.AWS, integ, cfg)
	if err != nil || !linked {
		t.Fatalf("run: %v %v", linked, err)
	}
	if !strings.HasPrefix(creds["aws_access_key_id"], "ASIAFAKE") || creds["aws_session_token"] == "" || creds["aws_secret_access_key"] == "server-secret" {
		t.Errorf("plugin credentials %v", creds)
	}
	if strings.Contains(string(out.Config), "role_arn") || strings.Contains(string(out.Config), "external_id") {
		t.Errorf("plugin config %s", out.Config)
	}
	if _, _, linked, err := api.AWSPluginRun(wsCtx, e.st, e.api.AWS, integ, api.PluginConfig{Plugin: "kubernetes"}); !linked || err == nil {
		t.Errorf("another plugin was given the session: %v", err)
	}
	if _, creds, linked, err := api.AWSPluginRun(wsCtx, e.st, e.api.AWS, integ+1000, cfg); linked || err != nil || creds != nil {
		t.Errorf("an unrelated integration: %v %v %v", linked, creds, err)
	}

	// Its integration takes no secret, runs only aws-managed, and names no role.
	ipath := "/api/v1/integrations/" + itoa(integ)
	for name, body := range map[string]map[string]any{
		"secret":      {"secret_ref": "secret:AWS_KEYS"},
		"plugin":      {"config": map[string]any{"plugin": "kubernetes", "config": map[string]any{}}},
		"role":        {"config": map[string]any{"plugin": "aws-managed", "config": map[string]any{"regions": []string{"eu-west-1"}, "role_arn": "arn:aws:iam::999999999999:role/x"}}},
		"external id": {"config": map[string]any{"plugin": "aws-managed", "config": map[string]any{"regions": []string{"eu-west-1"}, "external_id": "x"}}},
	} {
		if code := admin.do("PATCH", ipath, body, nil); code < 400 || code >= 500 {
			t.Errorf("%s: %d", name, code)
		}
	}

	if code := admin.do("DELETE", path, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := e.st.GetIntegration(wsCtx, integ); err == nil {
		t.Error("the integration outlived its connection")
	}
}

// Agent installs through SSM: instances SSM manages are listed with the
// ones already reporting, each chosen instance gets its own single-use
// code, and each result is read back from SSM (success, failure, a send
// SSM refused, and a command that never ended).
func TestAWSAgentInstallSSM(t *testing.T) {
	e, f, admin := awsEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	c := createAWS(t, admin, map[string]any{"regions": []string{"eu-west-1"}, "agent_install": true})
	path := "/api/v1/aws/connections/" + itoa(c.Connection.ID)
	if code := admin.do("GET", path+"/instances", nil, nil); code != 409 {
		t.Errorf("instances before the role is verified: %d", code)
	}
	f.Roles[awsRole] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: c.Connection.ExternalID}
	if code := admin.do("POST", path+"/verify", map[string]string{"role_arn": awsRole}, nil); code != 200 {
		t.Fatal(code)
	}
	ids := []string{"i-0000000000000001", "i-0000000000000002", "i-0000000000000003", "i-0000000000000004", "i-0000000000000005", "i-0000000000000006"}
	f.Instances = []map[string]any{
		{"InstanceId": ids[0], "ComputerName": "web-1.eu-west-1.compute.internal", "PlatformType": "Linux", "PingStatus": "Online"},
		{"InstanceId": ids[1], "ComputerName": "web-2", "PlatformType": "Linux", "PingStatus": "Online"},
		{"InstanceId": ids[2], "ComputerName": "win-1", "PlatformType": "Windows", "PingStatus": "Online"},
		{"InstanceId": ids[3], "ComputerName": "db-1", "PlatformType": "Linux", "PingStatus": "ConnectionLost"},
	}
	// web-2 already reports through the agent.
	var me struct{ User store.User }
	admin.do("GET", "/api/v1/auth/me", nil, &me)
	_, collector, err := e.st.CreateToken(wsCtx, "collector", auth.RoleCollector, nil, me.User.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := bearerBody(e, collector, "POST", "/api/v1/ingest", hostBatch(model.AssetHost, "web-2", "hostname")); code != 201 {
		t.Fatalf("ingest: %d %s", code, body)
	}
	var list struct {
		Items []struct {
			InstanceID string `json:"instance_id"`
			Eligible   bool
			AssetID    *int64 `json:"asset_id"`
		}
	}
	if code := admin.do("GET", path+"/instances", nil, &list); code != 200 || len(list.Items) != 4 {
		t.Fatalf("instances: %d %+v", code, list)
	}
	for i, want := range []struct{ eligible, covered bool }{{true, false}, {true, true}, {false, false}, {false, false}} {
		got := list.Items[i]
		if got.Eligible != want.eligible || (got.AssetID != nil) != want.covered {
			t.Errorf("%s: eligible %v covered %v", got.InstanceID, got.Eligible, got.AssetID != nil)
		}
	}
	if code := admin.do("GET", path+"/instances?region=us-east-1", nil, nil); code != 400 {
		t.Errorf("a region outside the connection: %d", code)
	}

	inst := func(ids ...string) map[string]any {
		var l []map[string]string
		for _, id := range ids {
			l = append(l, map[string]string{"instance_id": id, "computer_name": "name-" + id})
		}
		return map[string]any{"instances": l}
	}
	if code := view.do("POST", path+"/installs", inst(ids[0]), nil); code != 403 {
		t.Errorf("viewer installs: %d", code)
	}
	if code := admin.do("POST", path+"/installs", inst("i-0000000000000001; id"), nil); code != 400 {
		t.Errorf("a bad instance id: %d", code)
	}
	many := make([]string, 26)
	for i := range many {
		many[i] = "i-" + strings.Repeat("0", 14) + string(rune('a'+i%6)) + string(rune('a'+i/6))
	}
	if code := admin.do("POST", path+"/installs", inst(many...), nil); code != 400 {
		t.Errorf("26 instances: %d", code)
	}
	f.SendErrors[ids[4]] = "InvalidInstanceId"
	var sent struct{ Items []store.AWSAgentInstall }
	if code := admin.do("POST", path+"/installs", inst(ids[0], ids[1], ids[4], ids[5]), &sent); code != 202 || len(sent.Items) != 4 {
		t.Fatalf("install: %d %+v", code, sent)
	}
	byInstance := map[string]store.AWSAgentInstall{}
	for _, in := range sent.Items {
		byInstance[in.InstanceID] = in
	}
	if s := byInstance[ids[4]]; s.Status != "failed" || !strings.Contains(s.Detail, "InvalidInstanceId") || s.CommandID != "" {
		t.Errorf("refused send: %+v", s)
	}
	// One command per instance, each with its own code and this server's
	// installer.
	if len(f.Sent) != 3 {
		t.Fatalf("sent %+v", f.Sent)
	}
	codeRE := regexp.MustCompile(`STACKURITY_ENROLL_CODE='(enr_[A-Za-z0-9_]+)'`)
	codes := map[string]string{}
	for _, s := range f.Sent {
		m := codeRE.FindStringSubmatch(s.Commands[0])
		if m == nil || s.DocumentName != "AWS-RunShellScript" || len(s.InstanceIDs) != 1 ||
			!strings.HasPrefix(s.Commands[0], "curl -fsSL --proto '=https,http' 'https://stk.example.com/install/agent.sh' | ") {
			t.Fatalf("command %+v", s)
		}
		codes[s.InstanceIDs[0]] = m[1]
	}
	if len(codes) != 3 || codes[ids[0]] == codes[ids[1]] {
		t.Errorf("codes are not per instance: %v", codes)
	}
	// The codes are never stored with the installs.
	var raw string
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT string_agg(command_id || detail, '') FROM aws_agent_installs`).Scan(&raw); err != nil ||
		strings.Contains(raw, "enr_") {
		t.Errorf("a code was stored: %q %v", raw, err)
	}

	f.Lock(func() {
		f.Invocations[ids[0]] = map[string]any{"Status": "Success", "StandardOutputContent": "stackurity: enrolled"}
		f.Invocations[ids[1]] = map[string]any{"Status": "Failed", "StandardErrorContent": "stackurity: error: systemd is required", "ResponseCode": 1}
	})
	// ids[5]'s command never shows up in SSM; make it look 30 minutes old.
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE aws_agent_installs SET created_at = now() - interval '30 minutes' WHERE instance_id = $1`, ids[5]); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Items        []store.AWSAgentInstall
		RefreshError string `json:"refresh_error"`
	}
	if code := view.do("GET", path+"/installs", nil, &res); code != 403 {
		t.Errorf("viewer reads installs: %d", code)
	}
	if code := admin.do("GET", path+"/installs", nil, &res); code != 200 || res.RefreshError != "" || len(res.Items) != 4 {
		t.Fatalf("installs: %d %+v", code, res)
	}
	status := map[string]store.AWSAgentInstall{}
	for _, in := range res.Items {
		status[in.InstanceID] = in
	}
	for id, want := range map[string]string{ids[0]: "success", ids[1]: "failed", ids[4]: "failed", ids[5]: "timed_out"} {
		if status[id].Status != want {
			t.Errorf("%s: %s (%s), want %s", id, status[id].Status, status[id].Detail, want)
		}
	}
	if !strings.Contains(status[ids[1]].Detail, "systemd is required") {
		t.Errorf("failure detail %q", status[ids[1]].Detail)
	}
	// Codes of failed and timed-out installs are revoked; the successful
	// one is single use.
	for _, id := range []string{ids[1], ids[5]} {
		if code := e.anon().do("POST", "/api/v1/enroll", map[string]string{"code": codes[id], "hostname": "x"}, nil); code != 403 {
			t.Errorf("%s's code still works: %d", id, code)
		}
	}
	enroll := map[string]string{"code": codes[ids[0]], "hostname": "web-1"}
	if code := e.anon().do("POST", "/api/v1/enroll", enroll, nil); code != 200 {
		t.Errorf("enroll with the instance's code: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/enroll", enroll, nil); code != 403 {
		t.Errorf("the code worked twice: %d", code)
	}
}

// Without STACKURITY_AWS_PRINCIPAL_ARN nothing can be connected, and the
// page says so; the template is still served for review.
func TestAWSDisabled(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var out struct{ Enabled bool }
	if code := admin.do("GET", "/api/v1/aws/connections", nil, &out); code != 200 || out.Enabled {
		t.Errorf("list: %d %+v", code, out)
	}
	if code := admin.do("POST", "/api/v1/aws/connections", map[string]any{"regions": []string{"eu-west-1"}}, nil); code != 404 {
		t.Errorf("create: %d", code)
	}
	resp, err := http.Get(e.srv.URL + "/aws/" + awsconnect.TemplateFile)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(b, awsconnect.Template()) {
		t.Errorf("template: %d", resp.StatusCode)
	}
}
