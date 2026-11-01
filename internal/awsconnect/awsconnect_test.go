package awsconnect_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/stackurity/stackurity/internal/awsconnect"
	"github.com/stackurity/stackurity/internal/awsconnect/awsfake"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

const (
	principal = "arn:aws:iam::111111111111:user/stackurity"
	ext       = "stk-0123456789abcdef0123456789abcdef"
	role      = "arn:aws:iam::222222222222:role/Stackurity-1-StackurityRole-ABC"
)

func TestQuickCreateURL(t *testing.T) {
	tmplURL := "https://bucket.s3.eu-west-1.amazonaws.com/stackurity-aws-role-v1.json?versionId=a+b&x=1"
	token := "stkcb_eyJ2IjoxfQ.abc+/="
	p := awsconnect.LaunchParams{TemplateURL: tmplURL, Region: "eu-west-1", StackName: "Stackurity-7", Principal: principal,
		ExternalID: ext, AgentInstall: true, CallbackURL: "https://stk.example.com/api/v1/aws/callback", Token: token}
	got, err := awsconnect.QuickCreateURL(p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "eu-west-1.console.aws.amazon.com" || u.Path != "/cloudformation/home" || u.Query().Get("region") != "eu-west-1" {
		t.Fatalf("console address: %s", got)
	}
	route, query, ok := strings.Cut(u.Fragment, "?")
	if !ok || route != "/stacks/create/review" {
		t.Fatalf("fragment %q", u.Fragment)
	}
	// The fragment's query is what the console reads: each value comes back
	// exactly, including the template URL's own query and the token's
	// +, / and =.
	raw := strings.TrimPrefix(got, "https://eu-west-1.console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/create/review?")
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"templateURL": tmplURL, "stackName": "Stackurity-7", "param_StackurityPrincipal": principal, "param_ExternalId": ext,
		"param_EnableAgentInstall": "true", "param_CallbackUrl": p.CallbackURL, "param_CallbackToken": token}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if len(q) != len(want) {
		t.Errorf("parameters %v", q)
	}
	_ = query
	// Without a callback there are no callback parameters (the ARN is pasted).
	p.CallbackURL, p.Token, p.AgentInstall = "", "", false
	got, _ = awsconnect.QuickCreateURL(p)
	if strings.Contains(got, "Callback") || !strings.Contains(got, "param_EnableAgentInstall=false") {
		t.Errorf("no callback: %s", got)
	}
	for name, bad := range map[string]awsconnect.LaunchParams{
		"region":    {TemplateURL: tmplURL, Region: "eu-west-1'", Principal: principal, ExternalID: ext},
		"principal": {TemplateURL: tmplURL, Region: "eu-west-1", Principal: "*", ExternalID: ext},
		"external":  {TemplateURL: tmplURL, Region: "eu-west-1", Principal: principal, ExternalID: "mine"},
		"http":      {TemplateURL: "http://bucket.s3.amazonaws.com/t.json", Region: "eu-west-1", Principal: principal, ExternalID: ext},
	} {
		if _, err := awsconnect.QuickCreateURL(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCallbackToken(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	exp := time.Now().Add(time.Hour)
	tok, hash, err := awsconnect.NewCallbackToken(key, 7, 3, ext, exp)
	if err != nil {
		t.Fatal(err)
	}
	c, err := awsconnect.ParseCallbackToken(key, tok, time.Now())
	if err != nil || c.Connection != 7 || c.Workspace != 3 || c.ExternalID != ext {
		t.Fatalf("%+v %v", c, err)
	}
	if string(awsconnect.NonceHash(c.Nonce)) != string(hash) {
		t.Error("stored hash is not the nonce's")
	}
	tok2, _, _ := awsconnect.NewCallbackToken(key, 7, 3, ext, exp)
	if tok2 == tok {
		t.Error("two tokens are the same")
	}
	payload, sig, _ := strings.Cut(strings.TrimPrefix(tok, "stkcb_"), ".")
	// A token naming another connection, signed by someone without the key.
	other, _, _ := awsconnect.NewCallbackToken([]byte("another key of the right length!"), 8, 3, ext, exp)
	op, _, _ := strings.Cut(strings.TrimPrefix(other, "stkcb_"), ".")
	for name, bad := range map[string]string{
		"wrong key":      other,
		"swapped claims": "stkcb_" + op + "." + sig,
		"no prefix":      payload + "." + sig,
		"no signature":   "stkcb_" + payload,
		"truncated sig":  "stkcb_" + payload + "." + sig[:10],
		"empty":          "",
	} {
		if _, err := awsconnect.ParseCallbackToken(key, bad, time.Now()); !errors.Is(err, awsconnect.ErrBadToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := awsconnect.ParseCallbackToken(key, tok, exp.Add(time.Second)); !errors.Is(err, awsconnect.ErrBadToken) {
		t.Errorf("expired token accepted: %v", err)
	}
}

func TestInstallCommand(t *testing.T) {
	cmd, err := awsconnect.InstallCommand("https://stk.example.com/", "enr_abc123")
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "curl -fsSL --proto '=https,http' 'https://stk.example.com/install/agent.sh' | STACKURITY_ENROLL_CODE='enr_abc123' sh" {
		t.Errorf("command %q", cmd)
	}
	for _, bad := range [][2]string{
		{"https://stk.example.com/'; rm -rf / #", "enr_a"},
		{"https://stk.example.com", "enr_a'; id; '"},
		{"ftp://stk.example.com", "enr_a"},
		{"https://stk example.com", "enr_a"},
	} {
		if _, err := awsconnect.InstallCommand(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func client(f *awsfake.Server) *awsconnect.Client {
	return &awsconnect.Client{Principal: principal, Credentials: credentials.NewStaticCredentialsProvider("AKIASTACKURITY", "secret", ""),
		STSEndpoint: f.URL, SSMEndpoint: f.URL}
}

// The default workspace may reach the loopback fake through netguard.
var wsCtx = tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

func TestVerify(t *testing.T) {
	f := awsfake.New(t)
	f.Roles[role] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: ext}
	c := client(f)
	s, err := c.Verify(wsCtx, role, ext, "stackurity-w1-c7")
	if err != nil {
		t.Fatal(err)
	}
	if s.Account != "222222222222" || !strings.HasPrefix(s.AccessKeyID, "ASIAFAKE") || s.SessionToken == "" {
		t.Errorf("session %+v", s)
	}
	if sec := s.PluginSecrets(); sec["aws_session_token"] == "" || sec["aws_access_key_id"] != s.AccessKeyID {
		t.Errorf("plugin secrets %v", sec)
	}
	// Assumed with the external ID, then without it (refused).
	if len(f.AssumeCalls) != 2 || f.AssumeCalls[0].Get("ExternalId") != ext || f.AssumeCalls[1].Has("ExternalId") ||
		f.AssumeCalls[0].Get("RoleSessionName") != "stackurity-w1-c7" || f.AssumeCalls[0].Get("DurationSeconds") != "3600" {
		t.Errorf("calls %v", f.AssumeCalls)
	}
	// The wrong external ID is refused by AWS, with a message to act on.
	if _, err := c.Verify(wsCtx, role, "stk-ffffffffffffffffffffffffffffffff", "s"); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("wrong external id: %v", err)
	}
	// A role that trusts Stackurity without the external ID is refused.
	loose := "arn:aws:iam::222222222222:role/loose"
	f.Roles[loose] = awsfake.Role{Mode: awsfake.RoleNoExternal}
	if _, err := c.Verify(wsCtx, loose, ext, "s"); !errors.Is(err, awsconnect.ErrNoExternalIDCondition) {
		t.Errorf("role without the condition: %v", err)
	}
	// Bad input never reaches AWS.
	n := len(f.AssumeCalls)
	for _, bad := range []string{"arn:aws:iam::222222222222:user/bob", "arn:aws:iam::22:role/x", "arn:aws-cn:iam::222222222222:role/x"} {
		if _, err := c.Verify(wsCtx, bad, ext, "s"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if len(f.AssumeCalls) != n {
		t.Error("an invalid ARN was sent to AWS")
	}
	if (&awsconnect.Client{}).Enabled() || (*awsconnect.Client)(nil).Enabled() {
		t.Error("a client without a principal is enabled")
	}
}

// Outbound calls go through netguard: a workspace that may not reach
// private addresses cannot be pointed at one, even by the endpoint setting.
func TestNetguardApplies(t *testing.T) {
	f := awsfake.New(t)
	f.Roles[role] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: ext}
	c := client(f)
	other := tenant.WithWorkspace(context.Background(), 42)
	_, err := c.AssumeRole(other, role, ext, "s")
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("loopback endpoint reached from workspace 42: %v", err)
	}
	if len(f.AssumeCalls) != 0 {
		t.Error("the request arrived")
	}
	// Control: the same call from the default workspace arrives.
	if _, err := c.AssumeRole(wsCtx, role, ext, "s"); err != nil {
		t.Fatal(err)
	}
}

func TestSSM(t *testing.T) {
	f := awsfake.New(t)
	f.Roles[role] = awsfake.Role{Mode: awsfake.RoleOK, ExternalID: ext}
	f.PageSize = 2
	for _, id := range []string{"i-0000000000000001", "i-0000000000000002", "i-0000000000000003"} {
		f.Instances = append(f.Instances, map[string]any{"InstanceId": id, "ComputerName": "web-" + id[len(id)-1:] + ".ec2.internal",
			"PlatformType": "Linux", "PingStatus": "Online", "IPAddress": "10.0.0.1"})
	}
	c := client(f)
	s, err := c.AssumeRole(wsCtx, role, ext, "s")
	if err != nil {
		t.Fatal(err)
	}
	list, truncated, err := c.ListInstances(wsCtx, s, "eu-west-1")
	if err != nil || truncated || len(list) != 3 || list[2].ComputerName != "web-3.ec2.internal" || list[0].PlatformType != "Linux" {
		t.Fatalf("%+v %v %v", list, truncated, err)
	}
	cmd, _ := awsconnect.InstallCommand("https://stk.example.com", "enr_one")
	id, err := c.SendInstall(wsCtx, s, "eu-west-1", "i-0000000000000001", cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Sent) != 1 || f.Sent[0].DocumentName != "AWS-RunShellScript" || f.Sent[0].Commands[0] != cmd ||
		f.Sent[0].InstanceIDs[0] != "i-0000000000000001" || f.Sent[0].AccessKey != s.AccessKeyID {
		t.Errorf("sent %+v", f.Sent)
	}
	f.SendErrors["i-0000000000000002"] = "InvalidInstanceId"
	if _, err := c.SendInstall(wsCtx, s, "eu-west-1", "i-0000000000000002", cmd); err == nil || !strings.Contains(err.Error(), "InvalidInstanceId") {
		t.Errorf("send to a bad instance: %v", err)
	}
	for status, want := range map[string]string{"Pending": "pending", "InProgress": "running", "Delayed": "pending", "Success": "success",
		"Failed": "failed", "TimedOut": "timed_out", "Cancelled": "failed"} {
		f.Invocations["i-0000000000000001"] = map[string]any{"Status": status, "StandardOutputContent": "stackurity: installed", "ResponseCode": 1}
		inv, err := c.GetInvocation(wsCtx, s, "eu-west-1", id, "i-0000000000000001")
		if err != nil || inv.Status != want {
			t.Errorf("%s: %+v %v", status, inv, err)
		}
	}
	f.Invocations["i-0000000000000001"] = map[string]any{"Status": "Failed", "StandardErrorContent": "stackurity: error: checksum mismatch", "ResponseCode": 1}
	if inv, _ := c.GetInvocation(wsCtx, s, "eu-west-1", id, "i-0000000000000001"); !strings.Contains(inv.Detail, "checksum mismatch") {
		t.Errorf("failure detail %+v", inv)
	}
	// Just after SendCommand SSM may not know the invocation yet.
	if inv, err := c.GetInvocation(wsCtx, s, "eu-west-1", id, "i-0000000000000009"); err != nil || inv.Status != "pending" {
		t.Errorf("unknown invocation: %+v %v", inv, err)
	}
	// SSM calls are signed with the customer role's session, never with
	// Stackurity's own keys (the fake refuses those).
	bad := &awsconnect.Session{AccessKeyID: "AKIASTACKURITY", SecretAccessKey: "secret"}
	if _, _, err := c.ListInstances(wsCtx, bad, "eu-west-1"); err == nil {
		t.Error("the fake accepted a call without a session")
	}
}
