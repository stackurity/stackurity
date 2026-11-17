package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPolicyFlagValidation(t *testing.T) {
	for in, want := range map[string]string{"": "auto", "auto": "auto", "OFF": "off", " off ": "off"} {
		p := policyGate{mode: in}
		if err := p.validate(); err != nil || p.mode != want {
			t.Errorf("--policy %q: %q %v", in, p.mode, err)
		}
	}
	for _, bad := range []string{"on", "enforce", "warn"} {
		p := policyGate{mode: bad}
		if err := p.validate(); err == nil {
			t.Errorf("--policy %q accepted", bad)
		}
	}
	// scan refuses a bad --policy before it scans anything.
	if _, err := runScan(t, t.TempDir(), "--policy", "maybe", "--output", "-"); err == nil || !strings.Contains(err.Error(), "--policy must be auto or off") {
		t.Errorf("scan --policy maybe: %v", err)
	}

	for _, tc := range []struct {
		o    policyCheckOptions
		want string // "" for valid
	}{
		{policyCheckOptions{}, "one of --asset, --image and --repo"},
		{policyCheckOptions{asset: 1, repo: "https://github.com/acme/app"}, "one of --asset, --image and --repo"},
		{policyCheckOptions{asset: -1}, "--asset must be an asset id"},
		{policyCheckOptions{image: "nginx:1.27"}, "--image takes an image digest"},
		{policyCheckOptions{image: "sha256:abc"}, "--image takes an image digest"},
		{policyCheckOptions{asset: 7}, ""},
		{policyCheckOptions{image: testDigest}, ""},
		{policyCheckOptions{image: "ghcr.io/acme/app@" + testDigest}, ""},
		{policyCheckOptions{repo: "https://github.com/acme/app", commit: "abc", ref: "v1"}, ""},
	} {
		req, err := tc.o.request()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%+v: %v", tc.o, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%+v: %v, want %q", tc.o, err, tc.want)
		case tc.want == "" && req.Source != "deploy":
			t.Errorf("%+v: source %q", tc.o, req.Source)
		}
		if tc.o.image != "" && tc.want == "" && req.ImageDigest != testDigest {
			t.Errorf("%+v: digest %q", tc.o, req.ImageDigest)
		}
	}
}

func id64(n int64) *int64 { return &n }

var (
	warnCheck = &client.PolicyCheck{CheckID: 3, Result: "warn", AssetID: 4, AssetName: "app", PoliciesEvaluated: 2,
		Violations: []client.PolicyViolation{{PolicyID: 1, PolicyName: "No old criticals", Mode: "warn", Kind: "finding_age",
			Reason: "CVE-1 in openssl 3.0.2 (critical) has been open for 30 days; the limit is 14", Component: "openssl 3.0.2",
			FindingID: id64(12), Link: "https://s.example/findings/12"}}}
	planCheck = &client.PolicyCheck{CheckID: 4, Result: "warn", AssetID: 4, AssetName: "app", PoliciesEvaluated: 1,
		Violations: []client.PolicyViolation{{PolicyID: 2, PolicyName: "No KEV", Mode: "enforce", Kind: "known_exploited",
			Reason: "CVE-2 in zlib 1.2.11 is known to be exploited", Component: "zlib 1.2.11", FindingID: id64(13),
			Link: "https://s.example/findings/13", EnforceRequiresPlan: true}}}
	failCheck = &client.PolicyCheck{CheckID: 5, Result: "fail", AssetID: 4, AssetName: "app", PoliciesEvaluated: 2, PoliciesEnforced: 1,
		Violations: []client.PolicyViolation{
			{PolicyID: 2, PolicyName: "No KEV", Mode: "enforce", Kind: "known_exploited", Reason: "CVE-2 in zlib 1.2.11 is known to be exploited",
				Component: "zlib 1.2.11", FindingID: id64(13), Link: "https://s.example/findings/13"},
			{PolicyID: 3, PolicyName: "No leaked keys", Mode: "warn", Kind: "leaked_key", Reason: "A high GitHub token is written in deploy.py:1",
				LeakID: id64(8), Link: "https://s.example/assets/4?tab=leaks&leak=8"}}}
)

func TestPrintPolicyCheck(t *testing.T) {
	for _, tc := range []struct {
		pc   *client.PolicyCheck
		want string
	}{
		{&client.PolicyCheck{Result: "pass", PoliciesEvaluated: 1, Violations: []client.PolicyViolation{}},
			"Policy gates: pass (1 policy checked)\n"},
		{warnCheck, `Policy gates: 1 violation, none enforced (2 policies checked)
  No old criticals [warn]
    CVE-1 in openssl 3.0.2 (critical) has been open for 30 days; the limit is 14
    https://s.example/findings/12
`},
		{planCheck, `Policy gates: 1 violation, none enforced (1 policy checked)
  No KEV [enforce, not enforced on this plan]
    CVE-2 in zlib 1.2.11 is known to be exploited
    https://s.example/findings/13
  Enforce mode needs a paid plan; until then those policies only warn.
`},
		{failCheck, `Policy gates: fail, 2 violations (2 policies checked)
  No KEV [enforce]
    CVE-2 in zlib 1.2.11 is known to be exploited
    https://s.example/findings/13
  No leaked keys [warn]
    A high GitHub token is written in deploy.py:1
    https://s.example/assets/4?tab=leaks&leak=8
`},
		// A component the reason does not name is printed on its own line.
		{&client.PolicyCheck{Result: "warn", PoliciesEvaluated: 1, Violations: []client.PolicyViolation{{PolicyName: "EOL", Mode: "warn",
			Reason: "python is past its end of life", Component: "python 3.8.10"}}},
			"Policy gates: 1 violation, none enforced (1 policy checked)\n  EOL [warn]\n    python is past its end of life\n    component: python 3.8.10\n"},
	} {
		var b bytes.Buffer
		printPolicyCheck(&b, tc.pc)
		if b.String() != tc.want {
			t.Errorf("got:\n%s\nwant:\n%s", b.String(), tc.want)
		}
	}
}

func TestPolicyExit(t *testing.T) {
	for _, pc := range []*client.PolicyCheck{{Result: "pass"}, warnCheck, planCheck} {
		if err := policyExit(pc); err != nil {
			t.Errorf("%s: %v, want exit 0", pc.Result, err)
		}
	}
	var ee *exitError
	if err := policyExit(failCheck); !errors.As(err, &ee) || ee.code != gateExitCode || ee.msg != "1 violation of enforced policy gates" {
		t.Errorf("fail: %v", err)
	}
}

// policyServer is a fake Stackurity server for the policy check: meta
// (with or without the feature), the dry run and the check.
type policyServer struct {
	mu       sync.Mutex
	feature  bool
	dry      func() (int, string)
	check    func() (int, string)
	requests []client.PolicyCheckRequest
	paths    []string
}

func (ps *policyServer) start(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.mu.Lock()
		defer ps.mu.Unlock()
		ps.paths = append(ps.paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/meta":
			f := []string{"leaks"}
			if ps.feature {
				f = append(f, client.FeatureGatePolicies)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "test", "features": f})
		case "/api/v1/ingest":
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"asset_id":4,"collection_id":21,"observations":1}`)
		case "/api/v1/collections/21/result":
			_, _ = io.WriteString(w, `{"collection_id":21,"asset_id":4,"status":"evaluated","findings":[
				{"severity":"high","priority":"P2","state":"new","key":"CVE-9","component_name":"requests","version":"2.0.0","priority_policy_version":"v1"}]}`)
		case "/api/v1/gate-policies/check":
			var req client.PolicyCheckRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			ps.requests = append(ps.requests, req)
			f := ps.check
			if req.DryRun {
				f = ps.dry
			}
			if f == nil {
				w.WriteHeader(404)
				_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"no such endpoint"}}`)
				return
			}
			code, body := f()
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"no such endpoint"}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (ps *policyServer) client(t *testing.T) *client.Client {
	cl, err := client.New(ps.start(t).URL, "t", "test")
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func answer(pc *client.PolicyCheck) func() (int, string) {
	return func() (int, string) {
		b, _ := json.Marshal(pc)
		return 200, string(b)
	}
}

func dryAnswer(evaluated, enforced int) func() (int, string) {
	return answer(&client.PolicyCheck{AssetID: 4, AssetName: "app", PoliciesEvaluated: evaluated, PoliciesEnforced: enforced, DryRun: true})
}

func TestScanPolicyDecisions(t *testing.T) {
	ctx := context.Background()
	newSP := func(ps *policyServer) (*scanPolicy, *bytes.Buffer) {
		var warn bytes.Buffer
		return &scanPolicy{cl: ps.client(t), warn: &warn, req: client.PolicyCheckRequest{CollectionID: 21, Source: "ci"}}, &warn
	}

	// A server without the feature: nothing asked, nothing printed.
	ps := &policyServer{}
	sp, warn := newSP(ps)
	sp.prepare(ctx)
	if sp.active || len(ps.requests) != 0 || warn.Len() != 0 {
		t.Errorf("no feature: active %v, %d checks, %q", sp.active, len(ps.requests), warn)
	}
	// The feature listed but the route missing (404/405): skipped silently.
	ps = &policyServer{feature: true}
	sp, warn = newSP(ps)
	sp.prepare(ctx)
	if sp.active || warn.Len() != 0 {
		t.Errorf("route missing: active %v, %q", sp.active, warn)
	}
	ps = &policyServer{feature: true, dry: func() (int, string) { return 405, "" }}
	sp, warn = newSP(ps)
	sp.prepare(ctx)
	if sp.active || warn.Len() != 0 {
		t.Errorf("405: active %v, %q", sp.active, warn)
	}
	// No policy applies: no wait, no check.
	ps = &policyServer{feature: true, dry: dryAnswer(0, 0)}
	sp, _ = newSP(ps)
	sp.prepare(ctx)
	if sp.active || len(ps.requests) != 1 || !ps.requests[0].DryRun || ps.requests[0].CollectionID != 21 {
		t.Errorf("no policy: active %v, %+v", sp.active, ps.requests)
	}
	// The dry run fails: a warning, no check.
	ps = &policyServer{feature: true, dry: func() (int, string) { return 500, `{"error":{"code":"internal","message":"boom"}}` }}
	sp, warn = newSP(ps)
	sp.prepare(ctx)
	if sp.active || !strings.Contains(warn.String(), "warning: policy gates not checked") {
		t.Errorf("dry run fails: active %v, %q", sp.active, warn)
	}

	// Policies apply: warn passes, fail exits 3, enforce without a plan
	// passes.
	for _, tc := range []struct {
		pc   *client.PolicyCheck
		exit int
	}{{&client.PolicyCheck{Result: "pass", PoliciesEvaluated: 2}, 0}, {warnCheck, 0}, {planCheck, 0}, {failCheck, gateExitCode}} {
		ps = &policyServer{feature: true, dry: dryAnswer(2, 1), check: answer(tc.pc)}
		sp, _ = newSP(ps)
		sp.prepare(ctx)
		if !sp.active || sp.enforced != 1 {
			t.Fatalf("policies apply: active %v, enforced %d", sp.active, sp.enforced)
		}
		var out bytes.Buffer
		err := sp.check(ctx, &out)
		var ee *exitError
		switch {
		case tc.exit == 0 && err != nil:
			t.Errorf("%s: %v, want exit 0", tc.pc.Result, err)
		case tc.exit != 0 && (!errors.As(err, &ee) || ee.code != tc.exit):
			t.Errorf("%s: %v, want exit %d", tc.pc.Result, err, tc.exit)
		}
		if !strings.HasPrefix(out.String(), "Policy gates: ") {
			t.Errorf("%s: printed %q", tc.pc.Result, out.String())
		}
		if last := ps.requests[len(ps.requests)-1]; last.DryRun || last.CollectionID != 21 || last.Source != "ci" {
			t.Errorf("check request %+v", last)
		}
	}

	// The check itself fails: an error when a policy is enforced,
	// otherwise a warning.
	broken := func() (int, string) { return 500, `{"error":{"code":"internal","message":"boom"}}` }
	ps = &policyServer{feature: true, dry: dryAnswer(2, 1), check: broken}
	sp, _ = newSP(ps)
	sp.prepare(ctx)
	var ee *exitError
	if err := sp.check(ctx, io.Discard); err == nil || errors.As(err, &ee) || !strings.Contains(err.Error(), "1 policy is enforced") {
		t.Errorf("check fails with an enforced policy: %v", err)
	}
	ps = &policyServer{feature: true, dry: dryAnswer(2, 0), check: broken}
	sp, warn = newSP(ps)
	sp.prepare(ctx)
	if err := sp.check(ctx, io.Discard); err != nil || !strings.Contains(warn.String(), "warning: policy gates not checked") {
		t.Errorf("check fails, nothing enforced: %v %q", err, warn)
	}

	// --wait runs out: exit 4 with an enforced policy, else a warning.
	notReady := &exitError{code: notReadyExitCode, msg: "result not ready"}
	sp = &scanPolicy{enforced: 1, warn: io.Discard}
	if err := sp.notReady(notReady); err != notReady {
		t.Errorf("not ready, enforced: %v", err)
	}
	var w bytes.Buffer
	sp = &scanPolicy{warn: &w}
	if err := sp.notReady(notReady); err != nil || !strings.Contains(w.String(), "result not ready") {
		t.Errorf("not ready, nothing enforced: %v %q", err, w.String())
	}
}

// runScanOut runs stackurity scan and returns what it printed on stdout.
func runScanOut(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	_, err = runScan(t, args...)
	os.Stdout = old
	w.Close()
	return string(<-done), err
}

// stackurity scan against a fake server: the policy check runs after the
// result, with --fail-on applied as well, and --policy=off skips it.
func TestScanPolicyGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_TOKEN", "t")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	scan := func(ps *policyServer, args ...string) (string, error) {
		srv := ps.start(t)
		return runScanOut(t, append([]string{dir, "--no-packs", "--no-leaks", "--server", srv.URL}, args...)...)
	}
	var ee *exitError

	// Warn only: printed, exit 0; the check names the upload and the ref.
	ps := &policyServer{feature: true, dry: dryAnswer(1, 0), check: answer(warnCheck)}
	out, err := scan(ps)
	if err != nil || !strings.Contains(out, "Policy gates: 1 violation, none enforced") {
		t.Fatalf("warn: %v\n%s", err, out)
	}
	if len(ps.requests) != 2 || ps.requests[1].CollectionID != 21 || ps.requests[1].Source != "ci" || ps.requests[1].Ref != "refs/heads/main" {
		t.Errorf("requests %+v", ps.requests)
	}

	// Enforced: exit 3.
	ps = &policyServer{feature: true, dry: dryAnswer(2, 1), check: answer(failCheck)}
	if out, err := scan(ps); !errors.As(err, &ee) || ee.code != gateExitCode || !strings.Contains(out, "Policy gates: fail") {
		t.Errorf("enforce: %v\n%s", err, out)
	}

	// --fail-on is applied as well: its report comes first and decides
	// the exit when both fail; a passing policy check does not hide it.
	ps = &policyServer{feature: true, dry: dryAnswer(1, 0), check: answer(&client.PolicyCheck{Result: "pass", PoliciesEvaluated: 1})}
	out, err = scan(ps, "--fail-on", "high")
	if !errors.As(err, &ee) || ee.code != gateExitCode || !strings.Contains(ee.msg, "finding meets the gate") ||
		!strings.Contains(out, "1 meets the gate") || !strings.Contains(out, "Policy gates: pass") {
		t.Errorf("--fail-on with a passing policy check: %v\n%s", err, out)
	}

	// --policy=off: no policy request at all.
	ps = &policyServer{feature: true, dry: dryAnswer(1, 1), check: answer(failCheck)}
	if out, err := scan(ps, "--policy=off"); err != nil || len(ps.requests) != 0 || strings.Contains(out, "Policy gates") {
		t.Errorf("--policy=off: %v, %d requests\n%s", err, len(ps.requests), out)
	}

	// An older server (no feature): the scan behaves as before, without
	// waiting for the result.
	ps = &policyServer{}
	if out, err := scan(ps); err != nil || strings.Contains(out, "Policy gates") {
		t.Errorf("old server: %v\n%s", err, out)
	}
	for _, p := range ps.paths {
		if strings.Contains(p, "/result") || strings.Contains(p, "gate-policies") {
			t.Errorf("old server: asked %s", p)
		}
	}
}

// stackurity policy check: text or JSON, exit 3 on fail, and an error on
// a server without policy gates.
func TestPolicyCheckCommand(t *testing.T) {
	ctx := context.Background()
	run := func(ps *policyServer, o policyCheckOptions) (string, error) {
		var out bytes.Buffer
		o.stdout, o.warn = &out, io.Discard
		err := o.run(ctx, ps.client(t))
		return out.String(), err
	}
	var ee *exitError

	ps := &policyServer{feature: true, check: answer(warnCheck)}
	out, err := run(ps, policyCheckOptions{image: "ghcr.io/acme/app@" + testDigest, commit: "abc", ref: "v1.2.0"})
	if err != nil || !strings.HasPrefix(out, "asset 4: app\nPolicy gates: 1 violation, none enforced") {
		t.Errorf("text: %v\n%s", err, out)
	}
	if r := ps.requests[0]; r.ImageDigest != testDigest || r.Source != "deploy" || r.Commit != "abc" || r.Ref != "v1.2.0" || r.DryRun {
		t.Errorf("request %+v", r)
	}

	ps = &policyServer{feature: true, check: answer(failCheck)}
	out, err = run(ps, policyCheckOptions{asset: 4, json: true})
	if !errors.As(err, &ee) || ee.code != gateExitCode {
		t.Errorf("json fail: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	for _, k := range []string{"check_id", "result", "asset_id", "asset_name", "policies_evaluated", "policies_enforced", "violations"} {
		if _, ok := got[k]; !ok {
			t.Errorf("json has no %s: %s", k, out)
		}
	}
	vs, _ := got["violations"].([]any)
	if got["result"] != "fail" || len(vs) != 2 {
		t.Fatalf("json: %s", out)
	}
	v0 := vs[0].(map[string]any)
	for _, k := range []string{"policy_id", "policy_name", "mode", "kind", "reason", "component", "key", "finding_id", "link"} {
		if _, ok := v0[k]; !ok {
			t.Errorf("violation has no %s: %v", k, v0)
		}
	}
	if _, ok := vs[1].(map[string]any)["leak_id"]; !ok {
		t.Errorf("leak violation: %v", vs[1])
	}

	// A server without policy gates is an error here: the deploy asked
	// for a check.
	ps = &policyServer{}
	if _, err := run(ps, policyCheckOptions{repo: "https://github.com/acme/app"}); !errors.Is(err, client.ErrPolicyCheckUnsupported) {
		t.Errorf("old server: %v", err)
	}
}
