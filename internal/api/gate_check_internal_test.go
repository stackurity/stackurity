package api

import (
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// The check's answer from violations, with and without enforcement (the
// Community build never enforces; enforce_requires_plan says so).
func TestGateCheckOutcome(t *testing.T) {
	fid, lid := int64(12), int64(8)
	warn := store.GateViolation{PolicyID: 1, PolicyName: "Old criticals", Mode: "warn", Kind: "finding_age", Reason: "r1",
		FindingID: &fid, Link: "/findings/12", Component: "openssl 3.0.2", Key: "CVE-1"}
	enforce := store.GateViolation{PolicyID: 2, PolicyName: "No leaks", Mode: "enforce", Kind: "leaked_key", Reason: "r2",
		LeakID: &lid, Link: "/assets/4?tab=leaks&leak=8"}

	if res, vs := gateCheckOutcome(nil, true, "https://s.example"); res != "pass" || vs == nil || len(vs) != 0 {
		t.Errorf("none: %s %v", res, vs)
	}
	res, vs := gateCheckOutcome([]store.GateViolation{warn}, true, "https://s.example/")
	if res != "warn" || len(vs) != 1 || vs[0].Link != "https://s.example/findings/12" || vs[0].EnforceRequiresPlan ||
		vs[0].FindingID == nil || *vs[0].FindingID != 12 || vs[0].Component != "openssl 3.0.2" || vs[0].Key != "CVE-1" {
		t.Errorf("warn: %s %+v", res, vs)
	}
	res, vs = gateCheckOutcome([]store.GateViolation{warn, enforce}, true, "")
	if res != "fail" || vs[1].EnforceRequiresPlan || vs[1].Link != "/assets/4?tab=leaks&leak=8" || vs[1].LeakID == nil {
		t.Errorf("enforced: %s %+v", res, vs)
	}
	// Order does not matter: fail stays fail after a warning.
	if res, _ := gateCheckOutcome([]store.GateViolation{enforce, warn}, true, ""); res != "fail" {
		t.Errorf("enforce then warn: %s", res)
	}
	res, vs = gateCheckOutcome([]store.GateViolation{enforce}, false, "https://s.example")
	if res != "warn" || !vs[0].EnforceRequiresPlan || vs[0].Mode != "enforce" || vs[0].Link != "https://s.example/assets/4?tab=leaks&leak=8" {
		t.Errorf("enforce without the plan: %s %+v", res, vs)
	}
}

// What a check may do on the plan: CI and API checks enforce with
// gate_enforce; a deploy check needs gate_deploy too, and without it never
// fails (deployLocked).
func TestGateCheckPlan(t *testing.T) {
	for _, tc := range []struct {
		source                string
		enforceOK, deployOK   bool
		wantEnforce, wantLock bool
	}{
		{"ci", false, false, false, false},
		{"ci", true, false, true, false},
		{"api", true, true, true, false},
		{"deploy", true, true, true, false},
		{"deploy", true, false, false, true},
		{"deploy", false, false, false, true},
		{"deploy", false, true, false, false},
	} {
		enforce, locked := gateCheckPlan(tc.source, tc.enforceOK, tc.deployOK)
		if enforce != tc.wantEnforce || locked != tc.wantLock {
			t.Errorf("%s enforce=%v deploy=%v: got %v %v", tc.source, tc.enforceOK, tc.deployOK, enforce, locked)
		}
	}
	if gateEnforceDowngraded([]gateCheckViolation{{Mode: "enforce"}}) || !gateEnforceDowngraded([]gateCheckViolation{{}, {EnforceRequiresPlan: true}}) {
		t.Error("gateEnforceDowngraded")
	}
}

func TestGateCheckRequestValidate(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, tc := range []struct {
		req  gateCheckRequest
		want string // "" for valid
	}{
		{gateCheckRequest{}, "name the asset"},
		{gateCheckRequest{AssetID: 1, RepositoryURL: "https://github.com/acme/app"}, "one of asset_id"},
		{gateCheckRequest{AssetID: 1, ImageDigest: digest}, "one of asset_id"},
		{gateCheckRequest{AssetID: -1}, "positive"},
		{gateCheckRequest{AssetID: 1, Source: "cron"}, "source must be"},
		{gateCheckRequest{ImageDigest: "nginx:1.27"}, "sha256 digest"},
		{gateCheckRequest{AssetID: 1, Commit: strings.Repeat("a", 101)}, "too long"},
		{gateCheckRequest{AssetID: 1}, ""},
		{gateCheckRequest{CollectionID: 3, Source: "CI"}, ""},
		{gateCheckRequest{CollectionID: 3, AssetID: 1}, ""},
		{gateCheckRequest{ImageDigest: "ghcr.io/acme/app@" + strings.ToUpper(digest[7:])}, ""},
		{gateCheckRequest{RepositoryURL: "git@github.com:Acme/App.git", Source: "deploy"}, ""},
	} {
		req := tc.req
		err := req.validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%+v: %v", tc.req, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%+v: %v, want %q", tc.req, err, tc.want)
		}
		if tc.want != "" {
			continue
		}
		if req.Source == "" || req.Source != strings.ToLower(req.Source) {
			t.Errorf("%+v: source %q", tc.req, req.Source)
		}
		if tc.req.ImageDigest != "" && req.ImageDigest != digest {
			t.Errorf("digest %q", req.ImageDigest)
		}
		if tc.req.RepositoryURL != "" && req.RepositoryURL != "https://github.com/Acme/App" {
			t.Errorf("repository %q", req.RepositoryURL)
		}
	}
	r := gateCheckRequest{AssetID: 1}
	if err := r.validate(); err != nil || r.Source != "api" {
		t.Errorf("default source: %q %v", r.Source, err)
	}
}

func TestGateCheckCaller(t *testing.T) {
	tok := &store.Token{ID: 1}
	for _, tc := range []struct {
		p                 *Principal
		reader, collector bool
	}{
		{nil, false, false},
		{&Principal{Role: auth.RoleViewer}, true, false},
		{&Principal{Role: auth.RoleAdmin, Token: tok}, true, false},
		{&Principal{ProjectRole: auth.RoleViewer, Restricted: true}, true, false},
		{&Principal{Role: auth.RoleCollector, Token: tok}, false, true},
		{&Principal{Role: auth.RoleCollector}, false, false},
		{&Principal{}, false, false},
	} {
		r, c := gateCheckCaller(tc.p)
		if r != tc.reader || c != tc.collector {
			t.Errorf("%+v: reader %v collector %v", tc.p, r, c)
		}
	}
}
