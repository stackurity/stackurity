package api_test

import (
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
)

// The unmaintained cutoff is part of the risk policy: 6 to 120 months, the
// default (24) stored as no value, and only admins may change it.
func TestRiskPolicyUnmaintainedMonths(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("view@x.io", auth.RoleViewer)
	admin, sec, view := e.login("admin@x.io"), e.login("sec@x.io"), e.login("view@x.io")
	var got struct {
		Policy  map[string]any `json:"policy"`
		Version string         `json:"version"`
	}
	if code := view.do("GET", "/api/v1/risk-policy", nil, &got); code != 200 {
		t.Fatalf("viewer reads the policy: %d", code)
	}
	if _, ok := got.Policy["unmaintained_months"]; ok {
		t.Errorf("the default is left out: %v", got.Policy["unmaintained_months"])
	}
	before := got.Version
	put := func(c *session, months any) int {
		pol := map[string]any{}
		for k, v := range got.Policy {
			pol[k] = v
		}
		pol["unmaintained_months"] = months
		return c.do("PUT", "/api/v1/risk-policy", pol, nil)
	}
	for _, bad := range []any{5, 121, -1, 1.5} {
		if code := put(admin, bad); code != 400 {
			t.Errorf("unmaintained_months %v accepted: %d", bad, code)
		}
	}
	if code := put(sec, 36); code != 403 {
		t.Errorf("security changed the policy: %d", code)
	}
	if code := put(view, 36); code != 403 {
		t.Errorf("viewer changed the policy: %d", code)
	}
	for _, ok := range []int{6, 120, 36} {
		if code := put(admin, ok); code != 200 {
			t.Errorf("unmaintained_months %d refused: %d", ok, code)
		}
	}
	admin.do("GET", "/api/v1/risk-policy", nil, &got)
	if got.Policy["unmaintained_months"] != float64(36) {
		t.Errorf("stored %v, want 36", got.Policy["unmaintained_months"])
	}
	// Choosing the default explicitly is the same policy as never setting it.
	if code := put(admin, 24); code != 200 {
		t.Fatalf("24: %d", code)
	}
	got.Policy = nil // a fresh map: decoding into the old one keeps its keys
	admin.do("GET", "/api/v1/risk-policy", nil, &got)
	if _, ok := got.Policy["unmaintained_months"]; ok || got.Version != before {
		t.Errorf("24 months stored as %v, version %s (was %s)", got.Policy["unmaintained_months"], got.Version, before)
	}
}
