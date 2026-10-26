package api_test

import (
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/risk"
)

// The risk policy preview needs the role that may edit the policy, validates
// like a save, writes nothing, and the policy page names who changed it last.
func TestRiskPolicyPreview(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("view@x.io", auth.RoleViewer)
	admin, sec, view := e.login("admin@x.io"), e.login("sec@x.io"), e.login("view@x.io")

	proposed := map[string]any{"known_exploited": 6}
	if code := e.anon().do("POST", "/api/v1/risk-policy/preview", proposed, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
	for name, s := range map[string]*session{"security": sec, "viewer": view} {
		if code := s.do("POST", "/api/v1/risk-policy/preview", proposed, nil); code != 403 {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	// Validation is the save's: unknown fields and invalid thresholds fail.
	if code := admin.do("POST", "/api/v1/risk-policy/preview", map[string]any{"bogus": 1}, nil); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
	if code := admin.do("POST", "/api/v1/risk-policy/preview", map[string]any{"thresholds": map[string]float64{"p1": 1, "p2": 2, "p3": 3}}, nil); code != 400 {
		t.Errorf("invalid thresholds: %d", code)
	}

	var pv struct {
		CurrentVersion  string         `json:"current_version"`
		ProposedVersion string         `json:"proposed_version"`
		ChangedFields   []string       `json:"changed_fields"`
		Before          map[string]int `json:"before"`
		After           map[string]int `json:"after"`
		Sample          []any          `json:"sample"`
		SampleLimit     int            `json:"sample_limit"`
	}
	if code := admin.do("POST", "/api/v1/risk-policy/preview", proposed, &pv); code != 200 {
		t.Fatalf("preview: %d", code)
	}
	p := risk.DefaultPolicy()
	p.KnownExploited = 6
	if pv.CurrentVersion != risk.DefaultPolicy().Version() || pv.ProposedVersion != p.Version() || len(pv.ChangedFields) != 1 ||
		pv.ChangedFields[0] != "known_exploited" || pv.Before == nil || pv.After == nil || pv.Sample == nil || pv.SampleLimit == 0 {
		t.Errorf("preview = %+v", pv)
	}

	type got struct {
		Version    string `json:"version"`
		LastChange *struct {
			ActorName string   `json:"actor_name"`
			Version   string   `json:"version"`
			Changed   []string `json:"changed"`
		} `json:"last_change"`
	}
	var g got
	if code := view.do("GET", "/api/v1/risk-policy", nil, &g); code != 200 || g.Version != risk.DefaultPolicy().Version() || g.LastChange != nil {
		t.Errorf("after preview, the policy is %d %+v", code, g)
	}
	if code := admin.do("PUT", "/api/v1/risk-policy", proposed, nil); code != 200 {
		t.Fatalf("save: %d", code)
	}
	g = got{}
	if code := view.do("GET", "/api/v1/risk-policy", nil, &g); code != 200 || g.LastChange == nil || g.LastChange.ActorName != "admin@x.io" ||
		g.LastChange.Version != p.Version() || len(g.LastChange.Changed) != 1 {
		t.Errorf("after save: %d %+v", code, g.LastChange)
	}
}
