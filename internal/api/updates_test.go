package api_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
)

func TestUpdatesEndpoint(t *testing.T) {
	e := newEnv(t)
	e.api.Version = "v0.3.1"
	e.api.UpdateCheck = true
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	e.instanceAdmin("owner@x.io")
	owner := e.login("owner@x.io")
	if err := e.st.SetInstanceValue(context.Background(), "update_check",
		`{"checked_at":"2026-10-25T08:00:00Z","releases":[
			{"version":"0.4.0","tag":"v0.4.0","name":"Stackurity v0.4.0","url":"https://github.com/stackurity/stackurity/releases/tag/v0.4.0","notes":"### Security\n\n- x","security":true},
			{"version":"0.3.1","tag":"v0.3.1","notes":"### Fixed"}]}`); err != nil {
		t.Fatal(err)
	}

	if code := e.anon().do("GET", "/api/v1/updates", nil, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
	// Workspace roles, even admin, cannot act on the installation.
	for _, who := range []string{"admin@x.io", "viewer@x.io"} {
		if code := e.login(who).do("GET", "/api/v1/updates", nil, nil); code != 403 {
			t.Errorf("%s: %d", who, code)
		}
	}
	var eng struct {
		Secret string `json:"secret"`
	}
	if code := owner.do("POST", "/api/v1/tokens", map[string]string{"name": "ci", "role": "engineer"}, &eng); code != 201 {
		t.Fatalf("engineer token: %d", code)
	}
	if code := bearer(e, eng.Secret, "GET", "/api/v1/updates", nil, nil); code != 403 {
		t.Errorf("instance admin's engineer token: %d", code)
	}

	var rep struct {
		Enabled         bool
		Current         string
		Latest          string
		Security        bool
		UpdateAvailable bool    `json:"update_available"`
		CheckedAt       *string `json:"checked_at"`
		Releases        []struct {
			Version, Notes string
			Security       bool
		}
	}
	if code := owner.do("GET", "/api/v1/updates", nil, &rep); code != 200 {
		t.Fatalf("instance admin: %d", code)
	}
	if !rep.Enabled || !rep.UpdateAvailable || !rep.Security || rep.Current != "v0.3.1" || rep.Latest != "0.4.0" ||
		rep.CheckedAt == nil || len(rep.Releases) != 1 || rep.Releases[0].Version != "0.4.0" || rep.Releases[0].Notes == "" {
		t.Errorf("report: %+v", rep)
	}

	e.api.UpdateCheck = false
	rep.Releases = nil
	rep.Latest = ""
	if code := owner.do("GET", "/api/v1/updates", nil, &rep); code != 200 {
		t.Fatalf("off: %d", code)
	}
	if rep.Enabled || rep.Latest != "" || len(rep.Releases) != 0 {
		t.Errorf("off: %+v", rep)
	}
}
