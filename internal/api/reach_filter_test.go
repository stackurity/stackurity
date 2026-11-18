package api_test

import (
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
)

// Filtering findings by reachability is part of the paid plans: Community
// gets plan_required (402), a paid plan the filtered list.
func TestFindingsReachabilityFilter(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	upgradeFixture(t, e) // three open findings; their packages not assessed (unknown)
	e.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Community, ExpiresAt: time.Now().AddDate(1, 0, 0)})

	if code := view.do("GET", "/api/v1/findings?reachability=not_reached", nil, nil); code != 402 {
		t.Errorf("Community: %d, want 402", code)
	}
	if code := view.do("GET", "/api/v1/findings/by-asset?reachability=unknown", nil, nil); code != 402 {
		t.Errorf("Community, by asset: %d, want 402", code)
	}
	if code := view.do("GET", "/api/v1/findings", nil, nil); code != 200 {
		t.Errorf("Community without the filter: %d", code)
	}

	e.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Pro, ExpiresAt: time.Now().AddDate(1, 0, 0)})
	var list struct {
		Items []store.Finding `json:"items"`
		Total int64           `json:"total"`
	}
	for q, want := range map[string]int64{"unknown": 3, "not_reached": 0, "reachable": 0, "not_running,unknown": 3} {
		if code := view.do("GET", "/api/v1/findings?reachability="+q, nil, &list); code != 200 || list.Total != want {
			t.Errorf("reachability=%s: %d, %d findings, want %d", q, code, list.Total, want)
		}
	}
	if code := view.do("GET", "/api/v1/findings?reachability=safe", nil, nil); code != 400 {
		t.Errorf("an unknown status: %d, want 400", code)
	}
}
