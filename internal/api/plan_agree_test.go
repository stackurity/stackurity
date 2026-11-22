package api_test

import (
	"slices"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
)

// The gate (/auth/me's features and requireFeature) and plan options read
// the same rules, the add-on that brings the evidence pack included
// (license.BroughtBy): for every licence, a feature is in plan options'
// included list exactly when /auth/me lists it, and the evidence report
// route lets through exactly those that include it.
func TestGateAndPlanOptionsAgree(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	year := time.Now().AddDate(1, 0, 0)
	for name, l := range map[string]*license.License{
		"community":   nil,
		"pro":         {Version: 1, Customer: "A", Edition: license.Pro, ExpiresAt: year},
		"pro + addon": {Version: 1, Customer: "A", Edition: license.Pro, ExpiresAt: year, Addons: []license.Feature{license.ComplianceAddon}},
		"enterprise":  {Version: 1, Customer: "A", Edition: license.Enterprise, ExpiresAt: year},
	} {
		e.api.Licence.Set(l)
		var me struct {
			Features []license.Feature `json:"features"`
		}
		var po struct {
			Included []struct {
				Feature license.Feature `json:"feature"`
			} `json:"included"`
		}
		if admin.do("GET", "/api/v1/auth/me", nil, &me) != 200 || admin.do("GET", "/api/v1/plan/options", nil, &po) != 200 {
			t.Fatalf("%s: me or plan options failed", name)
		}
		for _, f := range license.PaidFeatures() {
			inPO := slices.ContainsFunc(po.Included, func(x struct {
				Feature license.Feature `json:"feature"`
			}) bool {
				return x.Feature == f
			})
			if inPO != slices.Contains(me.Features, f) {
				t.Errorf("%s: %s in plan options %v, in /auth/me %v", name, f, inPO, !inPO)
			}
		}
		// The licensed build serves the evidence report; Community answers
		// 402 for it whatever the licence says.
		if api.BuildEdition != "community" {
			code := admin.do("GET", "/api/v1/reports/evidence", nil, nil)
			if want := slices.Contains(me.Features, license.EvidenceReport); (code != 402) != want {
				t.Errorf("%s: evidence report %d, included %v", name, code, want)
			}
		}
	}
}
