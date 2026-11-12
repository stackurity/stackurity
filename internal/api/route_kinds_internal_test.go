package api

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// The kinds the dashboard offers on a rule are the kinds the server
// accepts: a kind only the dashboard knows makes Save fail.
func TestRouteKindsMatchTheDashboard(t *testing.T) {
	src, err := os.ReadFile("../../web/src/api.ts")
	if err != nil {
		t.Skip("no dashboard source: ", err)
	}
	m := regexp.MustCompile(`export const INCIDENT_KINDS = \[([^\]]*)\]`).FindSubmatch(src)
	if m == nil {
		t.Fatal("INCIDENT_KINDS not found in web/src/api.ts")
	}
	var web []string
	for _, q := range regexp.MustCompile(`"([a-z_]+)"`).FindAllSubmatch(m[1], -1) {
		web = append(web, string(q[1]))
	}
	if !slices.Equal(web, routeKinds) {
		t.Errorf("dashboard INCIDENT_KINDS %v, server routeKinds %v", web, routeKinds)
	}
}
