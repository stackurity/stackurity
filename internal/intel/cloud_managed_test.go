package intel

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const cloudEOL = `{"result":[
 {"name":"google-kubernetes-engine","label":"Google Kubernetes Engine","links":{"html":"https://endoflife.date/google-kubernetes-engine"},"identifiers":[],
  "releases":[{"name":"1.30","label":"1.30","releaseDate":"2024-05-01","isEol":false,"eolFrom":"2099-01-01"},
              {"name":"1.29","label":"1.29","releaseDate":"2024-01-01","isEol":true,"eolFrom":"2025-03-01"}]},
 {"name":"azure-kubernetes-service","label":"Azure Kubernetes Service","links":{"html":"https://endoflife.date/azure-kubernetes-service"},"identifiers":[],
  "releases":[{"name":"1.30","label":"1.30","releaseDate":"2024-05-01","isEol":false,"eolFrom":"2099-01-01"}]},
 {"name":"azure-database-for-postgresql","label":"Azure Database for PostgreSQL","links":{"html":"https://endoflife.date/azure-database-for-postgresql"},"identifiers":[],
  "releases":[{"name":"13","label":"13","releaseDate":"2021-01-01","isEol":true,"eolFrom":"2025-11-13"}]},
 {"name":"mysql","label":"MySQL","links":{"html":"https://endoflife.date/mysql"},"identifiers":[],
  "releases":[{"name":"8.0","label":"8.0","releaseDate":"2018-04-19","isEol":true,"eolFrom":"2026-04-30"}]},
 {"name":"python","label":"Python","links":{"html":"https://endoflife.date/python"},"identifiers":[],
  "releases":[{"name":"3.8","label":"3.8","releaseDate":"2019-10-14","isEol":true,"eolFrom":"2024-10-07"}]}]}`

// Versions as gcp-managed and azure-managed report them are matched to
// their endoflife.date release lines; a product endoflife.date does not
// have is a gap, never shown as clean.
func TestCloudManagedServiceLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	ms := func(name, purl string) int64 {
		return ingest(t, st, model.AssetManagedService, name, true, confirmed(purl, map[string]string{"kind": "managed-service"}))
	}
	gke := ms("gke-main", "pkg:generic/google-kubernetes-engine@1.29.8-gke.1031000")
	aks := ms("aks-main", "pkg:generic/azure-kubernetes-service@1.30.4")
	pg := ms("orders", "pkg:generic/azure-database-for-postgresql@13.14")
	sql := ms("legacy", "pkg:generic/mysql@8.0.31")
	fn := ms("resize", "pkg:generic/python@3.8")
	ms("sessions", "pkg:generic/azure-cache-for-redis@6.0.14")
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", cloudEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	for asset, want := range map[int64]string{gke: "google-kubernetes-engine:1.29", pg: "azure-database-for-postgresql:13", sql: "mysql:8.0", fn: "python:3.8", aks: ""} {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, f := range fs {
			keys = append(keys, f.Key)
		}
		if got := strings.Join(keys, ","); got != want {
			t.Errorf("asset %d findings %q, want %q", asset, got, want)
		}
	}
	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	found := false
	for _, g := range gaps {
		if strings.Contains(g.PurlKey, "azure-cache-for-redis") {
			found = strings.Contains(g.Reason, "managed service")
		}
	}
	if !found {
		t.Errorf("Azure Cache for Redis (no lifecycle product) should be a managed-service gap: %+v", gaps)
	}
}
