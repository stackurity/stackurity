package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type publicCVEs struct {
	TrackingSince *time.Time           `json:"tracking_since"`
	CVEs          []store.CVEFirstSeen `json:"cves"`
}

// The public log of new CVEs needs no sign-in, holds only CVE IDs, times and
// the feed that brought each, and caps what one request can ask.
func TestPublicCVEs(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.System(context.Background())
	mark := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	for _, q := range []string{
		`INSERT INTO cve_first_seen (cve, first_seen, source, backfilled) VALUES ('CVE-2021-44228', '2026-10-29T10:00:00Z', 'kev', true)`,
		`INSERT INTO cve_first_seen (cve, first_seen, source) VALUES ('CVE-2026-0001', '2026-10-30T17:38:17Z', 'epss')`,
		`INSERT INTO cve_first_seen (cve, first_seen, source) VALUES ('CVE-2026-0002', '2026-10-30T18:00:05Z', 'kev')`,
	} {
		if _, err := e.st.Pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	a := e.anon()

	var recent publicCVEs
	if code := a.do("GET", "/api/v1/public/cves/recent", nil, &recent); code != 200 {
		t.Fatalf("recent: %d", code)
	}
	if len(recent.CVEs) != 2 || recent.CVEs[0].CVE != "CVE-2026-0002" || recent.CVEs[1].CVE != "CVE-2026-0001" ||
		!recent.CVEs[0].Exact || recent.TrackingSince == nil || !recent.TrackingSince.Equal(mark) {
		t.Fatalf("recent %+v", recent)
	}
	var page publicCVEs
	a.do("GET", "/api/v1/public/cves/recent?limit=1&before="+url.QueryEscape(recent.CVEs[0].At.Format(time.RFC3339Nano)), nil, &page)
	if len(page.CVEs) != 1 || page.CVEs[0].CVE != "CVE-2026-0001" {
		t.Errorf("page before the newest: %+v", page)
	}

	var some publicCVEs
	if code := a.do("GET", "/api/v1/public/cves?id=cve-2021-44228,CVE-2026-0001&id=CVE-2099-0001", nil, &some); code != 200 {
		t.Fatalf("by id: %d", code)
	}
	if len(some.CVEs) != 2 || some.CVEs[0].CVE != "CVE-2021-44228" || some.CVEs[0].Exact || !some.CVEs[1].Exact {
		t.Errorf("by id %+v", some)
	}

	for _, bad := range []string{
		"/api/v1/public/cves/recent?limit=0",
		"/api/v1/public/cves/recent?limit=201",
		"/api/v1/public/cves/recent?before=yesterday",
		"/api/v1/public/cves",
		"/api/v1/public/cves?id=GHSA-xxxx-yyyy-zzzz",
		"/api/v1/public/cves?id=" + manyIDs(201),
	} {
		if code := a.do("GET", bad, nil, nil); code != 400 {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}

	resp := a.req("GET", "/api/v1/public/cves/recent", nil, nil)
	resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control %q", cc)
	}
	// Writes are not routes here.
	if code := a.do("POST", "/api/v1/public/cves/recent", map[string]string{}, nil); code != http.StatusMethodNotAllowed && code != 404 && code != 403 {
		t.Errorf("POST: %d", code)
	}
}

func manyIDs(n int) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2025-%05d", 10000+i)
	}
	return strings.Join(ids, ",")
}
