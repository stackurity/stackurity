package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

const epssDay1 = "#model_version:v2026.06.15,score_date:2026-10-28T12:03:13Z\ncve,epss,percentile\n" +
	"CVE-2021-44228,0.99999,1.00000\nCVE-2024-0001,0.04753,0.91849\nGHSA-xxxx-yyyy-zzzz,0.5,0.5\nCVE-2024-0002,1.7,0.5\n" +
	"CVE-2024-0001,0.9,0.9\nCVE-2024-0003,0.00042,0.03100\n"

// The daily EPSS file replaces the stored scores, with the model and score
// date from its first line. Rows that are not CVEs or whose values are out
// of range are skipped; a CVE listed twice keeps its first row.
func TestEPSSSync(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, FeedEPSS, "prediction", 24*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	up.set("/epss_scores-current.csv.gz", gz(t, epssDay1))
	res, err := sy.Sync(ctx, FeedEPSS)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 3 {
		t.Errorf("changed %d, want 3", res.Changed)
	}
	e, err := st.EPSSFor(ctx, "CVE-2024-0001")
	if err != nil || e == nil {
		t.Fatalf("CVE-2024-0001: %+v %v", e, err)
	}
	if e.Score != 0.04753 || e.Percentile != 0.91849 || e.ModelVersion != "v2026.06.15" || e.Date.Format("2006-01-02") != "2026-10-28" {
		t.Errorf("stored %+v", e)
	}
	for _, cve := range []string{"CVE-2024-0002", "GHSA-xxxx-yyyy-zzzz"} {
		if e, _ := st.EPSSFor(ctx, cve); e != nil {
			t.Errorf("%s stored: %+v", cve, e)
		}
	}
	f, _ := st.GetFeed(ctx, FeedEPSS)
	if f.Records != 3 || f.LastError != "" || f.LastSuccess == nil {
		t.Errorf("feed after sync: %+v", f)
	}

	// The same file again changes nothing.
	if res, err := sy.Sync(ctx, FeedEPSS); err != nil || res.Changed != 0 {
		t.Errorf("same file: %+v %v", res, err)
	}

	// The next day's file, served uncompressed by a mirror, replaces the
	// whole set.
	up.set("/epss_scores-current.csv.gz", "#model_version:v2026.06.15,score_date:2026-10-29T12:00:00Z\ncve,epss,percentile\nCVE-2024-0001,0.2,0.97\n")
	if res, err := sy.Sync(ctx, FeedEPSS); err != nil || res.Changed != 1 {
		t.Fatalf("next day: %+v %v", res, err)
	}
	if e, _ := st.EPSSFor(ctx, "CVE-2024-0001"); e == nil || e.Score != 0.2 || e.Date.Format("2006-01-02") != "2026-10-29" {
		t.Errorf("next day: %+v", e)
	}
	if e, _ := st.EPSSFor(ctx, "CVE-2021-44228"); e != nil {
		t.Errorf("a CVE missing from the new file was kept: %+v", e)
	}

	// Broken files fail the sync and keep what is stored.
	for name, body := range map[string]string{
		"no scores":     gz(t, "#model_version:v2026.06.15,score_date:2026-10-30T00:00:00Z\ncve,epss,percentile\n"),
		"no preamble":   "cve,epss,percentile\nCVE-2024-0001,0.5,0.5\n",
		"other columns": "#model_version:v9,score_date:2026-10-30T00:00:00Z\ncve,percentile,epss\nCVE-2024-0001,0.5,0.5\n",
		"truncated gzip": func() string {
			z := gz(t, strings.Replace(epssDay1, "2026-10-28", "2026-10-30", 1)+strings.Repeat("CVE-2024-9999,0.1,0.1\n", 2000))
			return z[:len(z)/2]
		}(),
		"bad row": "#model_version:v9,score_date:2026-10-30T00:00:00Z\ncve,epss,percentile\nCVE-2024-0001,0.5\n",
	} {
		up.set("/epss_scores-current.csv.gz", body)
		if _, err := sy.Sync(ctx, FeedEPSS); err == nil {
			t.Errorf("%s: sync succeeded", name)
		}
		if e, _ := st.EPSSFor(ctx, "CVE-2024-0001"); e == nil || e.Score != 0.2 {
			t.Errorf("%s: stored scores changed: %+v", name, e)
		}
	}
	if f, _ := st.GetFeed(ctx, FeedEPSS); f.LastError == "" {
		t.Error("a failed sync left no error on the feed")
	}

	// A file larger than the cap once decompressed is refused.
	defer func(n int64) { epssMaxCSV = n }(epssMaxCSV)
	epssMaxCSV = 1000
	up.set("/epss_scores-current.csv.gz", gz(t, strings.Replace(epssDay1, "2026-10-28", "2026-10-31", 1)+strings.Repeat("CVE-2024-9999,0.1,0.1\n", 100)))
	if _, err := sy.Sync(ctx, FeedEPSS); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: %v", err)
	}
}

// The default URL redirects from "current" to the day's file, as
// epss.empiricalsecurity.com does; the fetcher follows it.
func TestEPSSFollowsRedirect(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, _ := setup(t)
	body := gz(t, epssDay1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/epss_scores-current.csv.gz":
			http.Redirect(w, r, "/epss_scores-2026-10-28.csv.gz", http.StatusFound)
		case "/epss_scores-2026-10-28.csv.gz":
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	sy.f.cfg.EPSSURL = srv.URL + "/epss_scores-current.csv.gz"
	if err := st.EnsureFeed(ctx, FeedEPSS, "prediction", 24*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	if res, err := sy.Sync(ctx, FeedEPSS); err != nil || res.Changed != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	// Nothing is re-evaluated: EPSS changes priorities only.
	if ids, err := ComponentsToEvaluate(ctx, st, FeedEPSS, &SyncResult{Changed: 3, Full: true}); err != nil || ids != nil {
		t.Errorf("components to evaluate: %v %v", ids, err)
	}
}
