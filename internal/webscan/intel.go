package webscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

// The prototype asks public services for advisories. A hosted version would
// read the OSV data Stackurity already keeps in its database instead.

var intelClient = &http.Client{Timeout: 20 * time.Second}

func getJSON(ctx context.Context, method, u string, body any, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := intelClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Vuln is one advisory that affects a library's version.
type Vuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"` // critical, high, medium, low
	Fixed    string   `json:"fixed,omitempty"`
	URL      string   `json:"url"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// npmVulns returns the advisories for each library (npm name, version),
// keyed "name@version". Tests replace it.
var npmVulns = osvNpmVulns

func osvNpmVulns(ctx context.Context, libs [][2]string) (map[string][]Vuln, error) {
	out := map[string][]Vuln{}
	if len(libs) == 0 {
		return out, nil
	}
	type q struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Version string `json:"version"`
	}
	var batch struct {
		Queries []q `json:"queries"`
	}
	for _, l := range libs {
		var x q
		x.Package.Ecosystem, x.Package.Name, x.Version = "npm", l[0], l[1]
		batch.Queries = append(batch.Queries, x)
	}
	var res struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := getJSON(ctx, http.MethodPost, "https://api.osv.dev/v1/querybatch", batch, &res); err != nil {
		return nil, err
	}
	// Fetch each advisory once.
	ids := map[string]bool{}
	for _, r := range res.Results {
		for _, v := range r.Vulns {
			ids[v.ID] = true
		}
	}
	details := map[string]*osvVuln{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var v osvVuln
			if err := getJSON(ctx, http.MethodGet, "https://api.osv.dev/v1/vulns/"+url.PathEscape(id), nil, &v); err == nil {
				mu.Lock()
				details[id] = &v
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	for i, r := range res.Results {
		if i >= len(libs) {
			break
		}
		name, ver := libs[i][0], libs[i][1]
		var vs []Vuln
		for _, ref := range r.Vulns {
			d := details[ref.ID]
			if d == nil {
				vs = append(vs, Vuln{ID: ref.ID, Severity: "medium", URL: "https://osv.dev/vulnerability/" + ref.ID})
				continue
			}
			v := Vuln{ID: d.ID, Aliases: d.Aliases, Summary: d.Summary, URL: "https://osv.dev/vulnerability/" + d.ID}
			if v.Summary == "" {
				v.Summary = firstLine(d.Details)
			}
			v.Severity = osvSeverity(d.DatabaseSpecific.Severity)
			v.Fixed = fixedAfter(d, name, ver)
			vs = append(vs, v)
		}
		sort.Slice(vs, func(a, b int) bool { return rank[vs[a].Severity] > rank[vs[b].Severity] })
		out[name+"@"+ver] = vs
	}
	return out, nil
}

func osvSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "LOW":
		return "low"
	}
	return "medium"
}

// fixedAfter is the lowest fixed version above ver in the advisory's
// ranges for name.
func fixedAfter(d *osvVuln, name, ver string) string {
	best := ""
	for _, a := range d.Affected {
		if a.Package.Ecosystem != "npm" || a.Package.Name != name {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				f := e["fixed"]
				if f == "" {
					continue
				}
				if c, err := version.CompareSemver(f, ver); err != nil || c <= 0 {
					continue
				}
				if best == "" {
					best = f
				} else if c, err := version.CompareSemver(f, best); err == nil && c < 0 {
					best = f
				}
			}
		}
	}
	return best
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\n."); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// wordpressStatus is WordPress.org's word for a core release: "latest",
// "outdated" or "insecure" ("" when unknown).
func wordpressStatus(ctx context.Context, v string) string {
	var m map[string]string
	if err := getJSON(ctx, http.MethodGet, "https://api.wordpress.org/core/stable-check/1.0/", nil, &m); err != nil {
		return ""
	}
	return m[v]
}

// wordpressPluginLatest is the newest release of a plugin on WordPress.org.
func wordpressPluginLatest(ctx context.Context, slug string) string {
	var info struct {
		Version string `json:"version"`
	}
	u := "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=" + url.QueryEscape(slug)
	if err := getJSON(ctx, http.MethodGet, u, nil, &info); err != nil {
		return ""
	}
	return info.Version
}

// eolCycle is a release line's end-of-life date from endoflife.date, for
// a product such as php and a version such as 7.4.33. ok is false when
// the line is unknown or still supported.
func eolCycle(ctx context.Context, product, v string) (cycle, date string, ok bool) {
	var cycles []struct {
		Cycle string `json:"cycle"`
		EOL   any    `json:"eol"` // date string or bool
	}
	if err := getJSON(ctx, http.MethodGet, "https://endoflife.date/api/"+product+".json", nil, &cycles); err != nil {
		return "", "", false
	}
	for _, c := range cycles {
		if v != c.Cycle && !strings.HasPrefix(v, c.Cycle+".") {
			continue
		}
		switch e := c.EOL.(type) {
		case bool:
			return c.Cycle, "", e
		case string:
			t, err := time.Parse("2006-01-02", e)
			if err == nil && t.Before(time.Now()) {
				return c.Cycle, e, true
			}
		}
		return c.Cycle, "", false
	}
	return "", "", false
}
