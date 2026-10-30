package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// NVD's CVE API 2.0 (services.nvd.nist.gov/rest/json/cves/2.0) answers, for
// a CPE product given as virtualMatchString, every CVE whose configurations
// name that product, with the version ranges NVD's analysts recorded. It is
// read for the programs of the curated Windows program catalogue
// (internal/winprograms), never searched by a program's name.
//
// NVD has a backlog: a CVE NVD has not analysed has no configuration and
// so is not returned for any product. Those CVEs are not matched; the
// catalogue's documentation says so.

const (
	nvdPage      = 2000      // NVD's largest page
	nvdPageMax   = 128 << 20 // one page; Firefox's largest is about 40 MB
	nvdTotalMax  = 20000     // a CPE answering more is not a program's
	nvdFullRead  = 7 * 24 * time.Hour
	nvdIncrMax   = 100 * 24 * time.Hour // NVD allows 120 days per query
	nvdSummary   = 480                  // bytes; the store keeps 500
	nvdOverlap   = time.Hour            // incremental reads start this much before the last read
	nvdMaxRefs   = 6
	nvdTimeParam = "2006-01-02T15:04:05.000Z07:00"
)

type nvdResponse struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Vulnerabilities []nvdWrapped `json:"vulnerabilities"`
}

type nvdWrapped struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        map[string][]nvdMetric `json:"metrics"`
	Configurations []nvdConfig            `json:"configurations"`
	References     []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
}

type nvdMetric struct {
	Type     string `json:"type"` // Primary (NVD), Secondary (the CNA)
	CVSSData struct {
		VectorString string `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdConfig struct {
	Operator string    `json:"operator"`
	Negate   bool      `json:"negate"`
	Nodes    []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// nvdAnomalies counts what a conversion skipped, by reason.
type nvdAnomalies map[string]int

func (a nvdAnomalies) String() string {
	ks := make([]string, 0, len(a))
	for k := range a {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = fmt.Sprintf("%s %d", k, a[k])
	}
	return strings.Join(parts, ", ")
}

// Reasons a CPE match of a program is not used.
const (
	nvdUnbounded    = "no version bound"        // "all versions": never a usable claim
	nvdStartOnly    = "lower bound only"        // no fix and no last affected version
	nvdStartExcl    = "start excluding"         // cannot be expressed exactly
	nvdUnreadable   = "version not readable"    // not in the form installed versions are read in
	nvdOtherOS      = "another platform only"   // an AND configuration for macOS, Linux...
	nvdNegated      = "negated configuration"   // NVD's rare "not" nodes
	nvdNoUsableCPEs = "no usable configuration" // the CVE names the product, but nothing above was usable
)

// windowsPlatform reports whether a non-vulnerable platform CPE allows
// Windows: a Windows CPE, or any operating system ("*").
func windowsPlatform(criteria string) bool {
	f := winprograms.SplitCPE(criteria)
	if len(f) < 5 {
		return false
	}
	switch {
	case f[2] == "o" && f[3] == "microsoft" && strings.HasPrefix(f[4], "windows"):
		return true
	case f[2] == "o" && f[3] == "*":
		return true
	}
	return false
}

// nvdRecord turns one NVD CVE into an advisory for a program: the ranges of
// the configurations that name the program's CPE products for Windows. nil
// when none does (the CVE is about another product, platform or edition, or
// nothing usable is recorded); anomalies counts what was skipped.
func nvdRecord(p *winprograms.Program, c nvdCVE, anomalies nvdAnomalies) *osv.Vulnerability {
	if !cveID.MatchString(c.ID) || strings.EqualFold(c.VulnStatus, "Rejected") {
		return nil
	}
	aff := osv.Affected{Package: osv.Package{Ecosystem: p.Ecosystem(), Name: p.ID}}
	seenRange, seenVersion := map[string]bool{}, map[string]bool{}
	owned := false
	for _, cfg := range c.Configurations {
		var platform []nvdNode
		var vulnerable []nvdNode
		for _, n := range cfg.Nodes {
			anyVuln := false
			for _, m := range n.CPEMatch {
				anyVuln = anyVuln || m.Vulnerable
			}
			if anyVuln {
				vulnerable = append(vulnerable, n)
			} else {
				platform = append(platform, n)
			}
		}
		mine := false
		for _, n := range vulnerable {
			for _, m := range n.CPEMatch {
				if m.Vulnerable && p.OwnsCPE(m.Criteria) {
					mine = true
				}
			}
		}
		if !mine {
			continue
		}
		owned = true
		if cfg.Negate {
			anomalies[nvdNegated]++
			continue
		}
		if strings.EqualFold(cfg.Operator, "AND") && len(platform) > 0 {
			// "Program X running on Y": only a configuration that allows
			// Windows applies to a Windows host.
			windows := false
			for _, n := range platform {
				if n.Negate {
					continue
				}
				for _, m := range n.CPEMatch {
					windows = windows || windowsPlatform(m.Criteria)
				}
			}
			if !windows {
				anomalies[nvdOtherOS]++
				continue
			}
		}
		for _, n := range vulnerable {
			if n.Negate {
				anomalies[nvdNegated]++
				continue
			}
			for _, m := range n.CPEMatch {
				if !m.Vulnerable || !p.OwnsCPE(m.Criteria) {
					continue
				}
				r, exact, why := nvdRange(p, m)
				switch {
				case why != "":
					anomalies[why]++
				case exact != "":
					if !seenVersion[exact] {
						seenVersion[exact] = true
						aff.Versions = append(aff.Versions, exact)
					}
				default:
					k := fmt.Sprint(r.Events)
					if !seenRange[k] {
						seenRange[k] = true
						aff.Ranges = append(aff.Ranges, r)
					}
				}
			}
		}
	}
	if len(aff.Ranges) == 0 && len(aff.Versions) == 0 {
		if owned {
			anomalies[nvdNoUsableCPEs]++
		}
		return nil
	}
	v := &osv.Vulnerability{ID: nvdPrefix(p.ID) + c.ID, Aliases: []string{c.ID}, Affected: []osv.Affected{aff},
		Published: nvdTime(c.Published), Modified: nvdTime(c.LastModified)}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Summary = nvdSummaryText(d.Value)
			break
		}
	}
	if v.Summary == "" {
		v.Summary = c.ID + " in " + p.Label
	}
	if sev := nvdSeverity(c.Metrics); sev != nil {
		v.Severity = []osv.Severity{*sev}
	}
	v.References = append(v.References, osv.Reference{Type: "ADVISORY", URL: "https://nvd.nist.gov/vuln/detail/" + c.ID})
	n := 0
	for _, r := range c.References {
		if n >= nvdMaxRefs || !strings.HasPrefix(r.URL, "https://") {
			continue
		}
		for _, t := range r.Tags {
			if t == "Vendor Advisory" || t == "Release Notes" || t == "Patch" {
				v.References = append(v.References, osv.Reference{Type: "WEB", URL: r.URL})
				n++
				break
			}
		}
	}
	return v
}

// nvdRange reads one CPE match: a range, an exact version, or why it is
// not used.
func nvdRange(p *winprograms.Program, m nvdCPEMatch) (r osv.Range, exact, why string) {
	read := func(s string) (string, bool) { return p.SourceVersion(s) }
	if m.VersionEndExcluding == "" && m.VersionEndIncluding == "" {
		switch {
		case m.VersionStartIncluding != "" || m.VersionStartExcluding != "":
			return r, "", nvdStartOnly
		}
		cv := winprograms.CPEVersion(m.Criteria)
		if cv == "" {
			return r, "", nvdUnbounded
		}
		v, ok := read(cv)
		if !ok {
			return r, "", nvdUnreadable
		}
		return r, v, ""
	}
	if m.VersionStartExcluding != "" {
		return r, "", nvdStartExcl
	}
	r.Type = "ECOSYSTEM"
	start := "0"
	if m.VersionStartIncluding != "" {
		v, ok := read(m.VersionStartIncluding)
		if !ok {
			return r, "", nvdUnreadable
		}
		start = v
	}
	r.Events = append(r.Events, osv.Event{Introduced: start})
	if m.VersionEndExcluding != "" {
		v, ok := read(m.VersionEndExcluding)
		if !ok {
			return r, "", nvdUnreadable
		}
		r.Events = append(r.Events, osv.Event{Fixed: v})
	} else {
		v, ok := read(m.VersionEndIncluding)
		if !ok {
			return r, "", nvdUnreadable
		}
		r.Events = append(r.Events, osv.Event{LastAffected: v})
	}
	return r, "", ""
}

func nvdPrefix(program string) string { return "NVD-" + program + "-" }

// nvdSeverity picks a CVSS vector: v3.1, then v3.0, then v4.0; NVD's own
// (Primary) before the CNA's.
func nvdSeverity(metrics map[string][]nvdMetric) *osv.Severity {
	for _, k := range []struct{ key, typ string }{{"cvssMetricV31", "CVSS_V3"}, {"cvssMetricV30", "CVSS_V3"}, {"cvssMetricV40", "CVSS_V4"}} {
		ms := metrics[k.key]
		for _, primary := range []bool{true, false} {
			for _, m := range ms {
				if (m.Type == "Primary") == primary && m.CVSSData.VectorString != "" {
					return &osv.Severity{Type: k.typ, Score: m.CVSSData.VectorString}
				}
			}
		}
	}
	return nil
}

func nvdSummaryText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= nvdSummary {
		return s
	}
	cut := s[:nvdSummary]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1] // not inside a character
	}
	if i := strings.LastIndexByte(cut, ' '); i > nvdSummary/2 {
		cut = cut[:i]
	}
	return cut + "…"
}

func nvdTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// nvdQuery reads every page of the CVEs naming one CPE product, modified in
// [since, until) when since is set. It fails rather than return a partial
// answer: a page out of place, fewer CVEs than NVD said it has, or a total
// that changes between pages.
func (s *Syncer) nvdQuery(ctx context.Context, cpe string, since, until time.Time, each func(nvdCVE) error) error {
	base := strings.TrimSuffix(s.f.cfg.NVDURL, "/")
	total, read := -1, 0
	for start := 0; ; start += nvdPage {
		q := url.Values{}
		q.Set("virtualMatchString", cpe)
		q.Set("resultsPerPage", fmt.Sprint(nvdPage))
		q.Set("startIndex", fmt.Sprint(start))
		if !since.IsZero() {
			q.Set("lastModStartDate", since.UTC().Format(nvdTimeParam))
			q.Set("lastModEndDate", until.UTC().Format(nvdTimeParam))
		}
		page, err := s.nvdPage(ctx, base+"?"+q.Encode())
		if err != nil {
			return err
		}
		switch {
		case page.StartIndex != start:
			return fmt.Errorf("NVD answered from index %d when %d was asked", page.StartIndex, start)
		case page.TotalResults < 0 || page.TotalResults > nvdTotalMax:
			return fmt.Errorf("NVD lists %d CVEs for %s; refusing more than %d", page.TotalResults, cpe, nvdTotalMax)
		case total >= 0 && page.TotalResults != total:
			return fmt.Errorf("NVD's count for %s changed from %d to %d while it was read; read again next time", cpe, total, page.TotalResults)
		case len(page.Vulnerabilities) > nvdPage:
			return fmt.Errorf("NVD returned %d CVEs in a page of %d", len(page.Vulnerabilities), nvdPage)
		}
		total = page.TotalResults
		for _, w := range page.Vulnerabilities {
			if err := each(w.CVE); err != nil {
				return err
			}
		}
		read += len(page.Vulnerabilities)
		if read >= total || len(page.Vulnerabilities) == 0 {
			break
		}
	}
	if read != total {
		return fmt.Errorf("NVD said %d CVEs name %s but returned %d; refusing a truncated answer", total, cpe, read)
	}
	return nil
}

// nvdPage downloads one page, waiting between requests as NVD asks (it
// allows 5 requests in 30 seconds without an API key, 50 with one) and
// again after a refusal (NVD answers 403 when the rate is exceeded).
func (s *Syncer) nvdPage(ctx context.Context, u string) (*nvdResponse, error) {
	headers := map[string]string{"Accept": "application/json"}
	if k := s.f.cfg.NVDAPIKey; k != "" {
		headers["apiKey"] = k
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		wait := s.f.cfg.NVDDelay
		if attempt > 0 {
			wait = s.f.cfg.NVDBackoff
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return nil, err
		}
		resp, err := s.f.get(ctx, u, headers)
		if err != nil {
			var se *statusError
			if errors.As(err, &se) && se.Status == 403 {
				lastErr = err
				continue
			}
			return nil, err
		}
		var page nvdResponse
		err = json.NewDecoder(&nvdCapReader{r: resp.Body, left: nvdPageMax}).Decode(&page)
		if err == nil {
			// Nothing may follow the document.
			if _, terr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10)); terr != nil {
				err = terr
			}
		}
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read NVD answer: %w", err)
		}
		return &page, nil
	}
	return nil, lastErr
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// nvdCapReader fails a read past its limit, so an oversized page is an
// error rather than a truncated (and silently partial) parse.
type nvdCapReader struct {
	r    io.Reader
	left int64
}

func (c *nvdCapReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("NVD page larger than %d bytes", nvdPageMax)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
