package intel

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// Mozilla publishes its security advisories (MFSA) as one YAML file each in
// github.com/mozilla/foundation-security-advisories (announce/<year>/
// mfsaYYYY-NN.yml): the releases that fix them ("Firefox 131.0.2",
// "Firefox ESR 128.3.1", "Thunderbird 128.3.1") and the CVEs they cover,
// with Mozilla's impact rating. The repository is read as one archive
// (about 600 KB). NVD has not analysed close to half of Mozilla's recent
// CVEs, so it is not used for Mozilla's programs.

// DefaultMozillaURL is the advisory repository's archive.
const DefaultMozillaURL = "https://codeload.github.com/mozilla/foundation-security-advisories/tar.gz/refs/heads/main"

const (
	mozillaArchiveMax = 64 << 20  // compressed; about 600 KB in October 2026
	mozillaTarMax     = 512 << 20 // uncompressed
	mozillaFileMax    = 4 << 20   // one advisory file
)

var (
	mfsaPath  = regexp.MustCompile(`^[^/]+/announce/(\d{4})/(mfsa\d{4}-\d+)\.yml$`)
	mfsaFixed = regexp.MustCompile(`^(Firefox|Firefox ESR|Thunderbird|Thunderbird ESR) (\d+(?:\.\d+)*)$`)
)

type mfsaFile struct {
	Announced  string                  `yaml:"announced"`
	Impact     string                  `yaml:"impact"`
	FixedIn    []string                `yaml:"fixed_in"`
	Title      string                  `yaml:"title"`
	Advisories map[string]mfsaAdvisory `yaml:"advisories"`
}

type mfsaAdvisory struct {
	Title  string `yaml:"title"`
	Impact string `yaml:"impact"`
}

// mfsaDoc is what the archive says, per MFSA.
type mfsaDoc struct {
	id        string
	announced time.Time
	fixed     map[string][]string // product -> versions
	cves      map[string]mfsaAdvisory
}

// readMozilla reads the advisory archive. It fails on anything but a
// complete, readable archive: a truncated download, too large an archive or
// file, or one that lists no advisory.
func readMozilla(r io.Reader) ([]mfsaDoc, int, error) {
	gz, err := gzip.NewReader(&mozillaCap{r: r, left: mozillaArchiveMax, what: "compressed"})
	if err != nil {
		return nil, 0, fmt.Errorf("read Mozilla's advisory archive: %w", err)
	}
	tr := tar.NewReader(&mozillaCap{r: gz, left: mozillaTarMax, what: "uncompressed"})
	var docs []mfsaDoc
	unread := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read Mozilla's advisory archive: %w", err)
		}
		m := mfsaPath.FindStringSubmatch(h.Name)
		if m == nil || h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > mozillaFileMax {
			return nil, 0, fmt.Errorf("Mozilla advisory %s is larger than %d bytes", m[2], mozillaFileMax)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, 0, fmt.Errorf("read Mozilla advisory %s: %w", m[2], err)
		}
		var f mfsaFile
		if err := yaml.Unmarshal(b, &f); err != nil || len(f.Advisories) == 0 {
			unread++ // the oldest files describe their CVEs in prose only
			continue
		}
		d := mfsaDoc{id: m[2], fixed: map[string][]string{}, cves: map[string]mfsaAdvisory{}}
		d.announced, _ = time.Parse("January 2, 2006", strings.TrimSpace(f.Announced))
		for _, x := range f.FixedIn {
			if fm := mfsaFixed.FindStringSubmatch(strings.TrimSpace(x)); fm != nil {
				d.fixed[fm[1]] = append(d.fixed[fm[1]], fm[2])
			}
		}
		for id, a := range f.Advisories {
			id = strings.TrimSpace(id)
			if !cveID.MatchString(id) {
				continue
			}
			if a.Impact == "" {
				a.Impact = f.Impact
			}
			d.cves[id] = a
		}
		if len(d.fixed) > 0 && len(d.cves) > 0 {
			docs = append(docs, d)
		}
	}
	if len(docs) == 0 {
		return nil, unread, errors.New("Mozilla's advisory archive lists no advisory; refusing to read it as empty")
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].id < docs[j].id })
	return docs, unread, nil
}

// mozillaRecords turns the advisories into one record per CVE for a program
// whose source names the products it reads ("Firefox ESR").
func mozillaRecords(p *winprograms.Program, docs []mfsaDoc) []*osv.Vulnerability {
	type agg struct {
		fixes      []string
		title      string
		impact     string
		first      time.Time
		last       time.Time
		advisories []string
	}
	byCVE := map[string]*agg{}
	for _, d := range docs {
		var fixes []string
		for _, prod := range p.Source.Products {
			fixes = append(fixes, d.fixed[prod]...)
		}
		if len(fixes) == 0 {
			continue
		}
		for cve, a := range d.cves {
			g := byCVE[cve]
			if g == nil {
				g = &agg{}
				byCVE[cve] = g
			}
			g.fixes = append(g.fixes, fixes...)
			if g.title == "" || d.announced.After(g.last) {
				g.title = strings.TrimSpace(a.Title)
			}
			if osv.LevelRank(mozillaLevel(a.Impact)) > osv.LevelRank(mozillaLevel(g.impact)) {
				g.impact = a.Impact
			}
			if !d.announced.IsZero() && (g.first.IsZero() || d.announced.Before(g.first)) {
				g.first = d.announced
			}
			if d.announced.After(g.last) {
				g.last = d.announced
			}
			g.advisories = appendUnique(g.advisories, d.id)
		}
	}
	out := make([]*osv.Vulnerability, 0, len(byCVE))
	for cve, g := range byCVE {
		ranges := rollingFixRange(g.fixes)
		if p.Source.PerLine {
			ranges = lineFixRanges(g.fixes)
		}
		if len(ranges) == 0 {
			continue
		}
		v := &osv.Vulnerability{ID: mozillaPrefix(p.ID) + cve, Aliases: []string{cve}, Published: g.first, Modified: g.last,
			Summary: g.title, Affected: lineEntries(p.Ecosystem(), p.ID, ranges)}
		if v.Summary == "" {
			v.Summary = cve + " in " + p.Label
		}
		if l := mozillaLevel(g.impact); l != "unknown" {
			v.DatabaseSpecific = []byte(fmt.Sprintf(`{"severity":%q}`, l))
		}
		sort.Strings(g.advisories)
		for _, a := range g.advisories {
			v.References = append(v.References, osv.Reference{Type: "ADVISORY", URL: "https://www.mozilla.org/en-US/security/advisories/" + a + "/"})
		}
		v.References = append(v.References, osv.Reference{Type: "WEB", URL: "https://nvd.nist.gov/vuln/detail/" + cve})
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mozillaPrefix(program string) string { return "MFSA-" + program + "-" }

// mozillaLevel maps Mozilla's impact ratings to the levels osv.Rate reads.
func mozillaLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	}
	return "unknown"
}

// mozillaCap fails a read past its limit, so an archive that expands
// without bound is an error.
type mozillaCap struct {
	r    io.Reader
	left int64
	what string
}

func (c *mozillaCap) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("Mozilla's advisory archive is larger than the limit (%s)", c.what)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// mozillaDocs downloads and reads the archive once per sync.
func (s *Syncer) mozillaDocs(ctx context.Context) ([]mfsaDoc, error) {
	resp, err := s.f.get(ctx, s.f.cfg.MozillaURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	docs, unread, err := readMozilla(resp.Body)
	if err != nil {
		return nil, err
	}
	if unread > 0 {
		s.Log.Debug("Mozilla advisories without structured CVEs skipped", "count", unread)
	}
	return docs, nil
}
