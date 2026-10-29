package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
	"github.com/stackurity/stackurity/internal/winrelease"
)

// Microsoft publishes Windows security updates in its Security Update Guide,
// one CVRF document per month ("2025-Oct", released on Patch Tuesday and
// revised afterwards) at api.msrc.microsoft.com/cvrf/v3.0. A document lists,
// for each CVE and product, the update (KB) that fixes it and the build that
// update brings: "Windows Server 2022", KB5066782, FixedBuild
// 10.0.20348.4294. OSV does not carry these.
//
// Each CVE of a document becomes one advisory, "MSRC-2025-Oct-CVE-2025-59287",
// with an affected entry per update line ("Windows:Server 2022", package
// "windows") fixed at that line's build; the updates themselves go to
// windows_updates. A CVE that appears in several documents (re-released with
// a new fix) has an advisory in each; the matcher groups them by CVE and
// takes the highest fixed build. Only the cumulative-update lines of Windows
// 10, 11 and Server 2016 and later are read (winrelease.CVRFLine): .NET
// Framework, Office, servicing stack updates and Windows releases numbered
// 6.x are not.
//
// The index (/updates, about 50 KB) says when each document last changed, so
// a sync reads only the documents changed since the last one; every 30 days
// it reads every document in the window again. The window is the last
// MSRCMonths months (24 by default): cumulative updates contain every earlier
// fix, so a host older than the window is still below every fixed build in
// it and is reported; only CVEs fixed before the window are not listed one
// by one. Documents that leave the window are not deleted: what they say
// stays true.

// FeedMSRC is the Windows updates feed (Microsoft's Security Update Guide).
const FeedMSRC = "msrc:Windows"

// DefaultMSRCMonths is how many months of Security Update Guide documents
// are read.
const DefaultMSRCMonths = 24

const (
	msrcIndexMax = 16 << 20  // the index is about 50 KB
	msrcDocMax   = 256 << 20 // the largest document so far (2026-Oct) is 29 MB
	msrcFullRead = 30 * 24 * time.Hour
)

// msrcDocID is a monthly document's id; anything else in the index (ids of
// other forms) is not read, and the id is the only part of the index that
// goes into a URL.
var msrcDocID = regexp.MustCompile(`^(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`)

var (
	cveID  = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	kbNum  = regexp.MustCompile(`^\d{6,8}$`)
	months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
		"Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
)

// msrcCursor records what the feed has read.
type msrcCursor struct {
	Docs map[string]string `json:"docs"` // document id -> CurrentReleaseDate when it was read
	Full time.Time         `json:"full"` // when every document in the window was last read
}

type msrcIndexEntry struct {
	ID                 string `json:"ID"`
	InitialReleaseDate string `json:"InitialReleaseDate"`
	CurrentReleaseDate string `json:"CurrentReleaseDate"`
	month              time.Time
}

func (s *Syncer) syncMSRC(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	base := strings.TrimSuffix(s.f.cfg.MSRCURL, "/")
	n := s.f.cfg.MSRCMonths
	if n <= 0 {
		n = DefaultMSRCMonths
	}
	now := s.clock()
	docs, err := s.msrcIndex(ctx, base, now, n)
	if err != nil {
		return nil, "", err
	}
	var cur msrcCursor
	if cursor != "" {
		_ = json.Unmarshal([]byte(cursor), &cur) // unusable: read everything
	}
	full := cur.Full.IsZero() || now.Sub(cur.Full) >= msrcFullRead
	next := msrcCursor{Docs: map[string]string{}, Full: cur.Full}
	for id, at := range cur.Docs {
		next.Docs[id] = at
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}}
	var failed []string
	read := 0
	for _, d := range docs {
		if !full && cur.Docs[d.ID] == d.CurrentReleaseDate {
			continue
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if err := s.syncMSRCDocument(ctx, feed, base, d, res); err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			s.Log.Warn("Security Update Guide document not read", "document", d.ID, "err", err)
			failed = append(failed, d.ID+": "+err.Error())
			delete(next.Docs, d.ID) // read again by the next sync
			continue
		}
		next.Docs[d.ID] = d.CurrentReleaseDate
		read++
	}
	if read > 0 {
		// A changed update (its KB, its date, a hotpatch build) changes
		// findings without changing any advisory; Windows hosts are few
		// rows, so all of them are evaluated again.
		res.All = true
	}
	if len(failed) == len(docs) {
		// Not one document of the window could be read (a broken mirror,
		// an outage): the feed fails and keeps its cursor.
		return nil, "", fmt.Errorf("no Security Update Guide document could be read: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		// One bad month must not hold up the rest: what was read is stored,
		// its cursor saved and its findings re-evaluated, and the sync
		// succeeds with a warning. Only the failed documents are read again
		// next time; their stored data is kept meanwhile.
		res.Warning = fmt.Sprintf("%d Security Update Guide documents could not be read and are kept as last read: %s",
			len(failed), strings.Join(failed, "; "))
	}
	if full {
		// The full read is done; documents that failed have no cursor
		// entry, so the next sync reads them again.
		next.Full = now
		// Ecosystems is complete only when every document was read.
		res.Full = len(failed) == 0
	}
	b, _ := json.Marshal(next)
	return res, string(b), nil
}

// msrcIndex reads the index and returns the monthly documents of the last n
// months, oldest first.
func (s *Syncer) msrcIndex(ctx context.Context, base string, now time.Time, n int) ([]msrcIndexEntry, error) {
	body, err := s.msrcGet(ctx, base+"/updates", msrcIndexMax)
	if err != nil {
		return nil, err
	}
	var idx struct {
		Value []msrcIndexEntry `json:"value"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("parse Security Update Guide index: %w", err)
	}
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -(n - 1), 0)
	var out []msrcIndexEntry
	seen := map[string]bool{}
	for _, e := range idx.Value {
		m := msrcDocID.FindStringSubmatch(e.ID)
		if m == nil || seen[e.ID] {
			continue
		}
		y, _ := strconv.Atoi(m[1])
		e.month = time.Date(y, months[m[2]], 1, 0, 0, 0, 0, time.UTC)
		if e.month.Before(first) || e.month.After(now) {
			continue
		}
		seen[e.ID] = true
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the Security Update Guide index lists no monthly document for the last %d months; refusing to read it as empty", n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].month.Before(out[j].month) })
	return out, nil
}

// msrcGet downloads a Security Update Guide resource as JSON (the API
// answers XML without the Accept header), at most max bytes.
func (s *Syncer) msrcGet(ctx context.Context, url string, max int64) ([]byte, error) {
	resp, err := s.f.get(ctx, url, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, max)
	}
	return b, nil
}

// syncMSRCDocument reads one monthly document and stores its advisories and
// updates. Advisories of the document that it no longer lists are withdrawn.
func (s *Syncer) syncMSRCDocument(ctx context.Context, feed, base string, d msrcIndexEntry, res *SyncResult) error {
	resp, err := s.f.get(ctx, base+"/cvrf/"+d.ID, map[string]string{"Accept": "application/json"})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	doc, err := parseCVRF(&msrcCapReader{r: resp.Body, left: msrcDocMax}, d.ID)
	if err != nil {
		return err
	}
	if doc.anomalies > 0 {
		s.Log.Info("Security Update Guide fixed builds skipped", "document", d.ID, "count", doc.anomalies,
			"why", "the build is not one of the product's own line")
	}
	stored, err := s.Store.AdvisoryIDs(ctx, feed, msrcPrefix(d.ID))
	if err != nil {
		return err
	}
	// A truncated or broken document would withdraw a month of advisories
	// and close their findings as withdrawn. Microsoft revises documents,
	// but never drops most of a month's CVEs: such a document is refused and
	// the stored month kept.
	if len(stored) > 0 && (len(doc.vulns) == 0 || 2*len(doc.vulns) < len(stored)) {
		return fmt.Errorf("lists %d Windows CVEs where %d are stored; refusing a document that lost more than half of them (the stored ones are kept)",
			len(doc.vulns), len(stored))
	}
	keep := map[string]bool{}
	for i := 0; i < len(doc.vulns); i += osvBatch {
		batch := doc.vulns[i:min(i+osvBatch, len(doc.vulns))]
		for _, v := range batch {
			keep[v.ID] = true
		}
		n, err := s.Store.UpsertAdvisories(ctx, feed, batch)
		if err != nil {
			return err
		}
		res.noteEcosystems("Windows", batch)
		res.Changed += n
	}
	var gone []*osv.Vulnerability
	now := s.clock()
	for _, id := range stored {
		if !keep[id] {
			gone = append(gone, &osv.Vulnerability{ID: id, Aliases: []string{strings.TrimPrefix(id, msrcPrefix(d.ID))},
				Modified: now, Withdrawn: &now, Summary: "no longer listed in the " + d.ID + " Security Update Guide document"})
		}
	}
	if len(gone) > 0 {
		n, err := s.Store.UpsertAdvisories(ctx, feed, gone)
		if err != nil {
			return err
		}
		res.Changed += n
	}
	return s.Store.ReplaceWindowsUpdates(ctx, d.ID, doc.updates)
}

func msrcPrefix(doc string) string { return "MSRC-" + doc + "-" }

// msrcCapReader fails a read past its limit, so an oversized document is an
// error rather than a truncated (and silently partial) parse.
type msrcCapReader struct {
	r    io.Reader
	left int64
}

func (c *msrcCapReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("Security Update Guide document larger than %d bytes", msrcDocMax)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// --- CVRF

// cvrfVuln is the part of a CVRF Vulnerability element that is read.
type cvrfVuln struct {
	CVE   string `json:"CVE"`
	Title struct {
		Value string `json:"Value"`
	} `json:"Title"`
	Threats []struct {
		Type        int `json:"Type"` // 3: severity
		Description struct {
			Value string `json:"Value"`
		} `json:"Description"`
		ProductID []string `json:"ProductID"`
	} `json:"Threats"`
	CVSSScoreSets []struct {
		BaseScore float64  `json:"BaseScore"`
		Vector    string   `json:"Vector"`
		ProductID []string `json:"ProductID"`
	} `json:"CVSSScoreSets"`
	Remediations []struct {
		Type        int `json:"Type"` // 2: vendor fix
		Description struct {
			Value string `json:"Value"` // the KB number
		} `json:"Description"`
		SubType    string   `json:"SubType"`
		FixedBuild string   `json:"FixedBuild"`
		ProductID  []string `json:"ProductID"`
	} `json:"Remediations"`
	RevisionHistory []struct {
		Date string `json:"Date"`
	} `json:"RevisionHistory"`
}

// cvrfDoc is what a document gives: advisories and updates.
type cvrfDoc struct {
	vulns   []*osv.Vulnerability
	updates []store.WindowsUpdate
	// anomalies counts fixed builds skipped because their build is not the
	// product's own (Microsoft lists a Windows 7 build for Windows 11 22H2
	// in CVE-2024-43583).
	anomalies int
}

// cvrfFix is one vendor fix of a CVE, kept from the stream until the
// product names are known.
type cvrfFix struct {
	kb, subType, build string
	products           []string
}

type cvrfCompact struct {
	cve, title          string
	published, modified time.Time
	severity            map[string]string // product id -> Critical, Important, ...
	cvss                map[string]cvrfScore
	fixes               []cvrfFix
}

type cvrfScore struct {
	score  float64
	vector string
}

// parseCVRF streams a CVRF document (JSON), holding one Vulnerability element
// at a time, and keeps only vendor fixes with a Windows 10.0 build.
func parseCVRF(r io.Reader, docID string) (*cvrfDoc, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	names := map[string]string{}
	var released, revised time.Time
	var vulns []cvrfCompact
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", docID, err)
		}
		key, _ := tok.(string)
		switch key {
		case "DocumentTracking":
			var dt struct {
				InitialReleaseDate string `json:"InitialReleaseDate"`
				CurrentReleaseDate string `json:"CurrentReleaseDate"`
			}
			if err := dec.Decode(&dt); err != nil {
				return nil, fmt.Errorf("parse %s: %w", docID, err)
			}
			released, revised = cvrfTime(dt.InitialReleaseDate), cvrfTime(dt.CurrentReleaseDate)
		case "ProductTree":
			var pt struct {
				FullProductName []struct {
					ProductID string `json:"ProductID"`
					Value     string `json:"Value"`
				} `json:"FullProductName"`
			}
			if err := dec.Decode(&pt); err != nil {
				return nil, fmt.Errorf("parse %s: %w", docID, err)
			}
			for _, p := range pt.FullProductName {
				names[p.ProductID] = p.Value
			}
		case "Vulnerability":
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", docID, err)
			}
			if tok == nil {
				continue // null: no CVEs (syncMSRCDocument refuses losing a month)
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return nil, fmt.Errorf("parse %s: expected \"[\", found %v", docID, tok)
			}
			for dec.More() {
				var v cvrfVuln
				if err := dec.Decode(&v); err != nil {
					return nil, fmt.Errorf("parse %s: %w", docID, err)
				}
				if c, ok := compactCVRF(v); ok {
					vulns = append(vulns, c)
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, fmt.Errorf("parse %s: %w", docID, err)
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("parse %s: %w", docID, err)
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, fmt.Errorf("parse %s: %w", docID, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("parse %s: no product tree", docID)
	}
	if released.IsZero() {
		return nil, fmt.Errorf("parse %s: no release date", docID)
	}
	lines := map[string]string{}
	for id, n := range names {
		if l := winrelease.CVRFLine(n); l != "" {
			lines[id] = l
		}
	}
	doc := &cvrfDoc{}
	updates := map[[3]string]store.WindowsUpdate{}
	uses := map[[2]string]int{} // line, build -> CVEs fixed by it
	for _, c := range vulns {
		if v := cvrfRecord(c, docID, released, revised, lines, updates, doc); v != nil {
			doc.vulns = append(doc.vulns, v)
			for _, a := range v.Affected {
				uses[[2]string{strings.TrimPrefix(a.Package.Ecosystem, "Windows:"), a.Ranges[0].Events[1].Fixed}]++
			}
		}
	}
	// The document's own update for each line is the build most of its
	// CVEs are fixed in; ties go to the lower build (an out-of-band update
	// comes after the monthly one).
	monthly := map[string]string{}
	for k, n := range uses {
		line, build := k[0], k[1]
		cur, ok := monthly[line]
		if !ok || n > uses[[2]string{line, cur}] || (n == uses[[2]string{line, cur}] && compareBuild(build, cur) < 0) {
			monthly[line] = build
		}
	}
	for _, u := range updates {
		u.Monthly = !u.Hotpatch && monthly[u.Line] == u.Build
		doc.updates = append(doc.updates, u)
	}
	sort.Slice(doc.updates, func(i, j int) bool {
		a, b := doc.updates[i], doc.updates[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Build != b.Build {
			return a.Build < b.Build
		}
		return a.KB < b.KB
	})
	return doc, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, found %v", want, tok)
	}
	return nil
}

// compactCVRF keeps what a vulnerability element says about Windows builds;
// ok is false when it has no vendor fix with a 10.0 build.
func compactCVRF(v cvrfVuln) (cvrfCompact, bool) {
	c := cvrfCompact{cve: strings.TrimSpace(v.CVE), title: strings.TrimSpace(v.Title.Value)}
	if !cveID.MatchString(c.cve) {
		return c, false // ADV advisories and others without a CVE
	}
	for _, r := range v.Remediations {
		if r.Type != 2 || !strings.HasPrefix(strings.TrimSpace(r.FixedBuild), "10.0.") {
			continue
		}
		c.fixes = append(c.fixes, cvrfFix{kb: strings.TrimPrefix(strings.TrimSpace(r.Description.Value), "KB"),
			subType: strings.TrimSpace(r.SubType), build: strings.TrimSpace(r.FixedBuild), products: r.ProductID})
	}
	if len(c.fixes) == 0 {
		return c, false
	}
	c.severity, c.cvss = map[string]string{}, map[string]cvrfScore{}
	for _, t := range v.Threats {
		if t.Type == 3 {
			for _, p := range t.ProductID {
				c.severity[p] = strings.TrimSpace(t.Description.Value)
			}
		}
	}
	for _, s := range v.CVSSScoreSets {
		for _, p := range s.ProductID {
			if s.BaseScore > c.cvss[p].score {
				c.cvss[p] = cvrfScore{s.BaseScore, strings.TrimSpace(s.Vector)}
			}
		}
	}
	for _, h := range v.RevisionHistory {
		t := cvrfTime(h.Date)
		if t.IsZero() {
			continue
		}
		if c.published.IsZero() || t.Before(c.published) {
			c.published = t
		}
		if t.After(c.modified) {
			c.modified = t
		}
	}
	return c, true
}

// hotpatch reports whether a Security Update Guide subtype is a hotpatch
// ("Security Hotpatch Update", "SecurityHotpatchUpdate").
func hotpatch(subType string) bool { return strings.Contains(strings.ToLower(subType), "hotpatch") }

// cvrfRecord turns one CVE of a document into an advisory, adding the
// updates it names to updates. nil when no update line has a usable fix.
func cvrfRecord(c cvrfCompact, docID string, released, revised time.Time, lines map[string]string,
	updates map[[3]string]store.WindowsUpdate, doc *cvrfDoc) *osv.Vulnerability {
	type best struct {
		ubr   int
		build string
		kb    string
	}
	fixed := map[string]best{}
	severity, label := cvrfScore{}, ""
	var kbs []string
	for _, f := range c.fixes {
		for _, pid := range f.products {
			line := lines[pid]
			if line == "" {
				continue
			}
			lb, _ := winrelease.LineBuild(line)
			b, ubr, ok := winrelease.ParseBuild(f.build)
			if !ok || !winrelease.Siblings(b, lb) {
				doc.anomalies++
				continue
			}
			// A sibling's build (10.0.19044.x for Windows 10 22H2) is the
			// same update: the line's own build with that revision.
			build := fmt.Sprintf("10.0.%d.%d", lb, ubr)
			kb := ""
			if kbNum.MatchString(f.kb) {
				kb = f.kb
			}
			hp := hotpatch(f.subType)
			k := [3]string{line, build, kb}
			if _, ok := updates[k]; !ok {
				updates[k] = store.WindowsUpdate{Line: line, Build: build, KB: kb, Kind: f.subType, Hotpatch: hp,
					Released: released, Document: docID}
			}
			if hp {
				continue // applies only to hosts enrolled in hotpatching
			}
			// Two regular fixes for one line (the Patch Tuesday update and
			// an out-of-band one that completed the fix, as for
			// CVE-2025-59287): the higher build is the one that fixes it.
			if cur, ok := fixed[line]; !ok || ubr > cur.ubr {
				fixed[line] = best{ubr, build, kb}
			}
			if s := c.cvss[pid]; s.score > severity.score {
				severity = s
			}
			if l := c.severity[pid]; osv.LevelRank(msrcLevel(l)) > osv.LevelRank(msrcLevel(label)) {
				label = l
			}
		}
	}
	if len(fixed) == 0 {
		return nil
	}
	v := &osv.Vulnerability{ID: msrcPrefix(docID) + c.cve, Aliases: []string{c.cve}, Summary: c.title,
		Published: c.published, Modified: c.modified}
	if v.Published.IsZero() {
		v.Published = released
	}
	if v.Modified.IsZero() {
		v.Modified = revised
	}
	if v.Summary == "" {
		v.Summary = c.cve + " in Windows"
	}
	v.References = append(v.References, osv.Reference{Type: "ADVISORY", URL: "https://msrc.microsoft.com/update-guide/vulnerability/" + c.cve})
	ls := make([]string, 0, len(fixed))
	for l := range fixed {
		ls = append(ls, l)
	}
	sort.Strings(ls)
	for _, l := range ls {
		f := fixed[l]
		v.Affected = append(v.Affected, osv.Affected{
			Package: osv.Package{Ecosystem: "Windows:" + l, Name: "windows"},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: f.build}}}},
		})
		if f.kb != "" {
			kbs = appendUnique(kbs, f.kb)
		}
	}
	sort.Strings(kbs)
	for _, kb := range kbs {
		v.References = append(v.References, osv.Reference{Type: "WEB", URL: "https://support.microsoft.com/help/" + kb})
	}
	if strings.HasPrefix(severity.vector, "CVSS:3") {
		v.Severity = []osv.Severity{{Type: "CVSS_V3", Score: severity.vector}}
	}
	if label != "" {
		v.DatabaseSpecific, _ = json.Marshal(map[string]string{"severity": label})
	}
	return v
}

// compareBuild compares two Windows builds "10.0.<build>.<ubr>" numerically.
func compareBuild(a, b string) int {
	c, _ := version.CompareGeneric(a, b)
	return c
}

// msrcLevel maps Microsoft's severity ratings (Critical, Important,
// Moderate, Low) to the levels osv.Rate reads.
func msrcLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "important":
		return "high"
	case "moderate":
		return "medium"
	case "low":
		return "low"
	}
	return "unknown"
}

// cvrfTime reads the API's dates: "2025-10-14T07:00:00" in documents,
// "2025-10-14T07:00:00Z" in the index.
func cvrfTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			if t.Year() <= 1 {
				return time.Time{} // "0001-01-01T00:00:00": not specified
			}
			return t.UTC()
		}
	}
	return time.Time{}
}
