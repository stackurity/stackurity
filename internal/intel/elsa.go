package intel

import (
	"compress/bzip2"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/version"
)

// Oracle publishes its Linux security advisories (ELSA) as OVAL, one file per
// release at linux.oracle.com/security/oval/com.oracle.elsa-ol<N>.xml.bz2
// (Oracle Linux 7: 3.4 MB compressed, 8: 5.8 MB, 9: 3.6 MB, 10: 1.3 MB; 30 to
// 110 MB of XML). OSV does not carry them. Only the files of the releases in
// inventory are read.
//
// A definition says, per release, which packages are affected below which
// version: AND(Oracle Linux 9 is installed, OR(AND(arch, OR(AND(glibc is
// earlier than 0:2.34-60.0.3.el9, glibc is signed with the Oracle Linux 9
// key), ...)))). The tests, objects and states the criteria name come after
// all definitions, so a file is read in one pass that keeps a compact record
// of each definition (its criteria and metadata) and the test, object and
// state index, never the document.
//
// One file also holds definitions for other releases (an Unbreakable
// Enterprise Kernel advisory covers Oracle Linux 8 and 9 in one definition),
// so a file contributes only the branches of its own release, and its
// advisories carry the release in their id: "OL9-ELSA-2023-12017", aliased
// to ELSA-2023-12017 and the CVEs (so KEV, EPSS and search apply). Each file
// thereby owns its advisories, and one that cannot be read leaves the others'
// alone.
//
// What a branch says beyond "earlier than":
//   - Ksplice and FIPS builds: a package test whose state matches the release
//     "ksplice" or "fips" ("glibc is ksplice-based") limits the branch to
//     those builds, which carry another epoch (glibc 2:2.34-60.0.3.ksplice1.el9,
//     openssl 10:3.5.8-2.0.1.el9_8_fips). Their entries go to their own
//     channel, "Oracle Linux:9:ksplice" or ":fips", which only such builds are
//     matched against; regular entries apply to every build, as in OVAL.
//   - A version pattern next to the fix ("5.15.0" for kernel-uek
//     5.15.0-325.221.6.4.el8uek, "^1\.20\." for a Kubernetes 1.20 package)
//     limits the entry to that line: it becomes the range's introduced
//     version, so a UEK R7 (5.15) kernel is never compared with a UEK R8
//     (6.12) fix, nor RHCK's bpftool 4.18 with UEK's 5.15.
//   - Module streams ("Module nodejs:18 is enabled"): when the stream is the
//     start of the fixed version (nodejs:18 and 1:18.20.4-1.module+el8...),
//     it is the introduced version, as above. Other streams (container-tools:ol8,
//     virt:ol) cannot be told apart by version and are matched like the
//     packages around them.
//   - Architecture and signing key are not used: the agent does not report
//     them. Where the fixed version differs by architecture or a branch lists
//     two fixes for one package, the higher one is kept (OVAL's OR: a version
//     below either fix is affected).

// FeedOracleLinux reads Oracle Linux security advisories (ELSA).
const FeedOracleLinux = "elsa:Oracle Linux"

const (
	elsaFileMax = 64 << 20 // compressed; the largest (Oracle Linux 8) is about 6 MB
	elsaXMLMax  = 1 << 30  // uncompressed; Oracle Linux 8 is about 110 MB
	// elsaMinRelease is the oldest release read: Oracle publishes no OVAL
	// file for Oracle Linux 5.
	elsaMinRelease = 6
)

var (
	// elsaID is an advisory id, with Oracle's revision suffix on some
	// ("ELSA-2025-20518-0", "ELSA-2022-9065-1"): those have no
	// unsuffixed twin, and the suffixed id is the one their page has.
	elsaID       = regexp.MustCompile(`^(ELSA-\d{4}-\d{1,8})(?:-\d{1,3})?$`)
	elsaModule   = regexp.MustCompile(`^Module (\S+) is enabled$`)
	elsaLine     = regexp.MustCompile(`^\d+(?:\.\d+)*$`)
	errNoRelease = errors.New("not published")
)

// elsaPrefix is the id prefix of a release's advisories.
func elsaPrefix(release string) string { return "OL" + release + "-" }

// elsaURL is the OVAL file of a release.
func elsaURL(base, release string) string {
	return base + "/com.oracle.elsa-ol" + release + ".xml.bz2"
}

func (s *Syncer) syncOracleLinux(ctx context.Context, feed string) (*SyncResult, error) {
	base := strings.TrimSuffix(s.f.cfg.OracleLinuxURL, "/")
	releases, err := s.oracleReleases(ctx)
	if err != nil {
		return nil, err
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}}
	var failed []string
	read, records := 0, 0
	for _, rel := range releases {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, err := s.syncOracleRelease(ctx, feed, base, rel, res)
		switch {
		case err == nil:
			read++
			records += n
		case errors.Is(err, errNoRelease):
			// Hosts of a release Oracle publishes nothing for stay "not
			// evaluated": the feed's ecosystems do not list it.
			s.Log.Info("Oracle Linux release has no ELSA file", "release", rel)
		default:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			s.Log.Warn("Oracle Linux ELSA file not read", "release", rel, "err", err)
			failed = append(failed, "Oracle Linux "+rel+": "+err.Error())
		}
	}
	if read == 0 && len(failed) > 0 {
		// Not one file could be read (a broken mirror, an outage): the feed
		// fails and the stored advisories stay as they are.
		return nil, fmt.Errorf("no ELSA file could be read: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		// One bad file must not hold up the others: what was read is stored
		// and re-evaluated and the sync succeeds with a warning. The failed
		// release keeps what was last read of it and is read again next time.
		res.Warning = fmt.Sprintf("%d ELSA files could not be read and are kept as last read: %s",
			len(failed), strings.Join(failed, "; "))
	} else if read > 0 {
		// Ecosystems is complete only when every release was read.
		res.Full = true
		_ = s.Store.SetFeedRecords(ctx, feed, int64(records))
	}
	return res, nil
}

// oracleReleases lists the Oracle Linux major releases in inventory (the
// "ol-9.4" distro qualifier of rpm packages), lowest first. Feeds are shared
// by every workspace, so it reads the whole installation's inventory (only
// the release numbers), also when a workspace asked for the refresh:
// otherwise that sync would read, and report coverage for, only that
// workspace's releases.
func (s *Syncer) oracleReleases(ctx context.Context) ([]string, error) {
	p, err := s.Store.InventoryProfile(tenant.System(ctx))
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	for d := range p.Distros {
		rel, ok := strings.CutPrefix(d, "rpm:ol-")
		if !ok {
			continue
		}
		major, _, _ := strings.Cut(rel, ".")
		if n, err := strconv.Atoi(major); err == nil && n >= elsaMinRelease && n < 100 {
			seen[n] = true
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	rels := make([]string, len(out))
	for i, n := range out {
		rels[i] = strconv.Itoa(n)
	}
	return rels, nil
}

// syncOracleRelease reads one release's file and stores its advisories,
// returning how many it lists. Advisories of the release that the file no
// longer lists are withdrawn.
func (s *Syncer) syncOracleRelease(ctx context.Context, feed, base, rel string, res *SyncResult) (int, error) {
	u := elsaURL(base, rel)
	resp, err := s.f.get(ctx, u, nil)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) && se.Status == 404 {
			return 0, errNoRelease
		}
		return 0, err
	}
	defer resp.Body.Close()
	body := bzip2.NewReader(&elsaCapReader{r: resp.Body, left: elsaFileMax, what: "ELSA file"})
	doc, err := parseELSA(&elsaCapReader{r: body, left: elsaXMLMax, what: "uncompressed ELSA file"}, rel)
	if err != nil {
		return 0, err
	}
	if doc.anomalies > 0 {
		s.Log.Info("ELSA criteria not understood were ignored", "release", rel, "count", doc.anomalies)
	}
	prefix := elsaPrefix(rel)
	stored, err := s.Store.AdvisoryIDs(ctx, feed, prefix)
	if err != nil {
		return 0, err
	}
	// A truncated or broken file would withdraw the release's advisories and
	// close their findings as withdrawn. Oracle adds advisories and revises
	// them, but never drops most of a release's: such a file is refused and
	// what is stored kept.
	if len(doc.vulns) == 0 {
		return 0, fmt.Errorf("lists no advisory for Oracle Linux %s; refusing to read it as empty (the stored ones are kept)", rel)
	}
	if 2*len(doc.vulns) < len(stored) {
		return 0, fmt.Errorf("lists %d advisories for Oracle Linux %s where %d are stored; refusing a file that lost more than half of them (the stored ones are kept)",
			len(doc.vulns), rel, len(stored))
	}
	keep := map[string]bool{}
	for i := 0; i < len(doc.vulns); i += osvBatch {
		batch := doc.vulns[i:min(i+osvBatch, len(doc.vulns))]
		for _, v := range batch {
			keep[v.ID] = true
		}
		n, err := s.Store.UpsertAdvisories(ctx, feed, batch)
		if err != nil {
			return 0, err
		}
		res.noteEcosystems("Oracle Linux", batch)
		res.Changed += n
	}
	var gone []*osv.Vulnerability
	now := s.clock()
	for _, id := range stored {
		if keep[id] {
			continue
		}
		// The withdrawn record keeps its aliases, so it stays in its CVE's
		// group (and the finding it closes says why).
		aliases := []string{strings.TrimPrefix(id, prefix)}
		if advs, err := s.Store.AdvisoryGroup(ctx, id); err == nil {
			for _, a := range advs {
				if a.ID == id && len(a.Aliases) > 0 {
					aliases = a.Aliases
				}
			}
		}
		gone = append(gone, &osv.Vulnerability{ID: id, Aliases: aliases,
			Modified: now, Withdrawn: &now, Summary: "no longer listed in Oracle's ELSA file for Oracle Linux " + rel})
	}
	if len(gone) > 0 {
		n, err := s.Store.UpsertAdvisories(ctx, feed, gone)
		if err != nil {
			return 0, err
		}
		res.Changed += n
	}
	return len(doc.vulns), nil
}

// elsaCapReader fails a read past its limit, so an oversized download is an
// error rather than a truncated (and silently partial) parse.
type elsaCapReader struct {
	r    io.Reader
	left int64
	what string
}

func (c *elsaCapReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, fmt.Errorf("%s larger than the limit", c.what)
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// --- OVAL

type ovalCriteria struct {
	Operator  string          `xml:"operator,attr"`
	Negate    bool            `xml:"negate,attr"`
	Criterion []ovalCriterion `xml:"criterion"`
	Criteria  []ovalCriteria  `xml:"criteria"`
}

type ovalCriterion struct {
	Test   string `xml:"test_ref,attr"`
	Negate bool   `xml:"negate,attr"`
}

type ovalDefinition struct {
	Class    string `xml:"class,attr"`
	Metadata struct {
		Title      string `xml:"title"`
		References []struct {
			Source string `xml:"source,attr"`
			ID     string `xml:"ref_id,attr"`
		} `xml:"reference"`
		Description string `xml:"description"`
		Advisory    struct {
			Severity string `xml:"severity"`
			Issued   struct {
				Date string `xml:"date,attr"`
			} `xml:"issued"`
			CVEs []struct {
				ID    string `xml:",chardata"`
				CVSS3 string `xml:"cvss3,attr"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria ovalCriteria `xml:"criteria"`
}

type ovalTest struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
	Object  struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type ovalObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type ovalValue struct {
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

type ovalState struct {
	ID        string     `xml:"id,attr"`
	EVR       *ovalValue `xml:"evr"`
	Version   *ovalValue `xml:"version"`
	Release   *ovalValue `xml:"release"`
	Arch      *ovalValue `xml:"arch"`
	Signature *ovalValue `xml:"signature_keyid"`
}

// elsaDef is what is kept of a definition until the tests are read.
type elsaDef struct {
	id, title, severity, description string
	issued                           time.Time
	cves                             []string
	vector                           string // the highest CVSS v3 vector of its CVEs
	criteria                         ovalCriteria
}

type elsaTest struct {
	object, state string
	module        string // "nodejs:18" for a module test
}

// elsaDoc is what a file gives.
type elsaDoc struct {
	vulns []*osv.Vulnerability
	// anomalies counts criteria that were not understood (a negated test, a
	// test that is none of release, architecture, key, build, module or
	// package): they are ignored, which can only widen a branch.
	anomalies int
}

// parseELSA streams an OVAL document and returns the release's advisories.
func parseELSA(r io.Reader, release string) (*elsaDoc, error) {
	dec := xml.NewDecoder(r)
	var defs []elsaDef
	tests := map[string]elsaTest{}
	objects := map[string]string{}
	states := map[string]ovalState{}
	root, closed := false, false
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse ELSA file: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			depth--
			if depth == 0 && t.Name.Local == "oval_definitions" {
				closed = true
			}
			continue
		case xml.StartElement:
			if depth == 0 {
				if t.Name.Local != "oval_definitions" {
					return nil, fmt.Errorf("parse ELSA file: not an OVAL document (<%s>)", t.Name.Local)
				}
				root = true
			}
			var err error
			switch t.Name.Local {
			case "definition":
				var d ovalDefinition
				if err = dec.DecodeElement(&d, &t); err == nil {
					if e, ok := compactELSA(d); ok {
						defs = append(defs, e)
					}
				}
			case "rpminfo_test", "textfilecontent54_test":
				var x ovalTest
				if err = dec.DecodeElement(&x, &t); err == nil {
					et := elsaTest{object: x.Object.Ref, state: x.State.Ref}
					if t.Name.Local == "textfilecontent54_test" {
						if m := elsaModule.FindStringSubmatch(strings.TrimSpace(x.Comment)); m != nil {
							et.module = m[1]
						}
					}
					tests[x.ID] = et
				}
			case "rpminfo_object":
				var x ovalObject
				if err = dec.DecodeElement(&x, &t); err == nil {
					objects[x.ID] = strings.TrimSpace(x.Name)
				}
			case "rpminfo_state":
				var x ovalState
				if err = dec.DecodeElement(&x, &t); err == nil {
					states[x.ID] = x
				}
			default:
				depth++
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("parse ELSA file: %w", err)
			}
		}
	}
	if !root || !closed {
		return nil, errors.New("parse ELSA file: the document is incomplete")
	}
	if len(defs) == 0 {
		return nil, errors.New("parse ELSA file: no ELSA definitions")
	}
	doc := &elsaDoc{}
	rs := elsaResolver{release: release, tests: tests, objects: objects, states: states, doc: doc}
	for _, d := range defs {
		if v := rs.record(d); v != nil {
			doc.vulns = append(doc.vulns, v)
		}
	}
	return doc, nil
}

// compactELSA keeps what is read of a definition; ok is false for anything
// but an ELSA (bug fix and enhancement advisories, ELBA and ELEA).
func compactELSA(d ovalDefinition) (elsaDef, bool) {
	e := elsaDef{criteria: d.Criteria}
	for _, r := range d.Metadata.References {
		if r.Source == "elsa" && elsaID.MatchString(strings.TrimSpace(r.ID)) {
			e.id = strings.TrimSpace(r.ID)
			break
		}
	}
	if e.id == "" {
		return e, false
	}
	title := strings.Join(strings.Fields(d.Metadata.Title), " ")
	if _, rest, ok := strings.Cut(title, ":"); ok && strings.HasPrefix(title, e.id) {
		title = strings.TrimSpace(rest)
	}
	e.title = title
	e.severity = strings.TrimSpace(d.Metadata.Advisory.Severity)
	e.description = truncate(strings.TrimSpace(d.Metadata.Description), 8000)
	e.issued = alasTime(d.Metadata.Advisory.Issued.Date)
	best := 0.0
	for _, c := range d.Metadata.Advisory.CVEs {
		id := strings.TrimSpace(c.ID)
		if !cveID.MatchString(id) {
			continue
		}
		e.cves = appendUnique(e.cves, id)
		// cvss3="7.1/CVSS:3.1/AV:N/AC:L/..."
		score, vector, ok := strings.Cut(c.CVSS3, "/")
		if f, err := strconv.ParseFloat(score, 64); ok && err == nil && f > best && strings.HasPrefix(vector, "CVSS:3") {
			best, e.vector = f, vector
		}
	}
	return e, true
}

// elsaKey is one affected entry of an advisory.
type elsaKey struct {
	channel, name, introduced string
}

// elsaContext is what the AND groups above a criterion say.
type elsaContext struct {
	release, module, channel string
}

type elsaResolver struct {
	release string
	tests   map[string]elsaTest
	objects map[string]string
	states  map[string]ovalState
	doc     *elsaDoc
}

// elsaCriterion is a criterion read through its test, object and state.
type elsaCriterion struct {
	release string // "9": Oracle Linux 9 is installed
	module  string // "nodejs:18"
	channel string // "ksplice", "fips": the package is such a build
	pkg     string // with fixed: the package is earlier than fixed
	fixed   string
	line    string // version pattern next to the fix, as a version ("5.15.0", "1.20")
	known   bool
}

func (r *elsaResolver) read(c ovalCriterion) elsaCriterion {
	t, ok := r.tests[c.Test]
	if !ok || c.Negate {
		return elsaCriterion{}
	}
	if t.module != "" {
		return elsaCriterion{module: t.module, known: true}
	}
	name, st := r.objects[t.object], r.states[t.state]
	switch {
	case st.EVR != nil:
		if st.EVR.Operation != "less than" || name == "" {
			return elsaCriterion{}
		}
		out := elsaCriterion{pkg: name, fixed: strings.TrimSpace(st.EVR.Value), known: true}
		if st.Version != nil {
			line, ok := elsaVersionLine(st.Version.Value)
			if !ok {
				return elsaCriterion{}
			}
			out.line = line
		}
		return out
	case name == "oraclelinux-release" && st.Version != nil:
		rel := strings.TrimPrefix(strings.TrimSpace(st.Version.Value), "^")
		if !isDigits(rel) {
			return elsaCriterion{}
		}
		return elsaCriterion{release: rel, known: true}
	case st.Release != nil && st.Release.Operation == "pattern match":
		switch ch := strings.TrimSpace(st.Release.Value); ch {
		case "ksplice", "fips":
			return elsaCriterion{channel: ch, known: true}
		}
	case st.Arch != nil, st.Signature != nil:
		return elsaCriterion{known: true} // not used: the agent does not report them
	}
	return elsaCriterion{}
}

// elsaVersionLine reads a version pattern ("5.15.0", "^1\.20\.") as the
// version line it selects.
func elsaVersionLine(p string) (string, bool) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "^")
	p = strings.ReplaceAll(p, `\.`, ".")
	p = strings.TrimSuffix(p, ".")
	return p, elsaLine.MatchString(p)
}

// walk collects the affected entries of a criteria tree for the release.
func (r *elsaResolver) walk(c ovalCriteria, ctx elsaContext, out map[elsaKey][]string) {
	if c.Negate {
		r.doc.anomalies++
		return
	}
	read := make([]elsaCriterion, len(c.Criterion))
	for i, x := range c.Criterion {
		read[i] = r.read(x)
		if !read[i].known {
			r.doc.anomalies++
		}
	}
	and := !strings.EqualFold(c.Operator, "OR")
	if and {
		// In an AND group the other criteria are conditions of each package
		// test: the release, the module, the build.
		for _, x := range read {
			switch {
			case x.release != "":
				ctx.release = x.release
			case x.module != "":
				ctx.module = x.module
			case x.channel != "":
				ctx.channel = x.channel
			}
		}
	}
	for _, x := range read {
		if x.pkg == "" || ctx.release != r.release {
			continue
		}
		k := elsaKey{channel: ctx.channel, name: x.pkg, introduced: elsaIntroduced(x, ctx)}
		out[k] = appendUnique(out[k], x.fixed)
	}
	for _, sub := range c.Criteria {
		r.walk(sub, ctx, out)
	}
}

// elsaIntroduced is where an entry's range starts: the version line its
// state names, or the module stream when the fixed version starts with it,
// with the fix's epoch; else "0".
func elsaIntroduced(x elsaCriterion, ctx elsaContext) string {
	epoch, ver := "0", x.fixed
	if e, rest, ok := strings.Cut(ver, ":"); ok && isDigits(e) {
		epoch, ver = e, rest
	}
	upstream, _, _ := strings.Cut(ver, "-")
	line := x.line
	if line == "" && ctx.module != "" {
		_, stream, _ := strings.Cut(ctx.module, ":")
		if elsaLine.MatchString(stream) && (upstream == stream || strings.HasPrefix(upstream, stream+".")) {
			line = stream
		}
	}
	if line == "" {
		return "0"
	}
	return epoch + ":" + line
}

func compareRPM(a, b string) int {
	c, _ := version.CompareRPM(a, b)
	return c
}

// record turns a definition into the release's advisory; nil when it has no
// entry for the release.
func (r *elsaResolver) record(d elsaDef) *osv.Vulnerability {
	entries := map[elsaKey][]string{}
	r.walk(d.criteria, elsaContext{}, entries)
	if len(entries) == 0 {
		return nil
	}
	aliases := []string{d.id}
	if base := elsaID.FindStringSubmatch(d.id); base != nil && base[1] != d.id {
		aliases = append(aliases, base[1]) // ELSA-2025-20518 for ELSA-2025-20518-0
	}
	v := &osv.Vulnerability{ID: elsaPrefix(r.release) + d.id, Aliases: append(aliases, d.cves...),
		Summary: d.title, Details: d.description, Published: d.issued, Modified: d.issued}
	if v.Summary == "" {
		v.Summary = d.id
	}
	v.References = append(v.References, osv.Reference{Type: "ADVISORY", URL: "https://linux.oracle.com/errata/" + url.PathEscape(d.id) + ".html"})
	for _, c := range d.cves {
		v.References = append(v.References, osv.Reference{Type: "WEB", URL: "https://linux.oracle.com/cve/" + url.PathEscape(c) + ".html"})
	}
	if d.vector != "" {
		v.Severity = []osv.Severity{{Type: "CVSS_V3", Score: d.vector}}
	}
	if d.severity != "" {
		v.DatabaseSpecific, _ = json.Marshal(map[string]string{"severity": d.severity})
	}
	keys := make([]elsaKey, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.channel != b.channel {
			return a.channel < b.channel
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.introduced < b.introduced
	})
	for _, k := range keys {
		eco := "Oracle Linux:" + r.release
		if k.channel != "" {
			eco += ":" + k.channel
		}
		for _, e := range elsaRanges(k.introduced, entries[k]) {
			v.Affected = append(v.Affected, osv.Affected{Package: osv.Package{Ecosystem: eco, Name: k.name},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: e.events}}})
		}
	}
	return v
}

// elsaRange is one affected range of a package. A range for versions on
// none of the listed lines ends in a limit with no fix, which is how the
// matcher tells it (osv.UnlistedLine).
type elsaRange struct {
	events []osv.Event
}

// elsaRanges turns the fixes a definition lists for one package into
// ranges. Fixes on one version line are alternatives (one per architecture,
// or a z-stream rebuild): the higher one counts, as OVAL's OR reads them.
// Some definitions list fixes for several lines of a package without a
// version pattern (Oracle Cloud Native Environment's kubeadm 1.22.16,
// 1.23.14 and 1.24.8 in one advisory); the highest fix would flag a 1.22
// host whose own line is fixed, so each line (major.minor) gets its own
// range, and a version between or below the listed lines gets an
// "unlisted" range with no fix: the matcher reports it as needing
// validation, never as a plain match. A version above every listed line is
// past every fix, as in OVAL.
func elsaRanges(introduced string, fixes []string) []elsaRange {
	highest := func(vs []string) string {
		best := vs[0]
		for _, v := range vs[1:] {
			if compareRPM(v, best) > 0 {
				best = v
			}
		}
		return best
	}
	single := []elsaRange{{events: []osv.Event{{Introduced: introduced}, {Fixed: highest(fixes)}}}}
	if introduced != "0" || len(fixes) < 2 {
		return single
	}
	type line struct {
		epoch, name  string
		major, minor int
		fixes        []string
	}
	byLine := map[string]*line{}
	for _, f := range fixes {
		epoch, ver := "0", f
		if e, rest, ok := strings.Cut(f, ":"); ok && isDigits(e) {
			epoch, ver = e, rest
		}
		upstream, _, _ := strings.Cut(ver, "-")
		parts := strings.SplitN(upstream, ".", 3)
		if len(parts) < 2 || !isDigits(parts[0]) || !isDigits(parts[1]) {
			return single // not a dotted version: the lines cannot be told
		}
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		name := epoch + ":" + parts[0] + "." + parts[1]
		if byLine[name] == nil {
			byLine[name] = &line{epoch: epoch, name: parts[0] + "." + parts[1], major: major, minor: minor}
		}
		byLine[name].fixes = append(byLine[name].fixes, f)
	}
	if len(byLine) < 2 {
		return single
	}
	lines := make([]*line, 0, len(byLine))
	for _, l := range byLine {
		lines = append(lines, l)
	}
	sort.Slice(lines, func(i, j int) bool {
		return compareRPM(lines[i].epoch+":"+lines[i].name, lines[j].epoch+":"+lines[j].name) < 0
	})
	var out []elsaRange
	from := "0"
	for _, l := range lines {
		start := l.epoch + ":" + l.name
		if from == "0" || compareRPM(from, start) < 0 {
			out = append(out, elsaRange{events: []osv.Event{{Introduced: from}, {Limit: start}}})
		}
		out = append(out, elsaRange{events: []osv.Event{{Introduced: start}, {Fixed: highest(l.fixes)}}})
		from = fmt.Sprintf("%s:%d.%d", l.epoch, l.major, l.minor+1) // the next line starts there
	}
	return out
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
