package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/javaapps"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/version"
)

// FeedJavaApps holds advisories for Java web applications deployed in a
// servlet container (Apache Roller): the product's NVD records, for the
// products of the curated catalogue (internal/javaapps) deployed on some
// host. The libraries in their WEB-INF/lib are Maven packages and are
// matched against OSV like any other.
const FeedJavaApps = "nvd:java-apps"

// isJavaApp reports whether a row is a Java web application the agent
// identified by its own files.
func isJavaApp(r store.EvalRow) bool {
	return r.Type == "generic" && r.Evidence["kind"] == javaapps.Kind
}

// javaAppUnsupported starts the reason on a Java web application row that is
// not matched; the store groups it by that start (unsupportedCategorySQL).
const javaAppUnsupported = "Java web application"

func (e *Evaluator) javaCatalogue() *javaapps.Catalogue {
	if e.JavaApps != nil {
		return e.JavaApps
	}
	return javaapps.Default()
}

// evaluateJavaApp matches one Java web application row against its
// product's NVD records. It sets rc's state and reason and returns the
// findings.
func (e *Evaluator) evaluateJavaApp(ctx context.Context, r store.EvalRow, feeds map[string]store.Feed,
	cache map[string][]store.AdvisoryMatch, unfixed map[string]int, rc *store.RowCoverage) ([]store.FindingInput, error) {
	notEvaluated := func(reason string) { rc.State, rc.Reason = store.CoverageNotEvaluated, reason }
	p := e.javaCatalogue().Identify(r.PurlKey)
	if p == nil {
		rc.State, rc.Reason = store.CoverageUnsupported, javaAppUnsupported+": not in the curated catalogue, so no vulnerability source is matched"
		return nil, nil
	}
	release, verr := p.Release(r.Version)
	feed, configured := feeds[FeedJavaApps]
	switch {
	case verr != nil:
		rc.State, rc.Reason = store.CoverageUnsupported, javaAppUnsupported+": "+verr.Error()
		return nil, nil
	case feedGapReason(FeedJavaApps, feed, configured) != "":
		notEvaluated(feedGapReason(FeedJavaApps, feed, configured))
		return nil, nil
	case feed.Ecosystems != nil && !coversRelease(feed.Ecosystems, p.Ecosystem()):
		notEvaluated(programNotReadReason(p.Label, "NVD", feed.Name))
		return nil, nil
	}
	advs, ok := cache[p.ID]
	if !ok {
		var err error
		if advs, err = e.Store.AdvisoriesFor(ctx, javaapps.Ecosystem, p.ID, p.Ecosystem()); err != nil {
			return nil, err
		}
		cache[p.ID] = advs
	}
	t := osv.Target{Ecosystem: p.Ecosystem(), Name: p.ID, Version: release, Compare: version.Generic}
	found, perr := matchAdvisories(r, t, advs, feed)
	if perr != "" {
		notEvaluated(perr)
		return nil, nil
	}
	rc.Feed = feed.Name
	rc.FeedCursor, rc.FeedLastSuccess, rc.FeedRead = feed.Cursor, feed.LastSuccess, true
	notes := []string{fmt.Sprintf("matched as %s %s against NVD's records for %s", p.Label, release, p.Label)}
	if n := unfixed[p.ID]; n > 0 {
		cves := fmt.Sprintf("%d CVEs", n)
		if n == 1 {
			cves = "1 CVE"
		}
		notes = append(notes, fmt.Sprintf("NVD also names %s in %s with no fixed version or no version bound, which are not matched", p.Label, cves))
	}
	if p.CoverageNote != "" {
		notes = append(notes, p.CoverageNote)
	}
	rc.Reason = strings.Join(notes, "; ")
	for i := range found {
		ev := found[i].Evidence
		// The action plan groups these as one update per host
		// (fixplan ProgramUpdate); "java:" keeps the ids apart from the
		// other catalogues'.
		ev["program"] = JavaAppProgramKey(p.ID)
		ev["program_label"] = p.Label
		ev["program_version"] = release
		ev["java_app"] = p.ID
		ev["java_app_catalogue_version"] = e.javaCatalogue().Version()
	}
	return found, nil
}

// JavaAppProgramKey is the "program" evidence of a Java web application's
// findings.
func JavaAppProgramKey(id string) string { return "java:" + id }

// installedJavaApps returns the catalogued products deployed on any host of
// the installation (system scope, so one workspace's refresh does not
// narrow what is read for the others).
func installedJavaApps(ctx context.Context, st *store.Store) ([]*javaapps.Product, error) {
	var out []*javaapps.Product
	for _, p := range javaapps.Default().Products() {
		ids, err := st.ComponentsWithPurlKey(ctx, p.PurlKey())
		if err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// syncJavaApps reads, for each catalogued product deployed somewhere, every
// CVE NVD names its CPE products in (full, weekly or after a catalogue
// change), or those modified since the last read.
func (s *Syncer) syncJavaApps(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	prods, err := installedJavaApps(tenant.System(ctx), s.Store)
	if err != nil {
		return nil, "", err
	}
	var cur programsCursor
	if cursor != "" {
		_ = json.Unmarshal([]byte(cursor), &cur) // unusable: read everything
	}
	next := programsCursor{Catalogue: javaapps.Default().Version(), Programs: map[string]programCursor{}}
	for id, c := range cur.Programs {
		next.Programs[id] = c
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}, Full: true, Ecosystems: map[string]bool{}}
	var failed []string
	for _, p := range prods {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		now := s.clock()
		pc := next.Programs[p.ID]
		full := pc.Full.IsZero() || now.Sub(pc.Full) >= nvdFullRead || now.Sub(pc.Read) >= nvdIncrMax || cur.Catalogue != next.Catalogue
		unfixed, err := s.syncProgram(ctx, feed, p, full, pc.Read, now, res)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			s.Log.Warn("Java web application advisories not read", "product", p.ID, "err", err)
			failed = append(failed, p.Label+": "+err.Error())
			continue
		}
		if full {
			pc.Unfixed, pc.Full = unfixed, now
		}
		pc.Read = now
		next.Programs[p.ID] = pc
	}
	if len(prods) > 0 && len(failed) == len(prods) {
		return nil, "", fmt.Errorf("no Java web application's advisories could be read: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		res.Warning = fmt.Sprintf("advisories of %d Java web applications could not be read and are kept as last read: %s",
			len(failed), strings.Join(failed, "; "))
	}
	// A product's ecosystem is listed once its advisories have been read
	// completely, so one never read is "not evaluated" rather than clean.
	for id, pc := range next.Programs {
		if !pc.Full.IsZero() {
			res.Ecosystems[javaapps.Ecosystem+":"+id] = true
		}
	}
	b, _ := json.Marshal(next)
	return res, string(b), nil
}

// javaAppComponents is what a Java web application sync re-evaluates: every
// catalogued product's components when the feed's coverage changed,
// otherwise those of the products whose advisories changed.
func javaAppComponents(ctx context.Context, st *store.Store, res *SyncResult) ([]int64, error) {
	var out []int64
	for _, p := range javaapps.Default().Products() {
		if !res.All && !res.Packages[store.PackageRef{BaseEcosystem: javaapps.Ecosystem, Name: p.ID}] {
			continue
		}
		ids, err := st.ComponentsWithPurlKey(ctx, p.PurlKey())
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
	}
	return out, nil
}
