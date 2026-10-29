package intel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// closure is how a finding closed.
type closure struct {
	status, kind, resolution string
	detail                   map[string]any
}

func (e *changeEnv) closures() map[string]closure {
	e.t.Helper()
	rows, err := e.st.Pool.Query(e.ctx, `SELECT f.key || ' ' || split_part(split_part(i.purl, '@', 1), '/', 3), f.status,
		f.resolution_kind, f.resolution, f.resolution_detail
		FROM findings f JOIN inventory i ON i.id = f.inventory_id WHERE f.asset_id = $1 ORDER BY f.id`, e.host)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]closure{}
	for rows.Next() {
		var k string
		var c closure
		if err := rows.Scan(&k, &c.status, &c.kind, &c.resolution, &c.detail); err != nil {
			e.t.Fatal(err)
		}
		if prev, ok := out[k]; ok && prev.status == "open" {
			continue // a finding on another row of the same package: keep the open one
		}
		out[k] = c
	}
	return out
}

// A finding closes with the specific reason: a withdrawn advisory and a
// changed one close it with nothing changed on the host, which reports do
// not count as remediation; an upgrade to a fixed version is remediation;
// an upgrade to a version that is still affected is not.
func TestClosedFindingsSayWhy(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	for k, c := range e.closures() {
		if c.status != "open" || c.kind != "" {
			t.Fatalf("%s = %+v before any change", k, c)
		}
	}

	// Debian withdraws DSA-0001-1 and drops zlib from DSA-0003-1.
	recs := baseRecords
	recs.opensslWithdrawn, recs.withZlib, recs.modified = true, false, "2024-03-02T00:00:00Z"
	e.evaluate(e.sync(recs))
	c := e.closures()
	if o := c["CVE-2024-0001 openssl"]; o.status != "resolved" || o.kind != store.ResolutionAdvisoryWithdrawn ||
		o.resolution != "advisory withdrawn by Debian on 2024-03-01" || o.detail["source"] != "Debian" ||
		o.detail["feed"] != "osv:Debian" || o.detail["withdrawn_at"] == nil || o.detail["version"] != "3.0.11-1~deb12u1" {
		t.Errorf("withdrawn advisory: %+v", o)
	}
	if z := c["CVE-2024-0003 zlib"]; z.status != "resolved" || z.kind != store.ResolutionAdvisoryChanged ||
		z.resolution != "advisory updated: DSA-0003-1 no longer lists zlib 1:1.2.13.dfsg-1" {
		t.Errorf("changed advisory: %+v", z)
	}

	// curl is upgraded to the fixed version; libxml2 to a newer build that
	// is still affected.
	e.host = ingest(t, e.st, model.AssetHost, "web-1", true,
		confirmed("pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12", nil),
		confirmed("pkg:deb/debian/curl@7.88.1-10+deb12u6?distro=debian-12", nil),
		confirmed("pkg:deb/debian/libxml2@2.9.14+dfsg-1.3~deb12u1+b1?distro=debian-12", nil),
		confirmed("pkg:deb/debian/zlib@1:1.2.13.dfsg-1?distro=debian-12", nil),
	)
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	var curl, libxml2Old, libxml2New closure
	var successor int64
	rows, err := e.st.Pool.Query(e.ctx, `SELECT f.id, i.version, f.status, f.resolution_kind, f.resolution, f.resolution_detail
		FROM findings f JOIN inventory i ON i.id = f.inventory_id WHERE f.asset_id = $1 AND f.key IN ('CVE-2024-0002', 'CVE-2024-0003')
		  AND split_part(split_part(i.purl, '@', 1), '/', 3) IN ('curl', 'libxml2')`, e.host)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var version string
		var x closure
		if err := rows.Scan(&id, &version, &x.status, &x.kind, &x.resolution, &x.detail); err != nil {
			t.Fatal(err)
		}
		switch version {
		case "7.88.1-10+deb12u5":
			curl = x
		case "2.9.14+dfsg-1.3~deb12u1":
			libxml2Old = x
		case "2.9.14+dfsg-1.3~deb12u1+b1":
			libxml2New, successor = x, id
		}
	}
	rows.Close()
	if curl.status != "resolved" || curl.kind != store.ResolutionRemediated || curl.resolution != "upgraded to 7.88.1-10+deb12u6" {
		t.Errorf("upgraded curl: %+v", curl)
	}
	if libxml2New.status != "open" || successor == 0 {
		t.Fatalf("libxml2 on the new build: %+v", libxml2New)
	}
	if libxml2Old.status != "resolved" || libxml2Old.kind != store.ResolutionSuperseded ||
		libxml2Old.detail["successor"] != float64(successor) {
		t.Errorf("libxml2 upgraded but still affected: %+v (successor %d)", libxml2Old, successor)
	}

	// The matcher's history says why too.
	var ev json.RawMessage
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT e.detail FROM finding_events e JOIN findings f ON f.id = e.finding_id
		WHERE f.key = 'CVE-2024-0001' AND e.action = 'resolved'`).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	var evd map[string]any
	if err := json.Unmarshal(ev, &evd); err != nil || evd["resolution_kind"] != store.ResolutionAdvisoryWithdrawn || evd["source"] != "Debian" {
		t.Errorf("resolved event detail = %s", ev)
	}

	// Outcomes count curl only: the withdrawn and changed advisories and
	// the still-affected upgrade are listed apart, outside the SLA.
	now := time.Now()
	r, err := e.st.OutcomesReport(e.ctx, now.Add(-time.Hour), now.Add(time.Minute), map[string]int{"P1": 3, "P2": 14, "P3": 45, "P4": 90})
	if err != nil {
		t.Fatal(err)
	}
	var slaResolved int64
	for _, s := range r.SLA {
		slaResolved += s.Resolved
	}
	if r.Resolved != 1 || r.Remediated != 1 || slaResolved != 1 || r.NotRemediation.Total != 3 ||
		r.NotRemediation.ByKind[store.ResolutionAdvisoryWithdrawn] != 1 || r.NotRemediation.ByKind[store.ResolutionAdvisoryChanged] != 1 ||
		r.NotRemediation.ByKind[store.ResolutionSuperseded] != 1 {
		t.Errorf("outcomes: resolved %d, remediated %d, in SLA %d, not remediation %+v", r.Resolved, r.Remediated, slaResolved, r.NotRemediation)
	}

	// The issue list can show the findings closed without remediation.
	list, total, err := e.st.ListFindings(e.ctx, store.FindingFilter{Status: "resolved",
		ResolutionKind: []string{store.ResolutionAdvisoryWithdrawn, store.ResolutionAdvisoryChanged}})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("resolved by advisory changes = %d %v", total, err)
	}
	for _, f := range list {
		if f.ResolutionKind != store.ResolutionAdvisoryWithdrawn && f.ResolutionKind != store.ResolutionAdvisoryChanged {
			t.Errorf("listed %+v", f)
		}
	}
}

// A withdrawn advisory that comes back reopens the finding, which is open
// again with no resolution kind.
func TestReopenedFindingClearsItsKind(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	recs := baseRecords
	recs.opensslWithdrawn, recs.modified = true, "2024-03-02T00:00:00Z"
	e.evaluate(e.sync(recs))
	recs.opensslWithdrawn, recs.modified = false, "2024-03-03T00:00:00Z"
	e.evaluate(e.sync(recs))
	if o := e.closures()["CVE-2024-0001 openssl"]; o.status != "open" || o.kind != "" || o.resolution != "" || len(o.detail) != 0 {
		t.Errorf("reopened = %+v", o)
	}
	var kind string
	if err := e.st.Pool.QueryRow(e.ctx, `SELECT e.detail->>'resolution_kind' FROM finding_events e JOIN findings f ON f.id = e.finding_id
		WHERE f.key = 'CVE-2024-0001' AND e.action = 'reopened'`).Scan(&kind); err != nil || kind != store.ResolutionAdvisoryWithdrawn {
		t.Errorf("reopened event kind = %q %v", kind, err)
	}
}

// A package found to be a vendor's build (here by a newer lifecycle overlay)
// is no longer matched against the distribution's advisories: its open
// vulnerability finding closes as not evaluated, which the outcomes report
// counts as a coverage change, not remediation.
func TestVendorBuildClosesAsNotEvaluated(t *testing.T) {
	e := newChangeEnv(t)
	e.evaluate(e.sync(baseRecords))
	if c := e.closures()["CVE-2024-0002 curl"]; c.status != "open" {
		t.Fatalf("curl before the overlay: %+v", c)
	}

	ov, err := eoloverlay.Parse([]byte(`{"schema":1,"version":"test.1","namespace_families":[],"untracked":[],
	 "products":[{"product":"curl","purls":["pkg:deb/*/curl"],
	   "vendor_builds":[{"repository":"Example's repository","version":"^7\\.88\\.1-10\\+deb12u5$"}],
	   "sources":["https://example.org/Packages.gz"],"verified":"2026-10-28"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	e.ev.Overlay = ov
	if _, err := e.ev.Evaluate(e.ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	c := e.closures()["CVE-2024-0002 curl"]
	if c.status != "resolved" || c.kind != store.ResolutionNotEvaluated ||
		!strings.HasPrefix(c.resolution, "no longer evaluated: built by Example's repository") ||
		!strings.Contains(c.detail["reason"].(string), "Example's repository") {
		t.Errorf("vendor-built curl: %+v", c)
	}
	if o := e.closures()["CVE-2024-0001 openssl"]; o.status != "open" {
		t.Errorf("openssl is the distribution's own package: %+v", o)
	}

	now := time.Now()
	r, err := e.st.OutcomesReport(e.ctx, now.Add(-time.Hour), now.Add(time.Minute), map[string]int{"P1": 3, "P2": 14, "P3": 45, "P4": 90})
	if err != nil {
		t.Fatal(err)
	}
	var coverage int64
	for _, cs := range r.Causes {
		if cs.Kind == store.ResolutionNotEvaluated {
			if cs.Evidence != "coverage" || cs.Remediation {
				t.Errorf("not evaluated cause: %+v", cs)
			}
			coverage += cs.Count
		}
	}
	if coverage != 1 || r.Remediated != 0 || r.Resolved != 0 || r.NotRemediation.ByKind[store.ResolutionNotEvaluated] != 1 {
		t.Errorf("outcomes: coverage %d, remediated %d, resolved %d, not remediation %+v (causes %+v)",
			coverage, r.Remediated, r.Resolved, r.NotRemediation, r.Causes)
	}
}
