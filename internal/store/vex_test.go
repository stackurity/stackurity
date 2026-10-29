package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/vex"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

// ingestImage reports an image asset with a digest, as the image scanner
// does.
func ingestImage(t *testing.T, s *store.Store, ctx context.Context, ref, digest string, purls ...string) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "image-scanner", Version: "1", Method: "scanner"},
		model.AssetRef{Kind: model.AssetImage, Name: ref, Identifiers: []model.Identifier{{Scheme: "image-ref", Value: ref}},
			Attributes: map[string]string{"image": ref, "digest": digest}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

func readVEX(t *testing.T, doc string) *vex.Document {
	t.Helper()
	d, err := vex.Read([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// openVEX is a one-statement OpenVEX document.
func openVEX(ts time.Time, vuln, status, extra string, products string) string {
	return fmt.Sprintf(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:test:%d","author":"Vendor","timestamp":%q,"statements":[
		{"vulnerability":{"name":%q},"products":[%s],"status":%q%s}]}`, ts.UnixNano(), ts.Format(time.RFC3339Nano), vuln, products, status, extra)
}

func imageProduct(digest string, subs ...string) string {
	var ss []string
	for _, s := range subs {
		ss = append(ss, fmt.Sprintf(`{"@id":%q}`, s))
	}
	return fmt.Sprintf(`{"@id":%q,"subcomponents":[%s]}`, vex.ImagePurl("registry.example.com/shop/api:1", digest), strings.Join(ss, ","))
}

const notAffected = `,"justification":"vulnerable_code_not_in_execute_path","impact_statement":"TLS is terminated by the proxy"`

func importVEX(t *testing.T, s *store.Store, ctx context.Context, doc string, auto bool, scope ...int64) *store.VEXImportResult {
	t.Helper()
	in := store.VEXImport{Doc: readVEX(t, doc), Filename: "vendor.vex.json", SHA256: strings.Repeat("0", 64), Size: len(doc),
		Signature: "none", SourceName: "Vendor", AutoApply: auto}
	if len(scope) > 0 {
		in.ScopeAssets = scope
	}
	res, err := s.ImportVEX(ctx, in, user)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func pendingVEXRequest(t *testing.T, s *store.Store, ctx context.Context) store.IgnoreRequest {
	t.Helper()
	rs, _, err := s.ListIgnoreRequests(ctx, store.IgnoreRequestFilter{Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.VEXStatementID != nil {
			return r
		}
	}
	t.Fatalf("no pending VEX request in %+v", rs)
	return store.IgnoreRequest{}
}

func activeRules(t *testing.T, s *store.Store, ctx context.Context) []store.IgnoreRule {
	t.Helper()
	rs, _, err := s.ListIgnoreRules(ctx, false, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// An imported not_affected statement never suppresses anything by itself:
// it waits in the approval inbox, and an approval makes an ignore rule
// pinned to the matched version and image digest.
func TestVEXNotAffectedWaitsForApproval(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11?distro=debian-12", "pkg:npm/lodash@4.17.20")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-2024-0001": "openssl", "CVE-2024-0002": "lodash"})
	f := one(t, s, ctx, img, "CVE-2024-0001")

	res := importVEX(t, s, ctx, openVEX(time.Now().Add(-time.Hour), "CVE-2024-0001", "not_affected", notAffected,
		imageProduct(digestA, "pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12")), false)
	if res.Matched != 1 || res.Pending != 1 || res.AutoApproved != 0 || res.Ignored != 0 || len(res.Problems) != 0 {
		t.Fatalf("import %+v", res)
	}
	if got := one(t, s, ctx, img, "CVE-2024-0001"); got.State != "new" || got.ExceptionID != nil {
		t.Fatalf("finding suppressed before approval: %+v", got)
	}
	if v := one(t, s, ctx, img, "CVE-2024-0001").VEX; v == nil || v.Status != vex.StatusNotAffected || v.RequestStatus != "pending" ||
		v.Applied || v.Justification != vex.JustVulnerableCodeNotInExecutePath || v.Source != "Vendor" {
		t.Fatalf("finding VEX before approval: %+v", v)
	}
	if v := one(t, s, ctx, img, "CVE-2024-0002").VEX; v != nil {
		t.Errorf("lodash has VEX %+v", v)
	}
	req := pendingVEXRequest(t, s, ctx)
	if req.Reason != store.ReasonMitigated || req.Scope != "asset" || req.Expiry != "never" || len(req.FindingIDs) != 1 ||
		req.FindingIDs[0] != f.ID || req.VEX == nil || req.VEX.Filename != "vendor.vex.json" || req.VEX.Matches != 1 ||
		!strings.Contains(req.Note, "TLS is terminated") || req.AssetID == nil || *req.AssetID != img {
		t.Fatalf("request %+v vex %+v", req, req.VEX)
	}

	approved, err := s.DecideIgnoreRequest(ctx, req.ID, true, "checked the proxy config", 0, user)
	if err != nil || approved.Applied != 1 {
		t.Fatalf("approve: %+v %v", approved, err)
	}
	got := one(t, s, ctx, img, "CVE-2024-0001")
	if got.State != "risk_accepted" || got.IgnoreReason != store.ReasonMitigated || got.VEX == nil || !got.VEX.Applied ||
		got.VEX.RequestStatus != "approved" || got.SuppressedUntil != nil {
		t.Fatalf("after approval: %+v vex %+v", got, got.VEX)
	}
	rules := activeRules(t, s, ctx)
	if len(rules) != 1 || rules[0].Version != "3.0.11" || rules[0].Digest != digestA || rules[0].VEXStatementID == nil ||
		rules[0].AssetID == nil || *rules[0].AssetID != img || rules[0].RequestID == nil || *rules[0].RequestID != req.ID {
		t.Fatalf("rules %+v", rules)
	}
	// Approving twice is refused.
	if _, err := s.DecideIgnoreRequest(ctx, req.ID, true, "", 0, user); err == nil {
		t.Error("a decided request was decided again")
	}
}

// When the component is upgraded the statement stops applying: the new
// version's finding is not covered, and the rule ends by itself.
func TestVEXStopsAfterUpgrade(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-2024-0001": "openssl"})
	importVEX(t, s, ctx, openVEX(time.Now(), "CVE-2024-0001", "not_affected", notAffected, imageProduct(digestA, "pkg:deb/debian/openssl@3.0.11")), true)
	if f := one(t, s, ctx, img, "CVE-2024-0001"); f.State != "risk_accepted" {
		t.Fatalf("auto-applied: %+v", f)
	}
	// Upgraded, still vulnerable, same image digest.
	ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.12")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-2024-0001": "openssl"})
	if _, err := s.ApplyExceptions(ctx); err != nil {
		t.Fatal(err)
	}
	f := one(t, s, ctx, img, "CVE-2024-0001")
	if f.Version != "3.0.12" || f.State != "new" || f.VEX != nil {
		t.Fatalf("upgraded finding: version %s state %s vex %+v", f.Version, f.State, f.VEX)
	}
	n, err := s.EndStaleVEXRules(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ended %d, %v", n, err)
	}
	if rs := activeRules(t, s, ctx); len(rs) != 0 {
		t.Errorf("rules still active: %+v", rs)
	}
	all, _, _ := s.ListIgnoreRules(ctx, true, store.Page{})
	if len(all) != 1 || all[0].EndedReason != "no_longer_matches" {
		t.Errorf("ended rule %+v", all)
	}
	if n, _ := s.EndStaleVEXRules(ctx); n != 0 {
		t.Errorf("ended %d more", n)
	}
}

// A new image (another digest) with the same package version: the
// statement was about the old image, so the finding comes back.
func TestVEXStopsOnANewImageDigest(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-2024-0001": "openssl"})
	importVEX(t, s, ctx, openVEX(time.Now(), "CVE-2024-0001", "not_affected", notAffected, imageProduct(digestA, "pkg:deb/debian/openssl@3.0.11")), true)
	ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestB, "pkg:deb/debian/openssl@3.0.11")
	if n, err := s.EndStaleVEXRules(ctx); err != nil || n != 1 {
		t.Fatalf("ended %d, %v", n, err)
	}
	f := one(t, s, ctx, img, "CVE-2024-0001")
	if f.State != "new" || f.VEX != nil {
		t.Fatalf("after a new digest: state %s vex %+v", f.State, f.VEX)
	}
	if a := actions(t, s, ctx, f.ID); !has(a, "reopen") {
		t.Errorf("history %v has no reopen", a)
	}
}

func TestVEXMatchingEdgeCases(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.5",
		"pkg:pypi/Foo_Bar@1.0")
	// Two copies of minimist on one host: a version-less name is ambiguous there.
	host := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.5", "pkg:npm/minimist@1.2.8",
		"pkg:npm/zlib@1.3", "pkg:pypi/zlib@1.3")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-1": "lodash", "CVE-2": "minimist", "CVE-5": "Foo_Bar"})
	syncOpen(t, s, ctx, host, map[string]string{"CVE-1": "lodash", "CVE-2": "minimist", "CVE-3": "zlib"})
	ts := time.Now()
	cases := []struct {
		name, doc string
		matched   int
		problem   string
	}{
		{"versioned purl matches every asset", openVEX(ts, "CVE-1", "affected", "", `{"@id":"pkg:npm/lodash@4.17.20"}`), 1, ""},
		{"purl without a version", openVEX(ts, "CVE-1", "affected", "", `{"@id":"pkg:npm/lodash"}`), 0, "no version"},
		{"another version", openVEX(ts, "CVE-1", "affected", "", `{"@id":"pkg:npm/lodash@4.17.21"}`), 0, "no asset in scope"},
		{"unknown digest", openVEX(ts, "CVE-1", "affected", "", imageProduct(digestB, "pkg:npm/lodash@4.17.20")), 0, "digest"},
		{"version-less subcomponent of a pinned image", openVEX(ts, "CVE-2", "affected", "", imageProduct(digestA, "pkg:npm/minimist")), 1, ""},
		{"image without subcomponents: every finding for the vulnerability", openVEX(ts, "CVE-2", "fixed", "", imageProduct(digestA)), 1, ""},
		{"CPE fits two packages", openVEX(ts, "CVE-3", "affected", "", `{"@id":"cpe:2.3:a:zlib:zlib:1.3:*:*:*:*:*:*:*"}`), 0, "2 different packages"},
		{"CPE without a version", openVEX(ts, "CVE-3", "affected", "", `{"@id":"cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"}`), 0, "no version"},
		{"CPE matching one package", openVEX(ts, "CVE-2", "affected", "", `{"@id":"cpe:2.3:a:substack:minimist:1.2.8:*:*:*:*:*:*:*"}`), 1, ""},
		{"distro qualifier disagrees", openVEX(ts, "CVE-1", "affected", "", `{"@id":"pkg:npm/lodash@4.17.20?distro=alpine-3.19"}`), 1, ""},
		{"PyPI names compare normalised", openVEX(ts, "CVE-5", "affected", "", `{"@id":"pkg:pypi/foo-bar@1.0"}`), 1, ""},
		{"tag instead of digest", openVEX(ts, "CVE-1", "affected", "", `{"@id":"pkg:oci/api?tag=1"}`), 0, "digest"},
		{"not an identifier", openVEX(ts, "CVE-1", "affected", "", `{"@id":"lodash"}`), 0, "not a package URL"},
	}
	for _, c := range cases {
		res := importVEX(t, s, ctx, c.doc, false)
		if res.Matched != c.matched {
			t.Errorf("%s: matched %d, want %d (%+v)", c.name, res.Matched, c.matched, res.Problems)
		}
		if c.problem != "" && (len(res.Problems) == 0 || !strings.Contains(res.Problems[0].Reason, c.problem)) {
			t.Errorf("%s: problems %+v, want %q", c.name, res.Problems, c.problem)
		}
	}
	// The version-less subcomponent on the host, which has two versions.
	host2 := ingestImage(t, s, ctx, "registry.example.com/shop/worker:1", digestB, "pkg:npm/minimist@1.2.5", "pkg:npm/minimist@1.2.8")
	syncOpen(t, s, ctx, host2, map[string]string{"CVE-2": "minimist"})
	res := importVEX(t, s, ctx, openVEX(ts, "CVE-2", "affected", "", imageProduct(digestB, "pkg:npm/minimist")), false)
	if res.Matched != 0 || len(res.Problems) != 1 || res.Problems[0].Kind != "ambiguous" {
		t.Errorf("two versions in one image: %+v", res)
	}
	// Scoped to one asset, a versioned purl matches only there.
	res = importVEX(t, s, ctx, openVEX(ts, "CVE-1", "not_affected", notAffected, `{"@id":"pkg:npm/lodash@4.17.20"}`), false, host)
	req := pendingVEXRequest(t, s, ctx)
	if res.Matched != 1 || req.VEX.Assets != 1 || req.AssetID == nil || *req.AssetID != host {
		t.Errorf("scoped import: %+v request %+v", res, req.VEX)
	}
	// An invalid statement is recorded, not matched.
	res = importVEX(t, s, ctx, openVEX(ts, "CVE-1", "not_affected", "", `{"@id":"pkg:npm/lodash@4.17.20"}`), false)
	if res.Matched != 0 || len(res.Problems) != 1 || res.Problems[0].Kind != "invalid" {
		t.Errorf("invalid statement: %+v", res)
	}
}

// A CycloneDX VEX about a product with no identifier of its own (the CISA
// use case) matches only when the import is scoped to one asset.
func TestVEXCycloneDXSubject(t *testing.T) {
	ctx, s := loopStore(t)
	app := ingestHost(t, s, ctx, "abc", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	syncOpen(t, s, ctx, app, map[string]string{"CVE-2021-44228": "log4j-core"})
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,
		"metadata":{"component":{"name":"ABC","version":"4.2","type":"application","bom-ref":"abc"}},
		"components":[{"bom-ref":"log4j","type":"library","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
		"vulnerabilities":[{"id":"CVE-2021-44228","analysis":{"state":"not_affected","justification":"code_not_present","detail":"JndiLookup removed"},
		"affects":[{"ref":"log4j"}]}]}`
	res := importVEX(t, s, ctx, doc, false)
	if res.Matched != 0 || len(res.Problems) != 1 || !strings.Contains(res.Problems[0].Reason, "not an asset here") {
		t.Fatalf("unscoped: %+v", res)
	}
	res = importVEX(t, s, ctx, doc, false, app)
	if res.Matched != 1 || res.Pending != 1 {
		t.Fatalf("scoped: %+v", res)
	}
	if r := pendingVEXRequest(t, s, ctx); r.Reason != store.ReasonFalsePositive {
		t.Errorf("code_not_present is a false positive: %+v", r)
	}
}

// The latest statement wins: a newer affected statement ends the ignore
// rule an approved not_affected one made; an older one does not.
func TestVEXNewerAffectedEndsRule(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-2024-0001": "openssl"})
	product := imageProduct(digestA, "pkg:deb/debian/openssl@3.0.11")
	// Dated in the future: counted as the time of import.
	importVEX(t, s, ctx, openVEX(time.Now().AddDate(10, 0, 0), "CVE-2024-0001", "not_affected", notAffected, product), true)
	if f := one(t, s, ctx, img, "CVE-2024-0001"); f.State != "risk_accepted" {
		t.Fatalf("not applied: %+v", f)
	}
	res := importVEX(t, s, ctx, openVEX(time.Now().AddDate(-1, 0, 0), "CVE-2024-0001", "affected", `,"action_statement":"upgrade"`, product), false)
	if res.Ended != 0 {
		t.Fatalf("an older statement ended the rule: %+v", res)
	}
	if f := one(t, s, ctx, img, "CVE-2024-0001"); f.State != "risk_accepted" || f.VEX == nil || f.VEX.Status != vex.StatusNotAffected {
		t.Fatalf("after an older affected statement: %+v %+v", f, f.VEX)
	}
	res = importVEX(t, s, ctx, openVEX(time.Now(), "CVE-2024-0001", "affected", `,"action_statement":"upgrade to 3.0.12"`, product), false)
	if res.Ended != 1 {
		t.Fatalf("newer affected: %+v", res)
	}
	f := one(t, s, ctx, img, "CVE-2024-0001")
	if f.State != "new" || f.VEX == nil || f.VEX.Status != vex.StatusAffected || f.VEX.ActionStatement != "upgrade to 3.0.12" {
		t.Fatalf("after a newer affected statement: %+v %+v", f, f.VEX)
	}
	// A pending not_affected statement older than the affected one is
	// approved without applying.
	importVEX(t, s, ctx, openVEX(time.Now().Add(-time.Hour), "CVE-2024-0001", "not_affected", notAffected, product), false)
	r, err := s.DecideIgnoreRequest(ctx, pendingVEXRequest(t, s, ctx).ID, true, "", 0, user)
	if err != nil || r.Applied != 0 {
		t.Fatalf("approving a superseded statement: %+v %v", r, err)
	}
	if f := one(t, s, ctx, img, "CVE-2024-0001"); f.State != "new" {
		t.Errorf("superseded statement applied: %+v", f)
	}
}

// A statement named by an alias (GHSA) matches the finding keyed by its CVE.
func TestVEXAliases(t *testing.T) {
	ctx, s := loopStore(t)
	sys := tenant.System(context.Background())
	if _, err := s.Pool.Exec(sys, `INSERT INTO feeds (name, kind) VALUES ('osv:npm', 'vulnerability') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `INSERT INTO advisories (id, feed, group_key, aliases, modified) VALUES
		('GHSA-p6mc-m468-83gw', 'osv:npm', 'CVE-2020-8203', '{CVE-2020-8203}', now())`); err != nil {
		t.Fatal(err)
	}
	host := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncOpen(t, s, ctx, host, map[string]string{"CVE-2020-8203": "lodash"})
	res := importVEX(t, s, ctx, openVEX(time.Now(), "GHSA-P6MC-M468-83GW", "fixed", "", `{"@id":"pkg:npm/lodash@4.17.15"}`), false)
	if res.Matched != 1 {
		t.Fatalf("%+v", res)
	}
	if f := one(t, s, ctx, host, "CVE-2020-8203"); f.VEX == nil || f.VEX.Status != vex.StatusFixed || f.VEX.Vulnerability != "GHSA-p6mc-m468-83gw" {
		t.Errorf("vex %+v", f.VEX)
	}
}

// A declined statement is not shown on the finding and makes no rule.
func TestVEXDeclined(t *testing.T) {
	ctx, s := loopStore(t)
	host := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncOpen(t, s, ctx, host, map[string]string{"CVE-1": "lodash"})
	importVEX(t, s, ctx, openVEX(time.Now(), "CVE-1", "not_affected", notAffected, `{"@id":"pkg:npm/lodash@4.17.15"}`), false)
	if _, err := s.DecideIgnoreRequest(ctx, pendingVEXRequest(t, s, ctx).ID, false, "we do call it", 0, user); err != nil {
		t.Fatal(err)
	}
	if f := one(t, s, ctx, host, "CVE-1"); f.State != "new" || f.VEX != nil {
		t.Errorf("declined: %+v %+v", f, f.VEX)
	}
	if rs := activeRules(t, s, ctx); len(rs) != 0 {
		t.Errorf("rules %+v", rs)
	}
}

// A VEX document naming another workspace's image or packages matches
// nothing there: matching runs under the importer's workspace, and
// row-level security hides everything else.
func TestVEXStaysInItsWorkspace(t *testing.T) {
	ctx, s := loopStore(t)
	wsB, _, err := s.CreateWorkspace(context.Background(), "Beta", "", "beta@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	ctxB := tenant.WithWorkspace(context.Background(), wsB.ID)
	imgB := ingestImage(t, s, ctxB, "registry.example.com/beta/api:1", digestB, "pkg:deb/debian/openssl@3.0.11")
	syncOpen(t, s, ctxB, imgB, map[string]string{"CVE-2024-0001": "openssl"})

	// Workspace A (the default) imports a trusted statement about B's image
	// and B's package, and even scopes it to B's asset id.
	doc := openVEX(time.Now(), "CVE-2024-0001", "not_affected", notAffected,
		imageProduct(digestB, "pkg:deb/debian/openssl@3.0.11")+`,{"@id":"pkg:deb/debian/openssl@3.0.11"}`)
	for _, scope := range [][]int64{nil, {imgB}} {
		res := importVEX(t, s, ctx, doc, true, scope...)
		if res.Matched != 0 || res.AutoApproved != 0 || res.Ignored != 0 {
			t.Fatalf("scope %v: matched across workspaces: %+v", scope, res)
		}
	}
	if f := one(t, s, ctxB, imgB, "CVE-2024-0001"); f.State != "new" || f.VEX != nil {
		t.Fatalf("B's finding changed: %+v %+v", f, f.VEX)
	}
	var n int
	if err := s.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM vex_matches`).Scan(&n); err != nil || n != 0 {
		t.Errorf("vex_matches rows: %d %v", n, err)
	}
	// B sees none of A's documents.
	docs, _, err := s.ListVEXDocuments(ctxB, store.Page{})
	if err != nil || len(docs) != 0 {
		t.Errorf("B sees %d documents: %v", len(docs), err)
	}
}

func TestVEXExport(t *testing.T) {
	ctx, s := loopStore(t)
	img := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:deb/debian/openssl@3.0.11", "pkg:npm/lodash@4.17.20",
		"pkg:npm/minimist@1.2.5")
	syncOpen(t, s, ctx, img, map[string]string{"CVE-1": "openssl", "CVE-2": "lodash", "CVE-3": "minimist"})
	importVEX(t, s, ctx, openVEX(time.Now(), "CVE-1", "not_affected", notAffected, imageProduct(digestA, "pkg:deb/debian/openssl@3.0.11")), true)
	fp := store.FindingAction{Action: "ignore", Note: "we never call merge", Ignore: store.IgnoreSpec{
		Reason: store.ReasonFalsePositive, Scope: store.ScopeAsset, Expiry: store.ExpiryNever}}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, img, "CVE-2").ID, fp, user); err != nil {
		t.Fatal(err)
	}
	importVEX(t, s, ctx, openVEX(time.Now(), "CVE-3", "under_investigation", "", imageProduct(digestA, "pkg:npm/minimist@1.2.5")), false)
	rows, err := s.VEXExport(ctx, img)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	by := map[string]store.VEXExportRow{}
	for _, r := range rows {
		by[r.Key] = r
		if r.Digest != digestA || r.AssetKind != "image" {
			t.Errorf("row %+v", r)
		}
	}
	if r := by["CVE-1"]; r.Status != vex.StatusNotAffected || r.Justification != vex.JustVulnerableCodeNotInExecutePath ||
		r.ImpactStatement != "TLS is terminated by the proxy" || r.FalsePositive {
		t.Errorf("VEX rule %+v", r)
	}
	if r := by["CVE-2"]; r.Status != vex.StatusNotAffected || r.Justification != vex.JustVulnerableCodeNotPresent ||
		r.ImpactStatement != "we never call merge" || !r.FalsePositive || !strings.HasPrefix(r.Purl, "pkg:npm/lodash@4.17.20") {
		t.Errorf("manual false positive %+v", r)
	}
	if r := by["CVE-3"]; r.Status != vex.StatusUnderInvestigation {
		t.Errorf("imported statement %+v", r)
	}
}

func TestVEXSources(t *testing.T) {
	ctx, s := loopStore(t)
	name, on := "Acme", true
	if _, err := s.SaveVEXSource(ctx, 0, store.VEXSourceInput{Name: &name, AutoApply: &on}, user); err == nil {
		t.Fatal("an unpinned source was allowed to apply on its own")
	}
	src, err := s.SaveVEXSource(ctx, 0, store.VEXSourceInput{Name: &name}, user)
	if err != nil || src.AutoApply {
		t.Fatalf("%+v %v", src, err)
	}
	key, fp := "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", strings.Repeat("f", 64)
	src, err = s.SaveVEXSource(ctx, src.ID, store.VEXSourceInput{AutoApply: &on, PublicKey: &key, KeyFingerprint: fp}, user)
	if err != nil || !src.AutoApply || src.KeyFingerprint != fp || !src.Pinned() {
		t.Fatalf("%+v %v", src, err)
	}
	// Removing the only pin of an auto-applying source is refused.
	empty := ""
	if _, err := s.SaveVEXSource(ctx, src.ID, store.VEXSourceInput{PublicKey: &empty}, user); err == nil {
		t.Error("the pin of an auto-applying source was removed")
	}
	if _, err := s.SaveVEXSource(ctx, 0, store.VEXSourceInput{Name: &name}, user); err == nil {
		t.Error("a duplicate name was accepted")
	}
	if err := s.DeleteVEXSource(ctx, src.ID); err != nil {
		t.Fatal(err)
	}
}
