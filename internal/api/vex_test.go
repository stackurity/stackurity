package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/vex"
)

const vexDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// vexEnv is the loop fixture plus an image (by digest) with an openssl
// finding.
type vexEnv struct {
	*loopEnv
	image   int64
	openssl int64 // the finding
}

func newVEXEnv(t *testing.T) *vexEnv {
	l := newLoopEnv(t)
	b := model.NewBatch(model.Collector{ID: "image-scanner", Version: "1", Method: "scanner"},
		model.AssetRef{Kind: model.AssetImage, Name: "registry.example.com/shop/api:1",
			Identifiers: []model.Identifier{{Scheme: "image-ref", Value: "registry.example.com/shop/api:1"}},
			Attributes:  map[string]string{"image": "registry.example.com/shop/api:1", "digest": vexDigest}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/openssl@3.0.11?distro=debian-12", Confidence: model.ConfidenceConfirmed}}
	v := &vexEnv{loopEnv: l, image: l.send(l.collector, b)}
	rows, _, err := l.st.ListInventory(l.ctx, store.InventoryFilter{AssetID: v.image})
	if err != nil || len(rows) != 1 {
		t.Fatalf("inventory %v %v", rows, err)
	}
	if _, _, err := l.st.SyncFindings(l.ctx, []string{"vulnerability"}, []int64{rows[0].ID}, []store.FindingInput{{Kind: "vulnerability",
		Key: "CVE-2024-0001", InventoryID: rows[0].ID, AssetID: v.image, ComponentID: rows[0].ComponentID, Verification: "confirmed",
		Severity: "high", Sources: []string{"GHSA-aaaa-bbbb-cccc"}, Evidence: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	fs, _, err := l.st.ListFindings(l.ctx, store.FindingFilter{AssetID: v.image})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings %v %v", fs, err)
	}
	v.openssl = fs[0].ID
	return v
}

func (v *vexEnv) imageVEX(status, extra string, at time.Time) []byte {
	return []byte(fmt.Sprintf(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:test:%d","author":"Shop vendor","timestamp":%q,
		"statements":[{"vulnerability":{"name":"CVE-2024-0001"},"status":%q%s,
		"products":[{"@id":%q,"subcomponents":[{"@id":"pkg:deb/debian/openssl@3.0.11"}]}]}]}`,
		at.UnixNano(), at.Format(time.RFC3339Nano), status, extra, vex.ImagePurl("registry.example.com/shop/api:1", vexDigest)))
}

const vexNA = `,"justification":"vulnerable_code_not_in_execute_path","impact_statement":"only used by the build"`

// post sends a raw document as s (a session) or with a bearer token.
func (v *vexEnv) post(s *session, token, path string, doc []byte) (int, store.VEXImportResult, string) {
	v.t.Helper()
	var resp *http.Response
	if s != nil {
		resp = s.req("POST", path, bytes.NewReader(doc), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
	} else {
		req, _ := http.NewRequest("POST", v.srv.URL+path, bytes.NewReader(doc))
		req.Header.Set("Authorization", "Bearer "+token)
		var err error
		if resp, err = http.DefaultClient.Do(req); err != nil {
			v.t.Fatal(err)
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var res store.VEXImportResult
	_ = json.Unmarshal(body, &res)
	return resp.StatusCode, res, string(body)
}

func (v *vexEnv) finding(id int64) store.Finding {
	v.t.Helper()
	var out struct{ Finding store.Finding }
	if code := v.admin.do("GET", fmt.Sprintf("/api/v1/findings/%d", id), nil, &out); code != 200 {
		v.t.Fatalf("finding %d: %d", id, code)
	}
	return out.Finding
}

func (v *vexEnv) pendingVEX() store.IgnoreRequest {
	v.t.Helper()
	var list struct{ Items []store.IgnoreRequest }
	v.sec.do("GET", "/api/v1/ignore-requests", nil, &list)
	for _, r := range list.Items {
		if r.VEXStatementID != nil {
			return r
		}
	}
	v.t.Fatalf("no pending VEX request: %+v", list.Items)
	return store.IgnoreRequest{}
}

func vexAudit(t *testing.T, s *session) map[string]json.RawMessage {
	t.Helper()
	var list struct {
		Items []struct {
			Action string          `json:"action"`
			Detail json.RawMessage `json:"detail"`
		}
	}
	if code := s.do("GET", "/api/v1/audit?limit=200", nil, &list); code != 200 {
		t.Fatalf("audit: %d", code)
	}
	out := map[string]json.RawMessage{}
	for _, e := range list.Items {
		if _, ok := out[e.Action]; !ok {
			out[e.Action] = e.Detail
		}
	}
	return out
}

// The approval flow: engineers may import, the import only asks, and only
// an organisation-wide security or admin user approves. The audit log
// names the file, the statement and the approver.
func TestVEXImportNeedsApproval(t *testing.T) {
	v := newVEXEnv(t)
	doc := v.imageVEX("not_affected", vexNA, time.Now())
	if code, _, _ := v.post(v.view, "", "/api/v1/vex/import", doc); code != 403 {
		t.Errorf("viewer import: %d", code)
	}
	if code, _, _ := v.post(nil, v.collector, "/api/v1/vex/import", doc); code != 403 {
		t.Errorf("collector import: %d", code)
	}
	code, res, body := v.post(v.eng, "", "/api/v1/vex/import?filename=shop.vex.json", doc)
	if code != 201 || res.Matched != 1 || res.Pending != 1 || res.AutoApproved != 0 || res.Document.Filename != "shop.vex.json" ||
		len(res.Document.SHA256) != 64 || res.Document.Signature != "none" {
		t.Fatalf("engineer import: %d %s", code, body)
	}
	f := v.finding(v.openssl)
	if f.State != "new" || f.VEX == nil || f.VEX.Status != "not_affected" || f.VEX.RequestStatus != "pending" || f.VEX.Applied {
		t.Fatalf("finding after import: state %s vex %+v", f.State, f.VEX)
	}
	req := v.pendingVEX()
	if req.VEX == nil || req.VEX.Filename != "shop.vex.json" || req.VEX.Vulnerability != "CVE-2024-0001" {
		t.Fatalf("request %+v", req)
	}
	// An engineer cannot decide; nor can the requester approve their own.
	if code := v.eng.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", req.ID), map[string]any{"decision": "approve"}, nil); code != 403 {
		t.Errorf("engineer decision: %d", code)
	}
	if code := v.eng.do("POST", fmt.Sprintf("/api/v1/vex/documents/%d/decision", res.Document.ID), map[string]any{"decision": "approve"}, nil); code != 403 {
		t.Errorf("engineer document decision: %d", code)
	}
	var out struct{ Decided, Applied int }
	if code := v.sec.do("POST", fmt.Sprintf("/api/v1/vex/documents/%d/decision", res.Document.ID),
		map[string]any{"decision": "approve", "note": "checked"}, &out); code != 200 || out.Decided != 1 || out.Applied != 1 {
		t.Fatalf("security approves the document: %d %+v", code, out)
	}
	f = v.finding(v.openssl)
	if f.State != "risk_accepted" || f.IgnoreReason != "mitigated" || f.VEX == nil || !f.VEX.Applied {
		t.Fatalf("after approval: %+v %+v", f, f.VEX)
	}
	a := vexAudit(t, v.admin)
	for action, want := range map[string][]string{
		"vex.import":             {`"sha256"`, `"shop.vex.json"`, `"Shop vendor"`, `"pending":1`},
		"ignore_request.approve": {`"vex_statement_id"`, `"shop.vex.json"`, `"CVE-2024-0001"`, `"vulnerable_code_not_in_execute_path"`},
	} {
		d, ok := a[action]
		if !ok {
			t.Errorf("no %s in the audit log", action)
			continue
		}
		for _, w := range want {
			if !strings.Contains(string(d), w) {
				t.Errorf("%s detail %s lacks %s", action, d, w)
			}
		}
	}
	// The statement list says what matched.
	var sts struct{ Items []store.VEXStatement }
	if code := v.sec.do("GET", fmt.Sprintf("/api/v1/vex/documents/%d/statements", res.Document.ID), nil, &sts); code != 200 ||
		len(sts.Items) != 1 || sts.Items[0].Matches != 1 || sts.Items[0].RequestStatus != "approved" {
		t.Errorf("statements: %d %+v", code, sts.Items)
	}
}

func pubPEM(k *ecdsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signVEX wraps doc in an in-toto attestation signed with key (as cosign
// attest does).
func signVEX(key *ecdsa.PrivateKey, doc []byte) []byte {
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://openvex.dev/ns/v0.2.0",
		"subject":   []any{map[string]any{"name": "api", "digest": map[string]string{"sha256": strings.TrimPrefix(vexDigest, "sha256:")}}},
		"predicate": json.RawMessage(doc)})
	h := sha256.Sum256(vex.PAE("application/vnd.in-toto+json", st))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(st),
		"signatures": []any{map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)}}})
	return env
}

// A source may apply on its own only when pinned to a key or a token, and
// only an upload that meets every pin does.
func TestVEXTrustedSources(t *testing.T) {
	v := newVEXEnv(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if code := v.admin.do("POST", "/api/v1/vex/sources", map[string]any{"name": "Shop", "auto_apply": true}, nil); code != 400 {
		t.Errorf("unpinned auto-apply source: %d", code)
	}
	if code := v.sec.do("POST", "/api/v1/vex/sources", map[string]any{"name": "Shop"}, nil); code != 403 {
		t.Errorf("security creates a source: %d", code)
	}
	if code := v.admin.do("POST", "/api/v1/vex/sources", map[string]any{"name": "Shop", "public_key": "garbage"}, nil); code != 400 {
		t.Errorf("bad key: %d", code)
	}
	var src store.VEXSource
	if code := v.admin.do("POST", "/api/v1/vex/sources", map[string]any{"name": "Shop", "auto_apply": true, "public_key": pubPEM(key)}, &src); code != 201 ||
		src.KeyFingerprint == "" || !src.AutoApply {
		t.Fatalf("keyed source: %d %+v", code, src)
	}
	path := fmt.Sprintf("/api/v1/vex/import?source_id=%d", src.ID)
	doc := v.imageVEX("not_affected", vexNA, time.Now())
	// The plain document, without the signature: refused.
	if code, _, body := v.post(v.eng, "", path, doc); code != 400 || !strings.Contains(body, "signed") {
		t.Errorf("unsigned upload to a keyed source: %d %s", code, body)
	}
	// Signed with another key: refused.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if code, _, body := v.post(v.eng, "", path, signVEX(other, doc)); code != 400 || !strings.Contains(body, "does not verify") {
		t.Errorf("wrong key: %d %s", code, body)
	}
	// Tampered after signing: refused.
	signed := signVEX(key, doc)
	var env map[string]any
	_ = json.Unmarshal(signed, &env)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	env["payload"] = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte("only used by the build"), []byte("never used, trust me"), 1))
	tampered, _ := json.Marshal(env)
	if code, _, _ := v.post(v.eng, "", path, tampered); code != 400 {
		t.Errorf("tampered: %d", code)
	}
	if f := v.finding(v.openssl); f.State != "new" {
		t.Fatalf("refused uploads changed the finding: %+v", f)
	}
	// Signed with the source's key: applied on import.
	code, res, body := v.post(v.eng, "", path, signed)
	if code != 201 || res.AutoApproved != 1 || res.Ignored != 1 || res.Pending != 0 || res.Document.Signature != "verified" ||
		res.Document.KeyFingerprint != src.KeyFingerprint || !res.Document.AutoApplied {
		t.Fatalf("signed upload: %d %s", code, body)
	}
	if f := v.finding(v.openssl); f.State != "risk_accepted" || f.VEX == nil || !f.VEX.Applied {
		t.Fatalf("auto-applied: %+v %+v", f, f.VEX)
	}
	if d, ok := vexAudit(t, v.admin)["ignore_request.approve"]; !ok || !strings.Contains(string(d), `"auto_apply":true`) {
		t.Errorf("auto-approval audit: %s", d)
	}

	// A source pinned to a token: only that token's uploads apply.
	var tok struct {
		Token  struct{ ID int64 }
		Secret string `json:"secret"`
	}
	if code := v.admin.do("POST", "/api/v1/tokens", map[string]string{"name": "ci", "role": "engineer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	var tsrc store.VEXSource
	if code := v.admin.do("POST", "/api/v1/vex/sources", map[string]any{"name": "CI", "auto_apply": true, "token_id": tok.Token.ID}, &tsrc); code != 201 {
		t.Fatalf("token source: %d", code)
	}
	host := v.findings["CVE-L1"]
	lodash := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:t","author":"CI","statements":[{"vulnerability":{"name":"CVE-L1"},
		"products":[{"@id":"pkg:npm/lodash@4.17.15"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}`)
	tpath := fmt.Sprintf("/api/v1/vex/import?source_id=%d", tsrc.ID)
	if code, res, _ := v.post(v.admin, "", tpath, lodash); code != 201 || res.AutoApproved != 0 || res.Pending != 1 {
		t.Errorf("another uploader for a token source: %d %+v", code, res)
	}
	if code, res, body := v.post(nil, tok.Secret, tpath, lodash); code != 201 || res.AutoApproved != 1 {
		t.Errorf("the source's token: %d %s", code, body)
	}
	if f := v.finding(host); f.State != "risk_accepted" || f.IgnoreReason != "false_positive" {
		t.Errorf("token source applied: %+v", f)
	}
}

// Export our own decisions, then import the export: it matches the same
// component versions and, approved, ignores the same findings again.
func TestVEXExportImportRoundTrip(t *testing.T) {
	for _, format := range []string{"openvex", "cyclonedx"} {
		t.Run(format, func(t *testing.T) {
			v := newVEXEnv(t)
			if code := v.admin.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", v.openssl), map[string]any{"action": "ignore",
				"reason": "false_positive", "note": "openssl is not in the runtime layer", "scope": "asset", "expiry": "never"}, nil); code != 200 {
				t.Fatalf("ignore: %d", code)
			}
			resp := v.view.req("GET", fmt.Sprintf("/api/v1/vex/export?format=%s&asset_id=%d", format, v.image), nil, nil)
			doc, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), fmt.Sprintf("asset-%d", v.image)) {
				t.Fatalf("export: %d %s", resp.StatusCode, doc)
			}
			parsed, err := vex.Read(doc)
			if err != nil || len(parsed.Statements) != 1 {
				t.Fatalf("export does not read back: %v\n%s", err, doc)
			}
			st := parsed.Statements[0]
			if st.Vulnerability != "CVE-2024-0001" || st.Status != "not_affected" || vex.IgnoreReason(st) != "false_positive" ||
				!strings.Contains(st.ImpactStatement+st.StatusNotes, "runtime layer") || st.Products[0].Digest != vexDigest ||
				len(st.Aliases) != 1 || st.Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
				t.Fatalf("exported statement %+v\n%s", st, doc)
			}
			// End the rule, and bring the decision back from the file.
			var rules struct{ Items []store.IgnoreRule }
			v.admin.do("GET", "/api/v1/ignore-rules", nil, &rules)
			for _, r := range rules.Items {
				v.admin.do("DELETE", fmt.Sprintf("/api/v1/ignore-rules/%d", r.ID), nil, nil)
			}
			if f := v.finding(v.openssl); f.State != "new" {
				t.Fatalf("rule not ended: %+v", f)
			}
			code, res, body := v.post(v.admin, "", "/api/v1/vex/import", doc)
			if code != 201 || res.Matched != 1 || res.Pending != 1 {
				t.Fatalf("import the export: %d %s", code, body)
			}
			req := v.pendingVEX()
			if req.Reason != "false_positive" {
				t.Errorf("reason %s", req.Reason)
			}
			if code := v.sec.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", req.ID), map[string]any{"decision": "approve"}, nil); code != 200 {
				t.Fatalf("approve: %d", code)
			}
			if f := v.finding(v.openssl); f.State != "risk_accepted" || f.IgnoreReason != "false_positive" || f.VEX == nil || !f.VEX.Applied {
				t.Errorf("after the round trip: %+v %+v", f, f.VEX)
			}
		})
	}
}

// Real-world documents go through the API: an SBOM with VEX embedded,
// uploaded as an SBOM, asks for approval for the asset it created.
func TestVEXEmbeddedInSBOM(t *testing.T) {
	v := newVEXEnv(t)
	bom, err := os.ReadFile("../vex/testdata/cdx-bom-embedded.json")
	if err != nil {
		t.Fatal(err)
	}
	resp := v.admin.req("POST", "/api/v1/sbom/import", bytes.NewReader(bom), map[string]string{"X-Stackurity-CSRF": "1"})
	var res store.IngestResult
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != 201 || res.VEX == nil || res.VEX.Matched != 1 || res.VEX.Pending != 1 || res.VEX.Document.Via != "sbom" ||
		res.VEX.Document.ScopeAssetID == nil || *res.VEX.Document.ScopeAssetID != res.AssetID {
		t.Fatalf("sbom import: %d %+v %+v", resp.StatusCode, res, res.VEX)
	}
	// A collector token's SBOM keeps its VEX out.
	req, _ := http.NewRequest("POST", v.srv.URL+"/api/v1/sbom/import?asset_name=other", bytes.NewReader(bom))
	req.Header.Set("Authorization", "Bearer "+v.collector)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res2 store.IngestResult
	_ = json.NewDecoder(r2.Body).Decode(&res2)
	r2.Body.Close()
	if r2.StatusCode != 201 || res2.VEX != nil || !strings.Contains(res2.VEXNote, "collector") {
		t.Errorf("collector sbom: %d %+v", r2.StatusCode, res2)
	}
	// The CycloneDX VEX referring to that BOM by BOM-Link matches too.
	link, _ := os.ReadFile("../vex/testdata/cdx-vex-bomlink.json")
	link = bytes.ReplaceAll(link, []byte("3e671687-395b-41f5-a30f-a58921a69b79"), []byte("5f0f0da9-c03d-47d8-b38d-009e6df67094"))
	if code, out, body := v.post(v.admin, "", "/api/v1/vex/import", link); code != 201 || out.Matched != 1 {
		t.Errorf("BOM-Link VEX: %d %s", code, body)
	}
}

func TestVEXImportLimits(t *testing.T) {
	v := newVEXEnv(t)
	big := bytes.Repeat([]byte(" "), vex.MaxDocumentSize+10)
	if code, _, body := v.post(v.admin, "", "/api/v1/vex/import", big); code != 400 || !strings.Contains(body, "larger") {
		t.Errorf("oversized: %d %s", code, body)
	}
	if code, _, _ := v.post(v.admin, "", "/api/v1/vex/import", []byte(`{"hello":"world"}`)); code != 400 {
		t.Errorf("not VEX: %d", code)
	}
	if code, _, _ := v.post(v.admin, "", "/api/v1/vex/import", nil); code != 400 {
		t.Errorf("empty: %d", code)
	}
	if code, _, _ := v.post(v.admin, "", "/api/v1/vex/import?source_id=999", v.imageVEX("fixed", "", time.Now())); code != 404 {
		t.Errorf("unknown source: %d", code)
	}
	if code, _, _ := v.post(v.admin, "", "/api/v1/vex/import?asset_id=999999", v.imageVEX("fixed", "", time.Now())); code != 404 {
		t.Errorf("unknown asset: %d", code)
	}
	if code := v.view.do("GET", "/api/v1/vex/export?format=csaf", nil, nil); code != 400 {
		t.Errorf("unknown export format: %d", code)
	}
}
