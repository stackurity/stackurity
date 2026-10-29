package vex

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustRead(t *testing.T, name string) *Document {
	t.Helper()
	d, err := Read(fixture(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}

// Every real-world sample parses, in the format it is in.
func TestRealWorldSamplesParse(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	if len(files) < 10 {
		t.Fatalf("only %d fixtures", len(files))
	}
	for _, f := range files {
		name := filepath.Base(f)
		d, err := Read(fixture(t, name))
		if name == "cdx-bom.json" {
			// An SBOM with no vulnerabilities: a document with nothing to say.
			if err != nil || len(d.Statements) != 0 {
				t.Errorf("%s: %v, %d statements", name, err, len(d.Statements))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(d.Statements) == 0 {
			t.Errorf("%s: no statements", name)
		}
		want := FormatOpenVEX
		if strings.HasPrefix(name, "cdx-") {
			want = FormatCycloneDX
		}
		if d.Format != want {
			t.Errorf("%s: format %s, want %s", name, d.Format, want)
		}
	}
}

func TestOpenVEXImageDigest(t *testing.T) {
	d := mustRead(t, "openvex-nginx-history.json")
	if d.Author != "The OpenVEX Project" || d.Timestamp == nil || d.ID == "" {
		t.Errorf("document %+v", d)
	}
	st := d.Statements[0]
	if st.Vulnerability != "CVE-2023-27103" || st.Status != StatusNotAffected || st.Justification != JustComponentNotPresent || st.Problem != "" {
		t.Errorf("statement %+v", st)
	}
	if len(st.Aliases) != 1 || st.Aliases[0] != "SNYK-DEBIAN12-LIBDE265-3361563" {
		t.Errorf("aliases %v", st.Aliases)
	}
	p := st.Products[0]
	if p.Digest != "sha256:13d22ec63300e16014d4a42aed735207a8b33c223cff19627dd3042e5a10a3a0" || p.Problem != "" {
		t.Errorf("product %+v", p)
	}
	if IgnoreReason(st) != ReasonFalsePositive {
		t.Errorf("reason %s", IgnoreReason(st))
	}
	// The second statement has no timestamp of its own.
	if d.Statements[1].Timestamp != nil {
		t.Errorf("timestamp %v", d.Statements[1].Timestamp)
	}
}

func TestOpenVEXPackagesAndStatuses(t *testing.T) {
	d := mustRead(t, "openvex-demo.json")
	st := d.Statements[0]
	if st.Status != StatusFixed || len(st.Products) != 2 || st.Products[0].Purl != "pkg:apk/distro/git@2.39.0-r1?arch=armv7" {
		t.Errorf("statement %+v", st)
	}
	d = mustRead(t, "openvex-v020-under-investigation.json")
	if s := d.Statements[0]; s.Status != StatusUnderInvestigation || s.Products[0].Purl != "pkg:apk/wolfi/bash@1.0.0" {
		t.Errorf("statement %+v", s)
	}
}

// OpenVEX v0.0.1 wrote products and vulnerabilities as strings; anything
// that is not a package URL, CPE or image digest cannot match.
func TestOpenVEXv001Products(t *testing.T) {
	d := mustRead(t, "openvex-v001-images.json")
	if len(d.Statements) != 4 {
		t.Fatalf("%d statements", len(d.Statements))
	}
	if p := d.Statements[0].Products[0]; p.Digest != "sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a" || p.Problem != "" {
		t.Errorf("digest product %+v", p)
	}
	for i, want := range []string{"not a package URL", "not a package URL", "without a digest"} {
		if p := d.Statements[i+1].Products[0]; !strings.Contains(p.Problem, want) {
			t.Errorf("statement %d product %+v: want problem %q", i+1, p, want)
		}
	}
	if d.Statements[0].Vulnerability != "CVE-1234-5678" {
		t.Errorf("vulnerability %q", d.Statements[0].Vulnerability)
	}
	d = mustRead(t, "openvex-oci-no-digest.json")
	if p := d.Statements[0].Products[0]; !strings.Contains(p.Problem, "digest") {
		t.Errorf("product %+v", p)
	}
}

func TestCycloneDXBOMLink(t *testing.T) {
	d := mustRead(t, "cdx-vex-bomlink.json")
	st := d.Statements[0]
	if st.Status != StatusNotAffected || st.OriginalState != "not_affected" || st.OriginalJustification != "code_not_reachable" ||
		st.Justification != JustVulnerableCodeNotInExecutePath || !strings.Contains(st.ImpactStatement, "not reachable") {
		t.Errorf("statement %+v", st)
	}
	if IgnoreReason(st) != ReasonMitigated {
		t.Errorf("reason %s", IgnoreReason(st))
	}
	if len(st.Aliases) != 1 || st.Aliases[0] != "SNYK-JAVA-COMFASTERXMLJACKSONCORE-1048302" {
		t.Errorf("aliases %v", st.Aliases)
	}
	p := st.Products[0]
	if p.Serial != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" || len(p.Subcomponents) != 1 {
		t.Fatalf("product %+v", p)
	}
	if s := p.Subcomponents[0]; s.Purl != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar" || s.BOMRef == "" {
		t.Errorf("subcomponent %+v", s)
	}
}

// VEX embedded in an SBOM: the component sits in the SBOM's application,
// which its package URL identifies.
func TestCycloneDXEmbedded(t *testing.T) {
	d := mustRead(t, "cdx-bom-embedded.json")
	if len(d.Statements) != 1 {
		t.Fatalf("%d statements", len(d.Statements))
	}
	p := d.Statements[0].Products[0]
	if p.Purl != "pkg:maven/com.example/example-app@1.0.0?type=jar" || p.Serial != "urn:uuid:5f0f0da9-c03d-47d8-b38d-009e6df67094" ||
		len(p.Subcomponents) != 1 || p.Subcomponents[0].Purl != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar" {
		t.Errorf("product %+v", p)
	}
}

func TestCycloneDXCISAUseCases(t *testing.T) {
	for name, want := range map[string]string{
		"cdx-cisa1-not-affected.json": StatusNotAffected, "cdx-cisa1-affected.json": StatusAffected,
		"cdx-cisa1-fixed.json": StatusFixed, "cdx-cisa1-under-investigation.json": StatusUnderInvestigation,
	} {
		d := mustRead(t, name)
		st := d.Statements[0]
		if st.Status != want || st.Problem != "" {
			t.Errorf("%s: %+v", name, st)
		}
		// Product ABC has no identifier: it can stand only for the asset
		// an import is scoped to.
		if p := st.Products[0]; !p.Root || p.ID == "" || len(p.Subcomponents) != 0 {
			t.Errorf("%s: product %+v", name, p)
		}
	}
	d := mustRead(t, "cdx-cisa1-affected.json")
	if st := d.Statements[0]; !strings.Contains(st.ActionStatement, "update") {
		t.Errorf("action %q", st.ActionStatement)
	}
	// Version ranges are not matched.
	d = mustRead(t, "cdx-cisa7.json")
	for _, p := range d.Statements[0].Products {
		if !strings.Contains(p.Problem, "range") {
			t.Errorf("product %+v", p)
		}
	}
}

func TestStatementProblems(t *testing.T) {
	doc := func(st string) []byte {
		return []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","statements":[` + st + `]}`)
	}
	for st, want := range map[string]string{
		`{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected"}`:                                    "justification",
		`{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected","justification":"because"}`:          "unknown justification",
		`{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"maybe"}`:                                           "unknown status",
		`{"vulnerability":{"name":"<script>"},"products":[{"@id":"pkg:npm/a@1"}],"status":"fixed"}`:                                             "vulnerability",
		`{"vulnerability":{"name":"CVE-2024-1"},"products":[],"status":"fixed"}`:                                                                "no products",
		`{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected","impact_statement":"only in tests"}`: "",
	} {
		d, err := Read(doc(st))
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Statements[0].Problem; (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: problem %q, want %q", st, got, want)
		}
	}
	if _, err := Read([]byte(`{"@context":"https://example.com/ns","statements":[]}`)); err == nil {
		t.Error("a foreign @context was accepted")
	}
	if _, err := Read([]byte(`{"hello":"world"}`)); err != ErrUnknownFormat {
		t.Errorf("unknown document: %v", err)
	}
}

func TestNormalizeVulnID(t *testing.T) {
	for in, want := range map[string]string{
		"cve-2021-44228": "CVE-2021-44228", "GHSA-JFH8-C2JP-5V3Q": "GHSA-jfh8-c2jp-5v3q",
		"https://nvd.nist.gov/vuln/detail/CVE-2021-44228": "CVE-2021-44228", "DSA-5000-1": "DSA-5000-1",
		"a b": "", "": "", strings.Repeat("A", 300): "",
	} {
		if got := NormalizeVulnID(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Size caps: an oversized document, too many statements and too many
// products are refused before anything is matched.
func TestSizeCaps(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxDocumentSize+1)
	if _, err := Read(big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("oversized: %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[`)
	for i := 0; i <= MaxStatements; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"fixed"}`)
	}
	b.WriteString("]}")
	if _, err := Read([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "statements") {
		t.Errorf("too many statements: %v", err)
	}
	b.Reset()
	b.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-1"},"status":"fixed","products":[`)
	for i := 0; i <= MaxProducts; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"@id":"pkg:npm/a@%d"}`, i)
	}
	b.WriteString("]}]}")
	if _, err := Read([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "products") {
		t.Errorf("too many products: %v", err)
	}
	long := strings.Repeat("x", 20000)
	d, err := Read([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-2024-1"},` +
		`"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected","impact_statement":"` + long + `"}]}`))
	if err != nil || len(d.Statements[0].ImpactStatement) != maxTextLen {
		t.Errorf("long impact statement: %v %d", err, len(d.Statements[0].ImpactStatement))
	}
}

// A real cosign attestation (cosign attest-blob --type openvex) verifies
// with its key, and not after any change or with another key.
func TestCosignBundle(t *testing.T) {
	data := fixture(t, "cosign-openvex.bundle.json")
	d, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if d.Envelope == nil || len(d.Envelope.Signatures) != 1 || len(d.Statements) != 2 || d.Format != FormatOpenVEX {
		t.Fatalf("document %+v", d)
	}
	if len(d.Subjects) != 1 || d.Subjects[0].Name != "blob.txt" || d.Subjects[0].SHA256 == "" {
		t.Errorf("subjects %+v", d.Subjects)
	}
	v, fp, err := ParsePublicKey(string(fixture(t, "cosign.pub")))
	if err != nil || len(fp) != 64 {
		t.Fatal(err, fp)
	}
	if err := v.Verify(d.Envelope); err != nil {
		t.Errorf("verify: %v", err)
	}
	// Tampered payload.
	env := *d.Envelope
	env.Payload = bytes.Replace(env.Payload, []byte("not_affected"), []byte("affected"), 1)
	if err := v.Verify(&env); err == nil {
		t.Error("a changed payload verified")
	}
	// Another key.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	ov, _, err := ParsePublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.Verify(d.Envelope); err == nil {
		t.Error("verified with another key")
	}
	if _, _, err := ParsePublicKey("not a key"); err == nil {
		t.Error("garbage accepted as a key")
	}
}

// signEnvelope wraps an OpenVEX document in an in-toto attestation signed
// with key, as cosign attest does.
func signEnvelope(t *testing.T, key *ecdsa.PrivateKey, doc []byte) []byte {
	t.Helper()
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://openvex.dev/ns/v0.2.0",
		"subject":   []any{map[string]any{"name": "img", "digest": map[string]string{"sha256": strings.Repeat("a", 64)}}},
		"predicate": json.RawMessage(doc)})
	h := sha256.Sum256(PAE("application/vnd.in-toto+json", st))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(st),
		"signatures": []any{map[string]string{"keyid": "", "sig": base64.StdEncoding.EncodeToString(sig)}}})
	return env
}

func TestPlainDSSEEnvelope(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	v, _, err := ParsePublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Read(signEnvelope(t, key, fixture(t, "openvex-demo.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(d.Envelope); err != nil || d.Statements[0].Status != StatusFixed {
		t.Errorf("verify %v, %+v", err, d.Statements)
	}
}

func roundTrip(t *testing.T, write func(*bytes.Buffer, ExportMeta, []ExportStatement) error) *Document {
	t.Helper()
	img := ImagePurl("registry.example.com/team/app:1.2", "sha256:"+strings.Repeat("b", 64))
	sts := []ExportStatement{
		{Vulnerability: "CVE-2024-0001", Status: StatusNotAffected, Justification: JustVulnerableCodeNotInExecutePath,
			ImpactStatement: "only used at build time", Product: Product{Purl: img, Digest: "sha256:" + strings.Repeat("b", 64)},
			Component: Product{Purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"}, Timestamp: time.Unix(1700000000, 0)},
		{Vulnerability: "CVE-2024-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Status: StatusNotAffected, FalsePositive: true,
			Justification: JustVulnerableCodeNotPresent, Component: Product{Purl: "pkg:npm/lodash@4.17.20"}, Timestamp: time.Unix(1700000000, 0)},
		{Vulnerability: "CVE-2024-0003", Status: StatusAffected, ActionStatement: "upgrade to 2.0",
			Component: Product{Purl: "pkg:npm/lodash@4.17.20"}, Timestamp: time.Unix(1700000000, 0)},
		{Vulnerability: "CVE-2024-0004", Status: StatusUnderInvestigation, Component: Product{Purl: "pkg:npm/lodash@4.17.20"},
			Timestamp: time.Unix(1700000000, 0)},
	}
	var buf bytes.Buffer
	if err := write(&buf, ExportMeta{Author: "Stackurity (acme)", Tool: "stackurity test", Timestamp: time.Unix(1700000100, 0), Scope: "asset 1"}, sts); err != nil {
		t.Fatal(err)
	}
	d, err := Read(buf.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	if len(d.Statements) != 4 {
		t.Fatalf("%d statements\n%s", len(d.Statements), buf.String())
	}
	for _, st := range d.Statements {
		if st.Problem != "" {
			t.Errorf("%s: %s", st.Vulnerability, st.Problem)
		}
	}
	a := d.Statements[0]
	if a.Vulnerability != "CVE-2024-0001" || a.Status != StatusNotAffected || a.Justification != JustVulnerableCodeNotInExecutePath ||
		a.ImpactStatement != "only used at build time" {
		t.Errorf("statement 1 %+v", a)
	}
	if p := a.Products[0]; p.Digest != "sha256:"+strings.Repeat("b", 64) || len(p.Subcomponents) != 1 ||
		p.Subcomponents[0].Purl != "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12" {
		t.Errorf("statement 1 product %+v", p)
	}
	if b := d.Statements[1]; IgnoreReason(b) != ReasonFalsePositive || b.Products[0].Purl != "pkg:npm/lodash@4.17.20" ||
		len(b.Aliases) != 1 || b.Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("statement 2 %+v", b)
	}
	if c := d.Statements[2]; c.Status != StatusAffected || !strings.Contains(c.ActionStatement+c.StatusNotes, "upgrade to 2.0") {
		t.Errorf("statement 3 %+v", c)
	}
	if d.Statements[3].Status != StatusUnderInvestigation {
		t.Errorf("statement 4 %+v", d.Statements[3])
	}
	return d
}

func TestRoundTripOpenVEX(t *testing.T) {
	d := roundTrip(t, func(b *bytes.Buffer, m ExportMeta, s []ExportStatement) error { return WriteOpenVEX(b, m, s) })
	if d.Author != "Stackurity (acme)" || !strings.HasPrefix(d.ID, "urn:stackurity:vex:") {
		t.Errorf("document %+v", d)
	}
}

func TestRoundTripCycloneDX(t *testing.T) {
	d := roundTrip(t, func(b *bytes.Buffer, m ExportMeta, s []ExportStatement) error { return WriteCycloneDX(b, m, s) })
	if d.Spec != "1.6" || !strings.HasPrefix(d.ID, "urn:uuid:") {
		t.Errorf("document %+v", d)
	}
	if d.Statements[1].OriginalState != "false_positive" {
		t.Errorf("false positive written as %q", d.Statements[1].OriginalState)
	}
}

func TestImagePurl(t *testing.T) {
	d := "sha256:" + strings.Repeat("c", 64)
	for ref, want := range map[string]string{
		"registry.example.com/team/app:1.2": "pkg:oci/app@" + d + "?repository_url=registry.example.com%2Fteam%2Fapp",
		"nginx":                             "pkg:oci/nginx@" + d,
		"localhost:5000/app@" + d:           "pkg:oci/app@" + d + "?repository_url=localhost:5000%2Fapp",
	} {
		got := ImagePurl(ref, d)
		if got != want {
			t.Errorf("%s: %s, want %s", ref, got, want)
		}
		if p := productFromID(got); p.Digest != d {
			t.Errorf("%s: read back %+v", ref, p)
		}
	}
}

// FuzzRead feeds arbitrary documents to the reader. It must never panic,
// and what it returns stays within the limits.
func FuzzRead(f *testing.F) {
	for _, name := range []string{"openvex-demo.json", "openvex-v001-images.json", "cdx-vex-bomlink.json", "cdx-bom-embedded.json",
		"cdx-cisa7.json", "cosign-openvex.bundle.json"} {
		f.Add(fixture(f, name))
	}
	for _, s := range []string{`{}`, `[`, `null`, `{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`,
		`{"dsseEnvelope":{"dsseEnvelope":{"dsseEnvelope":{}}}}`, `{"@context":"https://openvex.dev/ns","statements":[{"products":[1]}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Read(data)
		if err != nil {
			return
		}
		if len(d.Statements) > MaxStatements {
			t.Fatalf("%d statements", len(d.Statements))
		}
		for _, st := range d.Statements {
			if len(st.Products) > MaxProducts*MaxProducts || len(st.ImpactStatement) > maxTextLen {
				t.Fatalf("statement %+v", st)
			}
		}
	})
}
