package intel

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleUpdateInfo = `<?xml version="1.0"?><updates>
<update type="security"><id>ALAS2023-2024-001</id><title>openssl</title><severity>important</severity>
<issued date="2024-01-02 03:04"/><updated date="2024-01-03"/><description>d</description>
<references><reference type="cve" id="CVE-2024-0001" href="https://x"/></references>
<pkglist><collection><package name="openssl" epoch="1" version="3.0.8" release="1.amzn2023" arch="x86_64"/></collection></pkglist>
</update></updates>`

// FuzzParseUpdateInfo: updateinfo.xml comes from a mirror the operator
// configures; whatever it contains, parsing must not panic and records
// must be well formed.
func FuzzParseUpdateInfo(f *testing.F) {
	f.Add([]byte(sampleUpdateInfo))
	f.Add([]byte(`<updates><update type="security"><id>ALAS-1</id><pkglist><collection><package name="" version="" release=""/></collection></pkglist></update></updates>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "aaaa">]><updates><update type="security"><id>&a;</id></update></updates>`))
	f.Add([]byte(`<updates><update`))
	f.Fuzz(func(t *testing.T, data []byte) {
		recs, err := parseUpdateInfo(bytes.NewReader(data), alasRepo{release: "2023"})
		if err != nil {
			return
		}
		for _, r := range recs {
			if !strings.HasPrefix(r.ID, "ALAS") || len(r.Affected) == 0 || len(r.Details) > 8000 {
				t.Fatalf("malformed record %+v", r)
			}
		}
	})
}

// TestHostileUpdateInfo: encoding/xml expands no entities beyond the five
// predefined ones and never reads external resources, so billion-laughs and
// XXE documents fail cleanly; deep nesting and huge text stay bounded.
func TestHostileUpdateInfo(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("TOP-SECRET-CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	laughs := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">` +
		`<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">` +
		`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">` +
		`<!ENTITY lol9 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]>` +
		`<updates><update type="security"><id>ALAS-1</id><description>&lol9;</description>` +
		`<pkglist><collection><package name="a" version="1" release="1" arch="x86_64"/></collection></pkglist></update></updates>`
	xxe := `<?xml version="1.0"?><!DOCTYPE u [<!ENTITY x SYSTEM "file://` + secret + `">]>` +
		`<updates><update type="security"><id>ALAS-1</id><description>&x;</description>` +
		`<pkglist><collection><package name="a" version="1" release="1" arch="x86_64"/></collection></pkglist></update></updates>`
	deep := `<updates><update type="security"><id>ALAS-1</id><description>` + strings.Repeat("<a>", 200000) + strings.Repeat("</a>", 200000) + `</description></update></updates>`
	huge := `<updates><update type="security"><id>ALAS-1</id><description>` + strings.Repeat("x", 32<<20) +
		`</description><pkglist><collection><package name="a" version="1" release="1" arch="x86_64"/></collection></pkglist></update></updates>`
	for name, doc := range map[string]string{"billion laughs": laughs, "external entity": xxe, "deep nesting": deep, "huge text": huge} {
		start := time.Now()
		recs, err := parseUpdateInfo(strings.NewReader(doc), alasRepo{release: "2023"})
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: took %s", name, d)
		}
		for _, r := range recs {
			if strings.Contains(r.Details, "TOP-SECRET") || strings.Contains(r.Details, "lollol") {
				t.Errorf("%s: entity expanded into %q", name, r.Details[:min(len(r.Details), 80)])
			}
			if len(r.Details) > 8000 {
				t.Errorf("%s: %d-byte description kept", name, len(r.Details))
			}
		}
		if (name == "billion laughs" || name == "external entity") && err == nil {
			t.Errorf("%s: parsed without error (%d records)", name, len(recs))
		}
	}
}
