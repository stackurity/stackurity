package notify

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// go test ./internal/notify -run TestBulkGolden -update rewrites the golden
// files after a deliberate change to the layout; review the diff.
var updateGolden = flag.Bool("update", false, "rewrite the golden files in testdata/bulk")

func loadCampaign(t *testing.T, path string) BulkCampaign {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c BulkCampaign
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return c
}

// TestBulkGolden renders the sample release and vulnerability news emails
// (testdata/bulk/*.json) and compares them with the golden HTML and text.
func TestBulkGolden(t *testing.T) {
	b := &Bulk{Mail: &bulkBox{}, BaseURL: "https://app.stackurity.dev", PostalAddress: "Example Ltd, 1 Main Road, Pune 411001, India"}
	for _, name := range []string{"release", "vuln-news"} {
		t.Run(name, func(t *testing.T) {
			p, err := b.Preview(loadCampaign(t, filepath.Join("testdata", "bulk", name+".json")))
			if err != nil {
				t.Fatal(err)
			}
			for ext, got := range map[string]string{".html": p.HTML, ".txt": p.Text} {
				golden := filepath.Join("testdata", "bulk", name+ext)
				if *updateGolden {
					if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("%v (run with -update to create it)", err)
				}
				if got != string(want) {
					t.Errorf("%s differs from the rendering (run with -update after a deliberate change):\n%s", golden, got)
				}
			}
		})
	}
}

func TestBulkLayout(t *testing.T) {
	camp := BulkCampaign{Key: "x", Category: store.CategoryMarketing, Message: Message{Title: "Hello", Summary: []string{"Hi."},
		Sections: []Section{{Title: "Added", Items: []Item{{Text: "A thing"}}}}, Link: "https://example.com/notes", LinkLabel: "Release notes"}}
	b := &Bulk{Mail: &bulkBox{}, BaseURL: "https://app.stk.example/"}
	p, err := b.Preview(camp)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`max-width:600px`, `<!--[if mso]>`, `role="presentation"`, `prefers-color-scheme:dark`, `>Stackurity</span>`,
		`href="https://app.stk.example/"`, "Unsubscribe from Marketing</a>", "Manage email preferences</a>",
		"Sent by Stackurity (news@stackurity.test)", `class="stk-btn" href="https://example.com/notes"`,
	} {
		if !strings.Contains(p.HTML, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if strings.Contains(p.HTML, "<img") || strings.Contains(p.HTML, "Postal") {
		t.Errorf("an image, or an address line with no postal address set:\n%s", p.HTML)
	}
	// Without a postal address the footer ends with the sender, in both parts.
	if !strings.HasSuffix(p.Text, "Sent by Stackurity (news@stackurity.test)\n") {
		t.Errorf("text footer:\n%s", p.Text)
	}
	b.PostalAddress = "Example Ltd, Pune"
	if p, _ = b.Preview(camp); !strings.Contains(p.HTML, `<p style="margin:0">Example Ltd, Pune</p>`) || !strings.HasSuffix(p.Text, "Example Ltd, Pune\n") {
		t.Errorf("postal address missing:\n%s\n%s", p.HTML, p.Text)
	}
}

// Advisory titles, descriptions and release notes come from outside (CISA,
// CHANGELOG.md): every piece of text is escaped, and a link that is not
// http or https is shown as text.
func TestBulkEscaping(t *testing.T) {
	bad := `<script>alert("x")</script> it's "quoted" & <b>bold</b>`
	camp := BulkCampaign{Key: "x", Category: store.CategoryVulnerabilityNews, Message: Message{
		Title:   "Vulnerability news: " + bad,
		Summary: []string{bad},
		Sections: []Section{
			{Title: "Added to CISA's Known Exploited Vulnerabilities catalogue " + bad, Items: []Item{
				{Text: "CVE-2026-1: " + bad, Link: `https://nvd.nist.gov/vuln/detail/CVE-2026-1?q="><script>`, Items: []Item{{Text: bad}}},
			}},
			{Title: "Added", Items: []Item{{Text: "Release note " + bad}, {Text: "click", Link: `javascript:alert("x")`}}},
		},
		Link: "https://example.com/" + `"onmouseover="x`, LinkLabel: bad}}
	p, err := (&Bulk{Mail: &bulkBox{}, BaseURL: "https://app.stk.example"}).Preview(camp)
	if err != nil {
		t.Fatal(err)
	}
	for _, no := range []string{"<script", "<b>", `"quoted"`, "it's", "javascript:", `"onmouseover="`} {
		if strings.Contains(p.HTML, no) {
			t.Errorf("HTML contains %q unescaped", no)
		}
	}
	esc := `&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; it&#39;s &#34;quoted&#34; &amp; &lt;b&gt;bold&lt;/b&gt;`
	// The <title>, preheader, heading, summary, section title, item,
	// sub-item, release note and button label.
	if n := strings.Count(p.HTML, esc); n != 9 {
		t.Errorf("escaped text appears %d times, want 9:\n%s", n, p.HTML)
	}
	if !strings.Contains(p.HTML, `<li style="margin:0 0 6px">click</li>`) {
		t.Errorf("javascript: link kept")
	}
	// The plain-text part keeps the text as written.
	if !strings.Contains(p.Text, "CVE-2026-1: "+bad) {
		t.Errorf("text part:\n%s", p.Text)
	}
}
