package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/license"
)

// Offers as a Stackurity Cloud server sends them (prices from its plan
// configuration) and as a self-hosted one does (names only).
func reachOffer(trial bool) *license.Offer {
	o := &license.Offer{Feature: license.Reachability, FeatureName: "Reachability", Hosted: true,
		IncludedIn: []string{"Team", "Business", "Enterprise"}, Plan: &license.Price{Name: "Team", Price: "35", Currency: "USD", Interval: "month"},
		PlansURL: license.PlansURL}
	if trial {
		o.TrialAvailable, o.TrialDays = true, 30
	}
	return o
}

func complianceOffer() *license.Offer {
	return &license.Offer{Feature: license.ComplianceAddon, FeatureName: "PCI DSS 4.0 evidence", Hosted: true, IncludedIn: []string{"Enterprise"},
		Addon:          &license.Price{Name: "Compliance add-on", Price: "99", Currency: "USD", Interval: "month", On: []string{"Team", "Business"}},
		TrialAvailable: true, TrialDays: 30, PlansURL: license.PlansURL}
}

var purchaseWords = []string{"$", "€", "₹", "trial", "checkout", "buy", "subscribe", "upgrade now"}

func TestOfferLines(t *testing.T) {
	selfReach := license.SelfHostedOffer(license.Reachability)
	selfPCI := license.SelfHostedOffer(license.ComplianceAddon)
	selfPCI.FeatureName = "PCI DSS 4.0 evidence"
	eur := complianceOffer()
	eur.Addon.Price, eur.Addon.Currency = "99", "EUR"
	anyPlan := complianceOffer()
	anyPlan.Addon.AnyPlan, anyPlan.Addon.On = true, []string{"Starter", "Team", "Business"}
	inr := reachOffer(false)
	inr.Plan.Price, inr.Plan.Currency = "2999", "INR"
	cases := []struct {
		name       string
		o          *license.Offer
		restricted bool
		want       string
	}{
		{"claude, Pro feature, lapsed trial", reachOffer(false), false,
			"Reachability is not included in this organisation's plan. It is included in the Team plan ($35 a month) and higher plans. Plans: https://stackurity.ai/pricing.html"},
		{"claude, Pro feature, trial open", reachOffer(true), false,
			"Reachability is not included in this organisation's plan. It is included in the Team plan ($35 a month) and higher plans. A 30-day free trial is available. Plans: https://stackurity.ai/pricing.html"},
		{"claude, add-on (a trial flag is never shown for it)", complianceOffer(), false,
			"PCI DSS 4.0 evidence is not included in this organisation's plan. It is part of the Compliance add-on: +$99 a month on the Team or Business plan, included in Enterprise. Plans: https://stackurity.ai/pricing.html"},
		{"claude, add-on on every paid plan (from the plans config)", anyPlan, false,
			"PCI DSS 4.0 evidence is not included in this organisation's plan. It is part of the Compliance add-on: +$99 a month on any paid plan, included in Enterprise. Plans: https://stackurity.ai/pricing.html"},
		{"chatgpt, add-on on every paid plan", anyPlan, true,
			"PCI DSS 4.0 evidence is not included in your current plan; it is part of the Compliance add-on. Plans: https://stackurity.ai/pricing.html"},
		{"claude, add-on in EUR", eur, false,
			"PCI DSS 4.0 evidence is not included in this organisation's plan. It is part of the Compliance add-on: +€99 a month on the Team or Business plan, included in Enterprise. Plans: https://stackurity.ai/pricing.html"},
		{"claude, Pro feature in INR", inr, false,
			"Reachability is not included in this organisation's plan. It is included in the Team plan (₹2999 a month) and higher plans. Plans: https://stackurity.ai/pricing.html"},
		{"chatgpt, Pro feature with a trial open", reachOffer(true), true,
			"Reachability is not included in your current plan; it is part of the Team plan. Plans: https://stackurity.ai/pricing.html"},
		{"chatgpt, add-on", complianceOffer(), true,
			"PCI DSS 4.0 evidence is not included in your current plan; it is part of the Compliance add-on. Plans: https://stackurity.ai/pricing.html"},
		{"self-hosted, Pro feature", selfReach, false,
			"Reachability is not included in this organisation's plan. It needs a Pro or Enterprise licence. Plans: https://stackurity.ai/pricing.html"},
		{"self-hosted, add-on", selfPCI, false,
			"PCI DSS 4.0 evidence is not included in this organisation's plan. It needs the Compliance add-on on a Pro licence, or an Enterprise licence. Plans: https://stackurity.ai/pricing.html"},
	}
	for _, c := range cases {
		if got := offerLine(c.o, c.restricted); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		if c.restricted {
			for _, w := range purchaseWords {
				if strings.Contains(strings.ToLower(offerLine(c.o, true)), w) {
					t.Errorf("%s: ChatGPT line has %q", c.name, w)
				}
			}
		}
	}
	// A plans page that is not https (or a checkout someone configured
	// oddly) is replaced by the public plans page.
	o := reachOffer(false)
	o.PlansURL = "javascript:alert(1)"
	if !strings.HasSuffix(offerLine(o, false), "Plans: "+license.PlansURL) {
		t.Errorf("plans link: %s", offerLine(o, false))
	}
}

func TestClientIsOpenAI(t *testing.T) {
	for c, want := range map[ClientInfo]bool{
		{Name: "openai-mcp"}:                    true,
		{UserAgent: "openai-mcp/1.0.0"}:         true,
		{OAuthClient: "ChatGPT"}:                true,
		{RedirectHost: "chatgpt.com"}:           true,
		{Name: "claude-ai"}:                     false,
		{Name: "Claude Code", UserAgent: "x/1"}: false,
		{}:                                      false,
	} {
		if c.OpenAI() != want {
			t.Errorf("%+v: OpenAI() = %v", c, !want)
		}
	}
}

// planAPI answers like a server whose plan lacks reachability and the
// Compliance add-on, and refuses a reachability filter with 402.
type planAPI struct {
	offers   map[license.Feature]*license.Offer
	evidence bool // the plan includes the evidence pack
	paths    []string
}

func (f *planAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	switch {
	case path == "/api/v1/plan/options":
		type feat struct {
			Feature     license.Feature `json:"feature"`
			Name        string          `json:"name"`
			Description string          `json:"description,omitempty"`
			Offer       *license.Offer  `json:"offer,omitempty"`
		}
		res := map[string]any{"edition": "community", "plans_url": license.PlansURL}
		in, missing := []feat{}, []feat{}
		for _, ft := range license.PaidFeatures() {
			if o, ok := f.offers[ft]; ok && !(ft == license.EvidenceReport && f.evidence) {
				missing = append(missing, feat{ft, ft.Name(), ft.Description(), o})
			} else {
				in = append(in, feat{Feature: ft, Name: ft.Name()})
			}
		}
		res["included"], res["not_included"] = in, missing
		b, _ := json.Marshal(res)
		return json.Unmarshal(b, out)
	case strings.HasPrefix(path, "/api/v1/findings?") && strings.Contains(path, "reachability="):
		o := *f.offers[license.Reachability]
		return &client.APIError{Status: 402, Code: "plan_required", Message: "Reachability is part of Stackurity Pro.", Offer: &o}
	}
	return json.Unmarshal([]byte(`{"items":[],"total":0}`), out)
}

func lapsedTrialAPI() *planAPI {
	return &planAPI{evidence: true, offers: map[license.Feature]*license.Offer{
		license.Reachability:    reachOffer(false),
		license.ComplianceAddon: func() *license.Offer { o := complianceOffer(); o.FeatureName = "The Compliance add-on"; return o }(),
	}}
}

func errText(t *testing.T, out map[string]any) string {
	t.Helper()
	e, ok := out["error"].(string)
	if !ok {
		t.Fatalf("want an error, got %v", out)
	}
	return e
}

// A refused filter becomes the offer line, per client.
func TestPlanRequiredRenderedPerClient(t *testing.T) {
	args := map[string]any{"reachability": "not_reached"}
	claude := &Server{API: lapsedTrialAPI(), Version: "t", Client: ClientInfo{Name: "claude-ai"}}
	if got := errText(t, callTool(t, claude, "list_findings", args)); got != offerLine(reachOffer(false), false) || !strings.Contains(got, "$35") {
		t.Errorf("claude: %s", got)
	}
	gpt := &Server{API: lapsedTrialAPI(), Version: "t", Client: ClientInfo{UserAgent: "openai-mcp/1.0.0"}}
	if got := errText(t, callTool(t, gpt, "list_findings", args)); strings.Contains(got, "$") ||
		got != "Reachability is not included in your current plan; it is part of the Team plan. Plans: https://stackurity.ai/pricing.html" {
		t.Errorf("chatgpt: %s", got)
	}
	// Other errors pass through as before.
	if got := errorText(context.Background(), &client.APIError{Status: 402, Code: "read_only", Message: "read-only"}); !strings.Contains(got, "read_only") {
		t.Errorf("read_only: %s", got)
	}
}

// stdio learns the client from initialize; a later call is rendered for it.
func TestInitializeClientInfoSelectsRendering(t *testing.T) {
	var out bytes.Buffer
	s := &Server{API: lapsedTrialAPI(), Version: "t"}
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"openai-mcp","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_findings","arguments":{"reachability":"not_reached"}}}`,
	}, "\n") + "\n"
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "$35") || !strings.Contains(out.String(), "not included in your current plan") {
		t.Errorf("after initialize as openai-mcp: %s", out.String())
	}
}

// Over HTTP the User-Agent (no session keeps initialize) selects it.
func TestHTTPUserAgentSelectsRendering(t *testing.T) {
	s := &Server{API: lapsedTrialAPI(), Version: "t", Client: ClientInfo{UserAgent: "openai-mcp/1.0.0"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"reachability":"not_reached"}}}`))
	s.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "$35") || !strings.Contains(rec.Body.String(), "your current plan") {
		t.Errorf("http: %s", rec.Body.String())
	}
}

func TestPlanOptionsTool(t *testing.T) {
	for _, c := range []struct {
		client     ClientInfo
		restricted bool
	}{{ClientInfo{Name: "claude-ai"}, false}, {ClientInfo{Name: "openai-mcp"}, true}} {
		out := callTool(t, &Server{API: lapsedTrialAPI(), Version: "t", Client: c.client}, "plan_options", nil)
		missing := out["not_included"].([]any)
		if len(missing) != 2 {
			t.Fatalf("not_included: %v", out)
		}
		reach, addon := missing[0].(map[string]any), missing[1].(map[string]any)
		if reach["feature"] != "reachability" || reach["what_it_does"] == "" || addon["feature"] != "compliance_addon" {
			t.Errorf("features: %v", missing)
		}
		if c.restricted {
			if reach["how_to_get"] != "Part of the Team plan." || addon["how_to_get"] != "Part of the Compliance add-on." {
				t.Errorf("chatgpt how_to_get: %v / %v", reach["how_to_get"], addon["how_to_get"])
			}
		} else if reach["how_to_get"] != "Team plan ($35 a month) and higher plans." ||
			addon["how_to_get"] != "Compliance add-on: +$99 a month on the Team or Business plan; included in Enterprise." {
			t.Errorf("claude how_to_get: %v / %v", reach["how_to_get"], addon["how_to_get"])
		}
		if inc := out["included"].([]any); len(inc) != 7 || out["plans_url"] != license.PlansURL {
			t.Errorf("included / plans_url: %v", out)
		}
	}
}

// Successful answers never carry an offer (no upsell in tool results).
func TestNoOfferInSuccessfulAnswers(t *testing.T) {
	s := &Server{API: lapsedTrialAPI(), Version: "t", Client: ClientInfo{Name: "claude-ai"}}
	for _, name := range readTools {
		if name == "plan_options" {
			continue
		}
		raw, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{"query": "openssl", "asset_id": 1, "finding_id": 1, "name": "x", "since": "2026-11-01"}})
		res, _ := s.handle(context.Background(), request{Method: "tools/call", Params: raw})
		m, _ := res.(map[string]any)
		if m == nil || m["isError"] == true {
			continue
		}
		text := m["content"].([]map[string]any)[0]["text"].(string)
		for _, w := range []string{"$35", "$99", "pricing.html", "free trial"} {
			if strings.Contains(text, w) {
				t.Errorf("%s answers with %q: %s", name, w, text)
			}
		}
	}
}

func TestEvidencePackTool(t *testing.T) {
	claude := &Server{API: lapsedTrialAPI(), Version: "t", BaseURL: "https://app.stackurity.ai", Client: ClientInfo{Name: "claude-ai"}}
	// PCI without the add-on: the add-on offer, naming what was asked for.
	got := errText(t, callTool(t, claude, "evidence_pack", map[string]any{"frameworks": "soc2,pci_dss_4_0"}))
	if got != "PCI DSS 4.0 evidence is not included in this organisation's plan. It is part of the Compliance add-on: +$99 a month on the Team or Business plan, included in Enterprise. Plans: https://stackurity.ai/pricing.html" {
		t.Errorf("claude pci: %s", got)
	}
	gpt := &Server{API: lapsedTrialAPI(), Version: "t", Client: ClientInfo{OAuthClient: "ChatGPT"}}
	got = errText(t, callTool(t, gpt, "evidence_pack", map[string]any{"frameworks": "pci_dss_4_0,eu_cra"}))
	if got != "PCI DSS 4.0 and EU Cyber Resilience Act evidence is not included in your current plan; it is part of the Compliance add-on. Plans: https://stackurity.ai/pricing.html" {
		t.Errorf("chatgpt pci: %s", got)
	}
	// SOC 2: a link, nothing built, no offer.
	api := lapsedTrialAPI()
	claude.API = api
	out := callTool(t, claude, "evidence_pack", map[string]any{"frameworks": "soc2", "from": "2026-07-01", "to": "2026-09-30", "format": "zip", "project_id": 4})
	link, _ := out["download_url"].(string)
	if !strings.HasPrefix(link, "https://app.stackurity.ai/api/v1/reports/evidence-pack?") || !strings.Contains(link, "frameworks=soc2") ||
		!strings.Contains(link, "from=2026-07-01") || !strings.Contains(link, "project_id=4") || !strings.Contains(link, "format=zip") {
		t.Errorf("link: %v", out)
	}
	if _, ok := out["files"]; ok {
		t.Errorf("SBOM/VEX files promised without the add-on: %v", out)
	}
	for _, p := range api.paths {
		if strings.Contains(p, "evidence-pack") {
			t.Errorf("the tool built a pack: %s", p)
		}
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), "$") || strings.Contains(string(b), "pricing") {
		t.Errorf("offer in a successful answer: %s", b)
	}
	// No evidence pack in the plan at all.
	noPack := lapsedTrialAPI()
	noPack.evidence = false
	noPack.offers[license.EvidenceReport] = &license.Offer{Feature: license.EvidenceReport, FeatureName: license.EvidenceReport.Name(), Hosted: true,
		IncludedIn: []string{"Team", "Business", "Enterprise"}, Plan: &license.Price{Name: "Team", Price: "35", Currency: "USD", Interval: "month"}, PlansURL: license.PlansURL}
	got = errText(t, callTool(t, &Server{API: noPack, Version: "t"}, "evidence_pack", nil))
	if !strings.HasPrefix(got, "The evidence pack is not included in this organisation's plan. It is included in the Team plan ($35 a month)") {
		t.Errorf("no pack: %s", got)
	}
	if got := errText(t, callTool(t, claude, "evidence_pack", map[string]any{"frameworks": "hipaa"})); !strings.Contains(got, "unknown framework") {
		t.Errorf("unknown framework: %s", got)
	}
}
