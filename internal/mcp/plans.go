package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/license"
)

// plan_options and evidence_pack. plan_options is the one tool that lists
// plan offers, for a person who asks about their plan; evidence_pack gives
// the link that downloads the compliance evidence pack, and answers with
// the plan_required line when the plan lacks the pack or a framework asked
// for.

type baseKey struct{}

type projectKey struct{}

func withBase(ctx context.Context, base string) context.Context {
	return context.WithValue(ctx, baseKey{}, base)
}

func baseFrom(ctx context.Context) string {
	b, _ := ctx.Value(baseKey{}).(string)
	return strings.TrimRight(b, "/")
}

func projectFrom(ctx context.Context) int64 {
	p, _ := ctx.Value(projectKey{}).(int64)
	return p
}

// WithLinks gives the read tools called outside Serve (Ask Stackurity,
// CallRead) what their links need: the server's public base URL
// (STACKURITY_BASE_URL; "" when not set, and then no link is given) and
// the project the person works in (0: none), which evidence_pack's link
// is limited to by default.
func WithLinks(ctx context.Context, base string, project int64) context.Context {
	return context.WithValue(withBase(ctx, base), projectKey{}, project)
}

// planOptions is GET /plan/options.
type planOptions struct {
	Edition  string `json:"edition"`
	Included []struct {
		Feature license.Feature `json:"feature"`
		Name    string          `json:"name"`
	} `json:"included"`
	NotIncluded []struct {
		Feature     license.Feature `json:"feature"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Offer       *license.Offer  `json:"offer"`
	} `json:"not_included"`
	PlansURL string `json:"plans_url"`
}

// lacks returns the offer for f when the plan does not include it.
func (p *planOptions) lacks(f license.Feature) (*license.Offer, bool) {
	for _, x := range p.NotIncluded {
		if x.Feature == f {
			o := x.Offer
			if o == nil {
				o = license.SelfHostedOffer(f)
			}
			return o, true
		}
	}
	return nil, false
}

// howToGet says what includes a feature, for plan_options: the plan or
// add-on, with its price and an open trial except for restricted clients
// (ChatGPT).
func howToGet(o *license.Offer, restricted bool) string {
	if restricted {
		return "Part of " + partOf(o) + "."
	}
	switch {
	case o.Addon != nil && o.Hosted:
		s := o.Addon.Name
		if m := money(o.Addon); m != "" {
			s += ": +" + m
			s += addonPlans(o.Addon)
		}
		if includes(o.IncludedIn, "Enterprise") {
			s += "; included in Enterprise"
		}
		return s + "."
	case o.Addon != nil:
		s := "The " + o.Addon.Name + " on a " + orList(o.Addon.On) + " licence"
		if includes(o.IncludedIn, "Enterprise") {
			s += ", or an Enterprise licence"
		}
		return s + "."
	case !o.Hosted:
		return "A " + orList(o.IncludedIn) + " licence."
	case o.Plan != nil:
		s := o.Plan.Name + " plan"
		if m := money(o.Plan); m != "" {
			s += " (" + m + ")"
		}
		if len(o.IncludedIn) > 1 && o.IncludedIn[len(o.IncludedIn)-1] != o.Plan.Name {
			s += " and higher plans"
		}
		if o.TrialAvailable && o.TrialDays > 0 {
			s += "; " + strconv.Itoa(o.TrialDays) + "-day free trial available"
		}
		return s + "."
	}
	return "Part of " + partOf(o) + "."
}

// evidenceFrameworks are the evidence pack's frameworks (the licensed
// build's internal/evidence is the source of truth; web/src/evidencePack.ts
// keeps the same list).
var evidenceFrameworks = []struct {
	ID, Name string
	Addon    bool
}{
	{"soc2", "SOC 2", false},
	{"iso27001_2022", "ISO 27001:2022", false},
	{"pci_dss_4_0", "PCI DSS 4.0", true},
	{"eu_cra", "EU Cyber Resilience Act", true},
}

func init() {
	tools["plan_options"] = tool{
		description: "Lists the organisation's plan options: which paid features its plan includes, which it does not, what each " +
			"missing one does, and the plan or add-on that includes it. Use it only when the person asks about their plan, " +
			"upgrading, or what another plan would add. Read-only.",
		schema: obj(map[string]any{}),
		run:    planOptionsTool,
	}
	tools["evidence_pack"] = tool{
		description: "The compliance evidence pack for an audit period: which frameworks this organisation's plan covers (SOC 2, " +
			"ISO 27001:2022, PCI DSS 4.0, EU Cyber Resilience Act) and a download_url for the pack. Opening the link while signed " +
			"in to Stackurity builds and downloads it (PDF, ZIP with the PDF and data, or JSON); this tool does not build it. " +
			"Read-only.",
		schema: obj(map[string]any{
			"frameworks": str("Comma-separated: soc2, iso27001_2022, pci_dss_4_0, eu_cra (default: every framework the plan covers)"),
			"from":       str("First day of the period, YYYY-MM-DD (default: 90 days before to)"),
			"to":         str("Last day of the period, YYYY-MM-DD, inclusive (default: today)"),
			"format":     map[string]any{"type": "string", "enum": []string{"pdf", "zip", "json"}, "description": "Default pdf"},
			"project_id": num("Limit the pack to one project (required for people who see only some projects)"),
		}),
		run: evidencePackTool,
	}
	readTitles["plan_options"] = "Plan options"
	readTitles["evidence_pack"] = "Evidence pack link"
}

func getPlanOptions(ctx context.Context, api API) (*planOptions, error) {
	var po planOptions
	if err := api.Do(ctx, "GET", "/api/v1/plan/options", nil, nil, &po); err != nil {
		return nil, err
	}
	return &po, nil
}

func planOptionsTool(ctx context.Context, api API, _ map[string]any) (any, error) {
	po, err := getPlanOptions(ctx, api)
	if err != nil {
		return nil, err
	}
	restricted := clientFrom(ctx).OpenAI()
	included := []string{}
	for _, f := range po.Included {
		included = append(included, f.Name)
	}
	type missing struct {
		Feature    license.Feature `json:"feature"`
		Name       string          `json:"name"`
		WhatItDoes string          `json:"what_it_does"`
		HowToGet   string          `json:"how_to_get"`
	}
	lacking := []missing{}
	for _, f := range po.NotIncluded {
		o := f.Offer
		if o == nil {
			o = license.SelfHostedOffer(f.Feature)
		}
		lacking = append(lacking, missing{f.Feature, f.Name, f.Description, howToGet(o, restricted)})
	}
	plans := po.PlansURL
	if !strings.HasPrefix(plans, "https://") {
		plans = license.PlansURL
	}
	return map[string]any{"edition": po.Edition, "included": included, "not_included": lacking, "plans_url": plans}, nil
}

// planRefusal is a plan_required error for the tool to return.
func planRefusal(o *license.Offer, name string) error {
	c := *o
	if name != "" {
		c.FeatureName = name
	}
	return &client.APIError{Status: 402, Code: "plan_required", Message: c.FeatureName + " is not included in this organisation's plan", Offer: &c}
}

func evidencePackTool(ctx context.Context, api API, a map[string]any) (any, error) {
	po, err := getPlanOptions(ctx, api)
	var ae *client.APIError
	if err != nil && !(errors.As(err, &ae) && ae.Status == 404) {
		return nil, err
	}
	// po is nil on a server older than plan options: the download link
	// then answers for the plan itself.
	if po != nil {
		if o, lacks := po.lacks(license.EvidenceReport); lacks {
			return nil, planRefusal(o, "The evidence pack")
		}
	}
	addon := true
	var addonOffer *license.Offer
	if po != nil {
		addonOffer, _ = po.lacks(license.ComplianceAddon)
		addon = addonOffer == nil
	}
	var wanted, refused []string
	if v, _ := a["frameworks"].(string); strings.TrimSpace(v) != "" {
		for _, id := range strings.Split(v, ",") {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			known := false
			for _, f := range evidenceFrameworks {
				if f.ID == id {
					known = true
					if f.Addon && !addon {
						refused = append(refused, f.Name)
					}
				}
			}
			if !known {
				return nil, fmt.Errorf("unknown framework %s (soc2, iso27001_2022, pci_dss_4_0, eu_cra)", id)
			}
			wanted = append(wanted, id)
		}
	}
	if len(refused) > 0 {
		return nil, planRefusal(addonOffer, strings.Join(refused, " and ")+" evidence")
	}
	format, _ := a["format"].(string)
	if format == "" {
		format = "pdf"
	}
	if format != "pdf" && format != "zip" && format != "json" {
		return nil, fmt.Errorf("format must be pdf, zip or json")
	}
	q := url.Values{"format": {format}}
	for _, k := range []string{"from", "to"} {
		if v, _ := a[k].(string); strings.TrimSpace(v) != "" {
			if _, err := time.Parse(time.DateOnly, strings.TrimSpace(v)); err != nil {
				return nil, fmt.Errorf("%s must be a date (YYYY-MM-DD)", k)
			}
			q.Set(k, strings.TrimSpace(v))
		}
	}
	if len(wanted) > 0 {
		q.Set("frameworks", strings.Join(wanted, ","))
	}
	// A connection limited to a project (or Ask in the project chosen)
	// gets a pack for that project: the browser session that opens the
	// link has no project of its own, and a member who sees only some
	// projects must choose one.
	if id, ok := intArg(a["project_id"]); ok && id > 0 {
		q.Set("project_id", strconv.Itoa(id))
	} else if p := projectFrom(ctx); p > 0 {
		q.Set("project_id", strconv.FormatInt(p, 10))
	}
	frameworks := []map[string]any{}
	for _, f := range evidenceFrameworks {
		in := len(wanted) == 0 && (addon || !f.Addon)
		for _, w := range wanted {
			in = in || w == f.ID
		}
		frameworks = append(frameworks, map[string]any{"id": f.ID, "name": f.Name, "covered_by_plan": addon || !f.Addon, "in_pack": in})
	}
	out := map[string]any{
		"frameworks": frameworks,
		"format":     format,
		"note": "The link works in a browser signed in to Stackurity; each download builds the pack and counts towards the " +
			"limit of 10 packs an hour per organisation. Without from and to the period is the last 90 days.",
	}
	// Only an absolute link: a relative one invites the model to invent a
	// host. Without the server's public address, say where the pack is.
	if base := baseFrom(ctx); strings.HasPrefix(base, "https://") || strings.HasPrefix(base, "http://") {
		out["download_url"] = base + "/api/v1/reports/evidence-pack?" + q.Encode()
	} else {
		out["note"] = "This server has no public address set (STACKURITY_BASE_URL), so there is no link: download the pack in " +
			"Stackurity under Reports → Evidence pack. Each download counts towards the limit of 10 packs an hour per organisation."
	}
	if format == "zip" && addon {
		out["files"] = "The ZIP also holds a CycloneDX SBOM per monitored asset and an OpenVEX document, as they are now."
	}
	return out, nil
}
