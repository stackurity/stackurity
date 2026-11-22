package api_test

import (
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
)

// plan_required keeps its code and a fixed message, and carries the offer:
// the editions that include the feature on a self-hosted server, never a
// price or trial (the server does not know them) and never a checkout.
func TestPlanRequiredCarriesOffer(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	e.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Community, ExpiresAt: time.Now().AddDate(1, 0, 0)})

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			license.Offer
		} `json:"error"`
	}
	if code := view.do("GET", "/api/v1/findings?reachability=not_reached", nil, &body); code != 402 {
		t.Fatalf("status %d", code)
	}
	o := body.Error
	if o.Code != "plan_required" || o.Message != "Reachability is part of Stackurity Pro. Ask your administrator to upgrade this workspace." ||
		o.Feature != license.Reachability || o.FeatureName != "Reachability" || o.Hosted || len(o.IncludedIn) != 2 || o.IncludedIn[0] != "Pro" ||
		o.Plan != nil || o.Addon != nil || o.TrialAvailable || o.PlansURL != license.PlansURL {
		t.Errorf("402 body: %+v", body)
	}
}

func TestPlanOptions(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	type feat struct {
		Feature     license.Feature `json:"feature"`
		Description string          `json:"description"`
		Offer       *license.Offer  `json:"offer"`
	}
	var po struct {
		Edition     license.Edition `json:"edition"`
		Included    []feat          `json:"included"`
		NotIncluded []feat          `json:"not_included"`
		PlansURL    string          `json:"plans_url"`
	}
	e.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Pro, ExpiresAt: time.Now().AddDate(1, 0, 0)})
	if code := view.do("GET", "/api/v1/plan/options", nil, &po); code != 200 {
		t.Fatalf("status %d", code)
	}
	has := func(list []feat, f license.Feature) *feat {
		for i := range list {
			if list[i].Feature == f {
				return &list[i]
			}
		}
		return nil
	}
	if po.Edition != license.Pro || has(po.Included, license.Reachability) == nil || has(po.Included, license.EvidenceReport) == nil {
		t.Errorf("included on Pro: %+v", po)
	}
	addon := has(po.NotIncluded, license.ComplianceAddon)
	if addon == nil || addon.Offer == nil || addon.Offer.Addon == nil || addon.Offer.Addon.Name != "Compliance add-on" ||
		addon.Offer.Addon.Price != "" || addon.Offer.TrialAvailable || addon.Description == "" {
		t.Errorf("Compliance add-on on Pro: %+v", addon)
	}
	if f := has(po.NotIncluded, license.PhishingResistantMFA); f == nil || len(f.Offer.IncludedIn) != 1 || f.Offer.IncludedIn[0] != "Enterprise" {
		t.Errorf("an Enterprise feature: %+v", f)
	}
	if len(po.Included)+len(po.NotIncluded) != len(license.PaidFeatures()) || po.PlansURL != license.PlansURL {
		t.Errorf("features: %+v", po)
	}
}
