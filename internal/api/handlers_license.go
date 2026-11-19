package api

import (
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// has reports whether a paid feature is on for the request's workspace.
func (s *Server) has(r *http.Request, f license.Feature) bool { return s.Gate.Has(r.Context(), f) }

// planRequired answers a request for a paid feature the workspace's plan
// does not include. 402 lets clients tell it apart from a permissions error.
// The refusal is counted (usage counts, migration 0109). Besides the code
// and its fixed message, the error carries a license.Offer (planOption):
// which plans include the feature and, on Stackurity Cloud, their prices.
// MCP renders it as one line (internal/mcp/offer.go).
func (s *Server) planRequired(w http.ResponseWriter, r *http.Request, f license.Feature) {
	s.planRequiredAs(w, r, f, "")
}

// planRequiredAs is planRequired naming what was asked for (name, such as
// "PCI DSS 4.0 evidence") where it is a part of feature f; "" is f's name.
func (s *Server) planRequiredAs(w http.ResponseWriter, r *http.Request, f license.Feature, name string) {
	s.countUsage(r, store.UsageLimitRefused, "feature_"+string(f))
	o, _ := s.planOption(r, f)
	if name != "" {
		o.FeatureName = name
	}
	writeJSON(w, 402, map[string]apiError{"error": {Code: "plan_required", Message: planMessage(f), Offer: o}})
}

// planMessage is plan_required's fixed message for f.
func planMessage(f license.Feature) string {
	if license.IsAddon(f) {
		return f.Name() + " is not included in this organisation's plan. Ask your administrator to add it."
	}
	ed := "Pro"
	if license.LowestEdition(f) == license.Enterprise {
		ed = "Enterprise"
	}
	return f.Name() + " is part of Stackurity " + ed + ". Ask your administrator to upgrade this workspace."
}

// planOption is the offer for f in the request's workspace, and whether f
// is on there: what a hosted edition knows (editionPlanOffer: its plans,
// prices and trial), or on a self-hosted server the licence editions that
// include f.
func (s *Server) planOption(r *http.Request, f license.Feature) (*license.Offer, bool) {
	o := license.SelfHostedOffer(f)
	p := principal(r)
	if p == nil || p.Workspace <= 0 {
		return o, false
	}
	if editionPlanOffer != nil {
		on, err := editionPlanOffer(s, r, p.Workspace, f, o)
		if err == nil {
			return o, on || s.broughtIn(r, p.Workspace, f)
		}
		// The answer still goes out, with the licence editions only.
		s.Log.Warn("plan offer", "feature", f, "err", err)
		o = license.SelfHostedOffer(f)
	}
	on, err := s.hasFeatureIn(r, p.Workspace, f)
	if err != nil {
		s.Log.Warn("plan offer", "feature", f, "err", err)
	}
	return o, on || s.broughtIn(r, p.Workspace, f)
}

// broughtIn reports whether f is on in workspace ws because an add-on it
// has brings f with it (license.BroughtBy: the Compliance add-on brings
// the evidence pack), so plan options never tell a Starter + Compliance
// organisation it lacks the pack.
func (s *Server) broughtIn(r *http.Request, ws int64, f license.Feature) bool {
	a, ok := license.BroughtBy(f)
	if !ok {
		return false
	}
	on, err := s.hasFeatureIn(r, ws, a)
	return err == nil && on
}

// requireFeature gates a route on a paid feature.
func (s *Server) requireFeature(f license.Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.has(r, f) && !s.broughtByAddon(r, f) {
				s.planRequired(w, r, f)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// broughtWith lists paid features an add-on brings with it on a plan that
// lacks them. The Compliance add-on adds frameworks to the audit evidence
// pack, so it brings the pack: Stackurity Cloud sells it on Starter, whose
// Community edition has no pack of its own (owner, 18 Nov 2026).
var broughtWith = map[license.Feature]license.Feature{license.EvidenceReport: license.ComplianceAddon}

// broughtByAddon reports whether f is on for the request's workspace
// because an add-on the workspace has brings it (broughtWith).
func (s *Server) broughtByAddon(r *http.Request, f license.Feature) bool {
	a, ok := broughtWith[f]
	p := principal(r)
	if !ok || p == nil || p.Workspace <= 0 {
		return false
	}
	on, err := s.hasFeatureIn(r, p.Workspace, a)
	return err == nil && on
}

// adminLicense shows the installation's licence and asset use.
func (s *Server) adminLicense(w http.ResponseWriter, r *http.Request) {
	st := s.Licence.Status()
	n, err := s.Store.CountActiveAssets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// key_link: "Get a free key" works here (keylink.go).
	writeJSON(w, 200, map[string]any{"status": st, "active_assets": n, "managed_by_env": s.LicenceFromEnv,
		"key_link": !s.LicenceFromEnv && !paidLicence(s.Licence) && s.keyLinkBase() != ""})
}

func (s *Server) putLicense(w http.ResponseWriter, r *http.Request) {
	if s.LicenceFromEnv {
		writeError(w, 409, "conflict", "the licence is set by STACKURITY_LICENSE on this server")
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	key := strings.TrimSpace(req.Key)
	l, err := s.parseLicence(key)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	s.installLicence(w, r, key, l, "")
}

// parseLicence verifies a key offline (ParseLicence in tests).
func (s *Server) parseLicence(key string) (*license.License, error) {
	if s.ParseLicence != nil {
		return s.ParseLicence(key)
	}
	return license.Parse(key)
}

// installLicence stores a verified key and applies it; via says how it
// came when not pasted ("key_link": the free-key button).
func (s *Server) installLicence(w http.ResponseWriter, r *http.Request, key string, l *license.License, via string) {
	if err := s.Store.SaveLicenseKey(r.Context(), key, principal(r).User.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.Licence.Set(l)
	details := map[string]any{"customer": l.Customer, "edition": l.Edition, "expires_at": l.ExpiresAt}
	if via != "" {
		details["via"] = via
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "license.install", "license", l.ID, details)
	s.adminLicense(w, r)
}

func (s *Server) deleteLicense(w http.ResponseWriter, r *http.Request) {
	if s.LicenceFromEnv {
		writeError(w, 409, "conflict", "the licence is set by STACKURITY_LICENSE on this server")
		return
	}
	if err := s.Store.DeleteLicenseKey(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.Licence.Set(nil)
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "license.remove", "license", "", nil)
	w.WriteHeader(204)
}

// countUsage adds one to the request's organisation's usage count of event
// and key (store.CountUsage). Best effort: a failure is logged, never
// returned. Requests without an organisation are not counted.
func (s *Server) countUsage(r *http.Request, event, key string) {
	p := principal(r)
	if p == nil || p.Workspace <= 0 {
		return
	}
	if !store.UsageKeyOK(key) {
		key = "other"
	}
	if err := s.Store.CountUsage(r.Context(), p.Workspace, event, key); err != nil {
		s.Log.Warn("usage count", "event", event, "key", key, "err", err)
	}
}
