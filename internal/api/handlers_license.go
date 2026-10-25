package api

import (
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/tenant"
)

// has reports whether a paid feature is on for the request's workspace.
func (s *Server) has(r *http.Request, f license.Feature) bool { return s.Gate.Has(r.Context(), f) }

// planRequired answers a request for a paid feature the workspace's plan
// does not include. 402 lets clients tell it apart from a permissions error.
func planRequired(w http.ResponseWriter, f license.Feature) {
	writeError(w, 402, "plan_required", featureName(f)+" is part of Stackurity Pro. Ask your administrator to upgrade this workspace.")
}

func featureName(f license.Feature) string {
	switch f {
	case license.Remediation:
		return "Automatic fixing"
	case license.Teams:
		return "Working with several teams"
	case license.EvidenceReport:
		return "The evidence report"
	case license.SSO:
		return "Single sign-on"
	case license.EnterprisePacks:
		return "This stack pack (Enterprise)"
	}
	return string(f)
}

// requireFeature gates a route on a paid feature.
func (s *Server) requireFeature(f license.Feature) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.has(r, f) {
				planRequired(w, f)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// adminLicense shows the installation's licence and asset use.
func (s *Server) adminLicense(w http.ResponseWriter, r *http.Request) {
	st := s.Licence.Status()
	n, err := s.Store.CountActiveAssets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": st, "active_assets": n, "managed_by_env": s.LicenceFromEnv})
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
	parse := s.ParseLicence
	if parse == nil {
		parse = license.Parse
	}
	l, err := parse(strings.TrimSpace(req.Key))
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	if err := s.Store.SaveLicenseKey(r.Context(), strings.TrimSpace(req.Key), principal(r).User.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.Licence.Set(l)
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "license.install", "license", l.ID,
		map[string]any{"customer": l.Customer, "edition": l.Edition, "expires_at": l.ExpiresAt})
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
