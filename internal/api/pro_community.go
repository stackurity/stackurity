//go:build !ee

package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/license"
)

// The Community build. Paid features (automatic fixing, the evidence report,
// single sign-on) are not compiled in; their endpoints answer 402 so clients
// and the dashboard explain how to get them. The licensed build replaces this
// file (see docs/design/open-core.md).

// ProConfig is empty in the Community build.
type ProConfig struct{}

// Edition of this build.
const BuildEdition = "community"

func needs(f license.Feature) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { planRequired(w, f) }
}

func (s *Server) proPublicRoutes(r chi.Router) {}

func (s *Server) proIngestRoutes(r chi.Router) {
	// Hosts enrolled for remediation poll for changes: there are none.
	r.Get("/agent/actions", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, all([]struct{}{})) })
	r.Get("/remediation/renovate.json", needs(license.Remediation))
}

func (s *Server) proViewerRoutes(r chi.Router) {
	r.Get("/reports/evidence", needs(license.EvidenceReport))
	r.Get("/remediation/plans", needs(license.Remediation))
	r.Get("/assets/{id}/remediation", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, all([]struct{}{})) })
}

func (s *Server) proSecurityRoutes(r chi.Router) {
	r.Get("/remediation/policies", needs(license.Remediation))
	r.Post("/remediation/plans/{id}/decision", needs(license.Remediation))
}

func (s *Server) proAdminRoutes(r chi.Router) {
	r.Post("/remediation/policies", needs(license.Remediation))
	r.Post("/assets/{id}/remediation-token", needs(license.Remediation))
}

// ssoMeta describes single sign-on for the sign-in page; none here.
func (s *Server) ssoMeta(r *http.Request) map[string]any { return nil }
