package api

import (
	"net/http"
	"strings"
)

// keyGate holds back the dashboard and API of a self-hosted server that
// needs its free key (license.Requirement) and has none. What stays open:
//
//   - signing in (everything under /auth/, single sign-on, setting up the
//     first administrator), so an administrator can enter the key;
//   - the key itself (/admin/license; instance administrators only);
//   - /meta and /openapi.json; /healthz, /readyz and the metrics listener
//     are outside the API and never gated;
//   - the data path of agents, CLI scans and CI uploads (enrolment,
//     ingest, SBOM and VEX uploads, scan results, agent checks), so nothing
//     is lost while the key is missing;
//   - links from email (confirming, unsubscribing, preferences).
//
// Everything else answers 403 key_required. AI assistants (/mcp and its
// OAuth endpoints) wait too.
func (s *Server) keyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.KeyRequirement.Blocked() && !keyGateAllows(r, principal(r)) {
			writeError(w, 403, "key_required", "this Stackurity server needs its free key before the dashboard and API can be used. "+
				"An instance administrator can get one at "+s.KeyRequirement.Status().SignupURL+" and enter it under Licence. "+
				"Agents and scans keep sending data meanwhile.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// keyGateAllows lists what works without the key (see keyGate).
func keyGateAllows(r *http.Request, p *Principal) bool {
	path, ok := strings.CutPrefix(r.URL.Path, "/api/v1")
	if !ok {
		return false // /mcp and the assistants' OAuth endpoints
	}
	switch {
	case strings.HasPrefix(path, "/auth/"), strings.HasPrefix(path, "/saml/"):
		return true // signing in, two-factor, password reset, single sign-on
	case path == "/admin/license" || path == "/admin/license/":
		return true // requireInstanceAdmin still applies
	case strings.HasPrefix(path, "/email/"), path == "/email-recipients/confirm", path == "/email-recipients/block":
		return true
	case strings.HasPrefix(path, "/agent/"):
		return true // agent checks and, in the licensed build, its actions
	}
	get, post := r.Method == http.MethodGet, r.Method == http.MethodPost
	switch path {
	case "/meta", "/openapi.json":
		return get
	case "/setup", "/enroll", "/ingest", "/sbom/import":
		return post
	case "/remediation/renovate.json":
		return get
	}
	if get && strings.HasPrefix(path, "/collections/") && strings.HasSuffix(path, "/result") {
		return true // stackurity scan --wait
	}
	// API tokens of CLI scans and CI: --project looks the project up, and
	// pipelines upload VEX. Browser sessions and assistants are not tokens.
	if p != nil && p.Token != nil && p.Assistant == nil && !p.Session {
		if get && (path == "/projects" || isIDPath(path, "/projects/")) {
			return true
		}
		if post && path == "/vex/import" {
			return true
		}
	}
	return false
}

// isIDPath reports whether path is prefix followed by a number.
func isIDPath(path, prefix string) bool {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
