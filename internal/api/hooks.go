package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// SSORequired explains why a session cannot work in a workspace: the
// workspace requires sign-in through its own identity provider.
type SSORequired struct {
	WorkspaceID   int64  `json:"workspace_id"`
	WorkspaceName string `json:"workspace_name"`
	LoginURL      string `json:"login_url"`
}

// Hooks an edition built on the core (docs/design/open-core.md) may set from
// an init function. Each is nil in the Community build, and nil does nothing,
// so an edition that does not use one needs no code for it.
var (
	// editionPrepare runs at the start of Handler, before any middleware is
	// set up, to adjust the server from the edition's configuration (for
	// example WidgetOrigins).
	editionPrepare func(s *Server)
	// editionRootRoutes adds routes outside /api/v1, so outside the session
	// and CSRF checks: callbacks from outside services that prove who they
	// are some other way (a signature).
	editionRootRoutes func(s *Server, r chi.Router)
	// editionAccountRoutes adds routes under /api/v1 for the caller's own
	// account: any signed-in person, whatever their role (Stackurity
	// Cloud's connected sign-ins). An edition lists each in projectRoutes
	// as accountScope, so assistants cannot change them.
	editionAccountRoutes func(s *Server, r chi.Router)
	// editionMeta adds what the dashboard needs to know before sign-in to
	// GET /api/v1/meta.
	editionMeta func(s *Server, r *http.Request, meta map[string]any)
	// editionSessionAccess decides whether a browser session may work in
	// workspace ws; nil allows every session. ssoWorkspace is the workspace
	// the session is pinned to (0: an ordinary session). A non-nil answer
	// refuses: the request continues with no workspace, and /auth/me
	// reports why (a workspace that requires its own single sign-on).
	editionSessionAccess func(s *Server, r *http.Request, user *store.User, ws, ssoWorkspace int64) *SSORequired
	// editionSSORequiredFor reports whether workspace ws requires userID
	// to sign in with its own single sign-on (an organisation's owner is
	// exempt); nil: never. Sessions are checked by editionSessionAccess; an
	// API token is not a session, so the requests a token could use to
	// get around the requirement (making tokens, changing single sign-on)
	// ask this (tokenUnderRequiredSSO).
	editionSSORequiredFor func(s *Server, r *http.Request, ws, userID int64) (bool, error)
	// editionHasFeature decides whether a paid feature is on for workspace
	// ws where the edition sets each organisation's plan itself (a hosted
	// edition's billing); nil uses the licence and the workspace's plan
	// (Gate). The key a hosted plan lists is the feature's value, such as
	// "phishing_resistant_mfa".
	editionHasFeature func(s *Server, r *http.Request, ws int64, f license.Feature) (bool, error)
	// reportWatermark is the line every report and export carries while the
	// organisation's report mode is trial (reportmode.go). An edition that
	// sets trial mode may name itself here.
	reportWatermark = "Trial — not for distribution"
)

// tokenUnderRequiredSSO reports whether p is a person's API token in a
// workspace that requires that person to sign in with its own single
// sign-on. Such a token keeps reading (the admin chose to keep it), but
// cannot make new tokens or change single sign-on. Machine tokens
// (collector, CI) have no user and are never refused here.
func (s *Server) tokenUnderRequiredSSO(r *http.Request, p *Principal) (bool, error) {
	if editionSSORequiredFor == nil || p == nil || p.Token == nil || p.User == nil || p.Workspace <= 0 {
		return false, nil
	}
	return editionSSORequiredFor(s, r, p.Workspace, p.User.ID)
}

// ssoRequiredForToken is the refusal of tokenUnderRequiredSSO.
func ssoRequiredForToken(w http.ResponseWriter, what string) {
	writeError(w, 403, "sso_required", "this organisation requires single sign-on: "+what+" from a single sign-on session, not with an API token")
}

// hasFeatureIn reports whether paid feature f is on for workspace ws.
func (s *Server) hasFeatureIn(r *http.Request, ws int64, f license.Feature) (bool, error) {
	if editionHasFeature != nil {
		return editionHasFeature(s, r, ws, f)
	}
	return s.Gate.Has(tenant.WithWorkspace(r.Context(), ws), f), nil
}
