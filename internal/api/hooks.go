package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
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
	// editionMeta adds what the dashboard needs to know before sign-in to
	// GET /api/v1/meta.
	editionMeta func(s *Server, r *http.Request, meta map[string]any)
	// editionSessionAccess decides whether a browser session may work in
	// workspace ws; nil allows every session. ssoWorkspace is the workspace
	// the session is pinned to (0: an ordinary session). A non-nil answer
	// refuses: the request continues with no workspace, and /auth/me
	// reports why (a workspace that requires its own single sign-on).
	editionSessionAccess func(s *Server, r *http.Request, user *store.User, ws, ssoWorkspace int64) *SSORequired
	// reportWatermark is the line every report and export carries while the
	// organisation's report mode is trial (reportmode.go). An edition that
	// sets trial mode may name itself here.
	reportWatermark = "Trial — not for distribution"
)
