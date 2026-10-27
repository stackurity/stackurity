package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

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
	// reportWatermark is the line every report and export carries while the
	// organisation's report mode is trial (reportmode.go). An edition that
	// sets trial mode may name itself here.
	reportWatermark = "Trial — not for distribution"
)
