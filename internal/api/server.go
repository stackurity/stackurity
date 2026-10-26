// Package api serves the versioned REST API (/api/v1) and the embedded
// dashboard.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/stackurity/stackurity/internal/license"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/metrics"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/packs"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
)

type Server struct {
	Store        *store.Store
	Log          *slog.Logger
	Secrets      secrets.Resolver
	Version      string
	SetupToken   string // required for first-admin creation; printed at startup
	CookieSecure bool
	UI           fs.FS // built dashboard; nil serves a placeholder
	// TrustProxy honours X-Forwarded-For / X-Real-IP. Enable only behind a
	// reverse proxy that overwrites those headers.
	TrustProxy bool
	// Dispatcher sends channel test messages; nil disables them.
	Dispatcher        *notify.Dispatcher
	AllowHTTPWebhooks bool
	Plugins           *plugins.Runner // nil when no plugin directory is configured
	// Pro holds what the licensed edition needs (single sign-on, ...);
	// it is empty in the Community build.
	Pro ProConfig
	// BaseURL is the public dashboard URL, used in the agent installer.
	BaseURL string
	// AgentDir holds agent builds served to new hosts (stackurity-linux-amd64
	// and its .sha256); empty disables downloads.
	AgentDir string
	// SecretBox encrypts secrets workspaces store themselves; nil disables
	// stored secrets.
	SecretBox *secrets.Box
	// Packs runs installed stack packs; nil disables them.
	Packs *packs.Manager
	// Licence is the installation's licence; Gate combines it with each
	// workspace's plan to decide which paid features are on. A nil Gate
	// turns every paid feature off.
	Licence        *license.Holder
	Gate           *license.Gate
	LicenceFromEnv bool
	// ParseLicence verifies uploaded keys; nil uses license.Parse.
	ParseLicence func(string) (*license.License, error)
	// Health checks the platform for instance admins; nil disables it.
	Health *health.Checker
	// UpdateCheck is false when the operator turned the release check off
	// (STACKURITY_UPDATE_CHECK=off); GET /updates then says so.
	UpdateCheck bool
	// HTTPMetrics records requests for the metrics listener; nil disables it.
	HTTPMetrics *metrics.HTTP
	// Schema reports when the database was migrated by a newer version while
	// this server runs; /readyz then fails so traffic moves to the new
	// replicas. Nil disables the check.
	Schema *db.SchemaGuard
	// FeedbackURL receives what users send with Send feedback
	// (STACKURITY_FEEDBACK_URL); empty turns feedback off.
	FeedbackURL string
	// FeedbackHTTP forwards feedback; nil uses a client with a 10 second
	// timeout that follows no redirects.
	FeedbackHTTP *http.Client
	// limiter counts sign-in, setup and enrollment attempts in the database,
	// shared by every replica (ratelimit.go).
	limiter *rateLimiter
}

func (s *Server) Handler() http.Handler {
	s.limiter = newRateLimiter(s.Store, s.Log)
	r := chi.NewRouter()
	if s.TrustProxy {
		r.Use(middleware.RealIP)
	}
	r.Use(s.instrument, middleware.RequestID, s.recoverer, securityHeaders, s.logRequests)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/readyz", s.ready)

	r.Get("/install/agent.sh", s.installScript)
	r.Get("/download/agent/{platform}", s.downloadAgent)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.authenticate, csrfGuard)
		r.Get("/meta", s.meta)
		r.Post("/setup", s.setup)
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		r.Post("/enroll", s.enroll)
		r.Group(func(r chi.Router) {
			// Single sign-on in the licensed build: the callback exchanges
			// the code with the identity provider, so the whole flow is
			// limited per address here as well.
			r.Use(s.limitAddress("sso-flow", limitSSOFlow, "too many sign-in attempts; wait a minute"))
			s.proPublicRoutes(r)
		})

		r.Group(func(r chi.Router) {
			r.Use(requireAuth)
			r.Get("/auth/me", s.me)
			r.Post("/auth/password", s.changePassword)
			r.Post("/feedback", s.sendFeedback)
			r.Get("/packs", s.listPacks)
			r.Get("/packs/{id}/archive", s.packArchive)
			r.Route("/admin/license", func(r chi.Router) {
				r.Use(requireInstanceAdmin)
				r.Get("/", s.adminLicense)
				r.Put("/", s.putLicense)
				r.Delete("/", s.deleteLicense)
			})
			r.Route("/admin/packs", func(r chi.Router) {
				r.Use(requireInstanceAdmin)
				r.Get("/", s.adminPacks)
				r.Post("/install", s.installPack)
				r.Post("/upload", s.uploadPack)
				r.Patch("/{id}", s.updatePack)
				r.Post("/{id}/rollback", s.rollbackPack)
				r.Delete("/{id}", s.removePack)
			})
			r.With(requireInstanceAdmin).Get("/admin/health", s.adminHealth)
			r.With(requireInstanceAdmin).Get("/updates", s.updatesStatus)
			r.Get("/workspaces", s.listMyWorkspaces)
			r.Post("/workspaces/{id}/activate", s.activateWorkspace)
			r.Route("/admin/workspaces", func(r chi.Router) {
				r.Use(requireInstanceAdmin)
				r.Get("/", s.adminListWorkspaces)
				r.Post("/", s.adminCreateWorkspace)
				r.Patch("/{id}", s.adminUpdateWorkspace)
			})

			r.With(requireIngest).Post("/ingest", s.ingest)
			r.With(requireIngest).Get("/collections/{id}/result", s.collectionResult)
			r.With(requireIngest).Post("/sbom/import", s.importSBOM)
			r.Group(func(r chi.Router) {
				r.Use(requireIngest)
				s.proIngestRoutes(r)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleViewer))
				r.Get("/overview", s.overview)
				r.Get("/facets", s.facets)
				r.Get("/search", s.search)
				r.Get("/assets", s.listAssets)
				r.Get("/assets/{id}", s.getAsset)
				r.Get("/assets/{id}/inventory", s.assetInventory)
				r.Get("/assets/{id}/coverage", s.assetCoverage)
				r.Get("/assets/{id}/coverage-summary", s.assetCoverageSummary)
				r.Get("/assets/{id}/collections", s.assetCollections)
				r.Get("/assets/{id}/relations", s.assetRelations)
				r.Get("/assets/{id}/drift", s.assetDrift)
				r.Get("/assets/{id}/stack", s.assetStack)
				r.Get("/assets/{id}/sbom", s.exportSBOM)
				r.Get("/components", s.listComponents)
				r.Get("/components/{id}", s.getComponent)
				r.Get("/components/{id}/intel", s.componentIntel)
				r.Get("/components/{id}/upgrade", s.componentUpgrade)
				r.Get("/findings", s.listFindings)
				r.Get("/findings/summary", s.findingSummary)
				r.Get("/findings/verify", s.verifySince)
				r.Get("/fix-groups", s.listFixGroups)
				r.Get("/fix-groups/summary", s.fixPlanSummary)
				r.Get("/fix-groups/{id}", s.getFixGroup)
				r.Get("/findings/{id}", s.getFinding)
				r.Get("/advisories/{key}", s.getAdvisory)
				r.Get("/feeds", s.listFeeds)
				r.Get("/evaluation-gaps", s.listEvaluationGaps)
				r.Get("/findings/{id}/events", s.findingEvents)
				r.Get("/findings/{id}/upgrade", s.findingUpgrade)
				r.Get("/findings/{id}/explain", s.explainFinding)
				r.Get("/reports/outcomes", s.outcomesReport)
				r.Get("/incidents", s.listIncidents)
				r.Get("/incidents/{id}", s.getIncident)
				r.Get("/risk-policy", s.getRiskPolicy)
				s.proViewerRoutes(r)
				r.Get("/inventory", s.listInventory)
				r.Get("/coverage", s.listCoverage)
				r.Get("/teams", s.listTeams)
				r.Get("/audit", s.listAudit)
				r.Get("/tokens", s.listTokens)
				r.Post("/tokens", s.createToken)
				r.Delete("/tokens/{id}", s.revokeToken)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleEngineer))
				r.Patch("/assets/{id}", s.updateAsset)
				r.Post("/assets/{id}/relations", s.addRelation)
				r.Delete("/assets/{id}/relations", s.deleteRelation)
				r.Get("/integrations", s.listIntegrations)
				r.Post("/integrations/{id}/run", s.runIntegration)
				r.Post("/feeds/{name}/refresh", s.refreshFeed)
				r.Post("/evaluate", s.reevaluate)
				// security-only actions are checked per action inside
				r.Post("/findings/{id}/actions", s.findingAction)
				r.Post("/findings/actions", s.bulkFindingAction)
				r.Post("/incidents/{id}/actions", s.incidentAction)
				r.Get("/users/directory", s.userDirectory)
				r.Get("/jobs/{id}", s.getJob)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleSecurity))
				r.Get("/deliveries", s.listDeliveries)
				r.Get("/channels", s.listChannels)
				r.Get("/routes", s.listRoutes)
				s.proSecurityRoutes(r)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleAdmin))
				r.Delete("/assets/{id}", s.deleteAsset)
				r.Get("/conflicts", s.listConflicts)
				r.Post("/conflicts/{id}/resolve", s.resolveConflict)
				r.Get("/users", s.listUsers)
				r.Post("/users", s.createUser)
				r.Patch("/users/{id}", s.updateUser)
				r.Delete("/users/{id}", s.removeMember)
				r.Post("/teams", s.createTeam)
				r.Patch("/teams/{id}", s.updateTeam)
				r.Delete("/teams/{id}", s.deleteTeam)
				r.Post("/integrations", s.createIntegration)
				r.Patch("/integrations/{id}", s.updateIntegration)
				r.Delete("/integrations/{id}", s.deleteIntegration)
				r.Get("/jobs", s.listJobs)
				r.Get("/plugins", s.listPlugins)
				// Feeds are shared by every workspace: switching one off
				// stops detection for all of them.
				r.With(requireInstanceAdmin).Patch("/feeds/{name}", s.updateFeed)
				r.Put("/risk-policy", s.putRiskPolicy)
				r.Post("/risk-policy/preview", s.previewRiskPolicy)
				r.Post("/channels", s.createChannel)
				r.Patch("/channels/{id}", s.updateChannel)
				r.Delete("/channels/{id}", s.deleteChannel)
				r.Post("/channels/{id}/test", s.testChannel)
				r.Post("/routes", s.createRoute)
				r.Put("/routes/{id}", s.updateRoute)
				r.Delete("/routes/{id}", s.deleteRoute)
				r.Post("/deliveries/{id}/retry", s.retryDelivery)
				s.proAdminRoutes(r)
				r.Get("/secrets", s.listSecrets)
				r.Put("/secrets/{name}", s.putSecret)
				r.Delete("/secrets/{name}", s.deleteSecret)
				r.Get("/enrollments", s.listEnrollments)
				r.Post("/enrollments", s.createEnrollment)
				r.Delete("/enrollments/{id}", s.revokeEnrollment)
			})
		})
		r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "not_found", "no such endpoint") })
	})
	r.Handle("/*", s.uiHandler())
	return r
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		writeError(w, 503, "database_unavailable", "database is not reachable")
		return
	}
	if err := s.Schema.Err(); err != nil {
		writeError(w, 503, "schema_newer", err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}

// --- helpers

type apiError struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string, details ...string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg, Details: details}})
}

// fail maps store and validation errors to HTTP responses; anything
// unexpected is logged and returned as a generic 500.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *model.ValidationError
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "not_found", "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, 409, "conflict", err.Error())
	case errors.Is(err, store.ErrInvalid):
		writeError(w, 400, "bad_request", err.Error())
	case errors.Is(err, errForbidden):
		writeError(w, 403, "forbidden", err.Error())
	case errors.As(err, &ve):
		writeError(w, 400, "invalid", "validation failed", ve.Problems...)
	case errors.Is(err, errBadRequest):
		writeError(w, 400, "bad_request", err.Error())
	case errors.Is(err, auth.ErrBadPassword):
		writeError(w, 400, "bad_request", err.Error())
	default:
		s.Log.Error("request failed", "path", r.URL.Path, "err", err, "request_id", middleware.GetReqID(r.Context()))
		writeError(w, 500, "internal", "internal error")
	}
}

var errBadRequest = errors.New("bad request")

var errForbidden = errors.New("forbidden")

func forbidden(msg string) error { return &wrapped{msg, errForbidden} }

func badRequest(msg string) error { return &wrapped{msg, errBadRequest} }

type wrapped struct {
	msg string
	err error
}

func (w *wrapped) Error() string { return w.msg }
func (w *wrapped) Unwrap() error { return w.err }

const maxJSONBody = 1 << 20

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON body: " + err.Error())
	}
	return nil
}

func idParam(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		return 0, badRequest("invalid " + name)
	}
	return id, nil
}

func page(r *http.Request) store.Page {
	q := r.URL.Query()
	l, _ := strconv.Atoi(q.Get("limit"))
	o, _ := strconv.Atoi(q.Get("offset"))
	return store.Page{Limit: l, Offset: o}
}

func qInt(r *http.Request, k string) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get(k), 10, 64)
	return v
}

func qBool(r *http.Request, k string) *bool {
	switch strings.ToLower(r.URL.Query().Get(k)) {
	case "true", "1", "yes":
		b := true
		return &b
	case "false", "0", "no":
		b := false
		return &b
	}
	return nil
}

type list[T any] struct {
	Items  []T   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit,omitempty"`
	Offset int   `json:"offset,omitempty"`
}

func paged[T any](items []T, total int64, p store.Page) list[T] {
	if items == nil {
		items = []T{}
	}
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	return list[T]{Items: items, Total: total, Limit: p.Limit, Offset: p.Offset}
}

func all[T any](items []T) list[T] {
	if items == nil {
		items = []T{}
	}
	return list[T]{Items: items, Total: int64(len(items))}
}
