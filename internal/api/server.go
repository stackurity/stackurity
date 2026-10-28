// Package api serves the versioned REST API (/api/v1) and the embedded
// dashboard.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/stackurity/stackurity/internal/license"
	"io"
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
	// IngestLimits overrides the upload limits (wire, after gzip) for
	// tests; zero means MaxIngestBody and MaxIngestInflow.
	IngestLimits [2]int64
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
	// WidgetOrigins are origins the dashboard may load scripts and frames
	// from (a hosted edition's sign-up challenge); empty allows none.
	WidgetOrigins []string
	// SlackRespond posts an answer to a Slack response_url (already checked
	// to be Slack's); nil posts it over HTTPS. Tests capture answers here.
	SlackRespond func(ctx context.Context, responseURL string, body []byte) error
	// OpenAIAppsChallenge is served as text/plain at
	// /.well-known/openai-apps-challenge, for OpenAI's domain check when an
	// app is submitted (STACKURITY_OPENAI_APPS_CHALLENGE); empty answers 404.
	OpenAIAppsChallenge string
	// ClientMetadataHTTP fetches OAuth client ID metadata documents; nil
	// uses a client through the outbound address guard. Tests set it.
	ClientMetadataHTTP *http.Client
	// limiter counts sign-in, setup and enrollment attempts in the database,
	// shared by every replica (ratelimit.go).
	limiter *rateLimiter
	// router serves the API to the MCP tools in process (assistants.go).
	router http.Handler
}

func (s *Server) Handler() http.Handler {
	if editionPrepare != nil {
		editionPrepare(s)
	}
	s.limiter = newRateLimiter(s.Store, s.Log)
	r := chi.NewRouter()
	if s.TrustProxy {
		r.Use(middleware.RealIP)
	}
	r.Use(s.instrument, middleware.RequestID, s.recoverer, s.securityHeaders, s.logRequests, assistantCORS)
	s.router = r

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/readyz", s.ready)

	// Routes an edition serves outside the API's session and CSRF checks
	// (signed callbacks from outside services); none in the Community build.
	if editionRootRoutes != nil {
		editionRootRoutes(s, r)
	}

	// AI assistants: the MCP endpoint and OAuth sign-in (assistants.go).
	s.assistantRoutes(r)
	r.Get("/.well-known/openai-apps-challenge", s.openAIAppsChallenge)

	r.Get("/install/agent.sh", s.installScript)
	r.Get("/download/agent/{platform}", s.downloadAgent)

	// Slack's interactivity Request URL. Public, outside the session and
	// CSRF checks (Slack sends neither): every request is verified with the
	// signing secret of the channel it names (slack.go).
	r.With(s.limitAddress("slack-actions", limitSlackActions, "too many requests")).Post("/api/v1/integrations/slack/actions", s.slackActions)
	// The Stackurity Slack app's Event Subscriptions Request URL (uninstall
	// and revoked tokens), verified with the app's signing secret.
	r.With(s.limitAddress("slack-events", limitSlackEvents, "too many requests")).Post("/api/v1/integrations/slack/events", s.slackEvents)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.authenticate, csrfGuard)
		r.Get("/meta", s.meta)
		r.Get("/openapi.json", s.openAPI)
		r.Post("/setup", s.setup)
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		r.Post("/enroll", s.enroll)
		// Following an invitation link: the person may have no account yet.
		r.Post("/invitations/preview", s.previewInvitation)
		r.Post("/invitations/accept", s.acceptInvitation)
		// Following an email confirmation link (email sent by Stackurity):
		// the person may have no account.
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email-recipients/confirm", s.confirmEmailRecipient)
		r.Group(func(r chi.Router) {
			// Single sign-on in the licensed build: the callback exchanges
			// the code with the identity provider, so the whole flow is
			// limited per address here as well.
			r.Use(s.limitAddress("sso-flow", limitSSOFlow, "too many sign-in attempts; wait a minute"))
			s.proPublicRoutes(r)
		})

		r.Group(func(r chi.Router) {
			r.Use(requireAuth, s.projectGate)
			r.Get("/auth/me", s.me)
			r.Put("/auth/default-project", s.setDefaultProject)
			r.Post("/auth/password", s.changePassword)
			r.Post("/feedback", s.sendFeedback)
			// Linking the caller's Slack account (slack.go).
			r.Get("/slack/links", s.listSlackLinks)
			r.Delete("/slack/links/{id}", s.deleteSlackLink)
			r.Post("/slack/links/preview", s.previewSlackLink)
			r.Post("/slack/links/confirm", s.confirmSlackLink)
			// Connecting an AI assistant: the consent page, and the
			// caller's connected assistants (assistants.go).
			r.Post("/oauth/authorize/preview", s.previewAuthorize)
			r.Post("/oauth/authorize", s.decideAuthorize)
			r.Get("/assistants", s.listAssistants)
			r.Patch("/assistants/{id}", s.updateAssistant)
			r.Delete("/assistants/{id}", s.disconnectAssistant)
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
			r.With(requireIngest).Get("/agent/check", s.agentCheck)
			r.Group(func(r chi.Router) {
				r.Use(requireIngest)
				s.proIngestRoutes(r)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleViewer))
				r.Get("/projects", s.listProjects)
				r.Get("/projects/{id}", s.getProject)
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
				r.Get("/second-checks", s.secondChecks)
				r.Get("/findings/{id}/events", s.findingEvents)
				r.Get("/findings/{id}/upgrade", s.findingUpgrade)
				r.Get("/findings/{id}/explain", s.explainFinding)
				r.Get("/reports/outcomes", s.outcomesReport)
				r.Get("/incidents", s.listIncidents)
				r.Get("/incidents/{id}", s.getIncident)
				r.Get("/risk-policy", s.getRiskPolicy)
				r.Get("/settings/fix-grouping", s.getFixGrouping)
				r.Get("/usage", s.assetUsage)
				r.Get("/onboarding/results", s.firstResults)
				r.Get("/checks", s.listChecks)
				r.Get("/checks/{id}", s.getCheck)
				r.Get("/ignore-rules", s.listIgnoreRules)
				// Anyone may ask for an ignore; security and admin decide.
				r.Get("/ignore-requests", s.listIgnoreRequests)
				r.Post("/ignore-requests", s.createIgnoreRequest)
				r.Get("/ignore-requests/{id}", s.getIgnoreRequest)
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
				r.With(s.requireWritable).Post("/integrations/{id}/run", s.runIntegration)
				r.Post("/feeds/{name}/refresh", s.refreshFeed)
				r.With(s.requireWritable).Post("/evaluate", s.reevaluate)
				// security-only actions are checked per action inside
				r.Post("/findings/{id}/actions", s.findingAction)
				r.Post("/findings/actions", s.bulkFindingAction)
				r.Post("/incidents/{id}/actions", s.incidentAction)
				r.With(s.requireWritable).Post("/assets/{id}/check", s.checkAsset)
				r.With(s.requireWritable).Post("/fix-groups/{id}/check", s.checkFixGroup)
				r.Post("/fix-groups/{id}/applied", s.fixApplied)
				r.Get("/users/directory", s.userDirectory)
				r.Get("/jobs/{id}", s.getJob)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleSecurity))
				r.Get("/deliveries", s.listDeliveries)
				r.Get("/channels", s.listChannels)
				r.Get("/routes", s.listRoutes)
				r.Get("/notification-options", s.notificationOptions)
				r.Get("/email-recipients", s.listEmailRecipients)
				r.Post("/ignore-requests/{id}/decision", s.decideIgnoreRequest)
				r.Delete("/ignore-rules/{id}", s.endIgnoreRule)
				s.proSecurityRoutes(r)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleAdmin))
				r.Delete("/assets/{id}", s.deleteAsset)
				r.Post("/projects", s.createProject)
				r.Patch("/projects/{id}", s.updateProject)
				r.Post("/projects/{id}/assets", s.changeProjectAssets(true))
				r.Delete("/projects/{id}/assets", s.changeProjectAssets(false))
				r.Get("/project-suggestions", s.projectSuggestions)
				r.Post("/project-suggestions/dismiss", s.dismissSuggestion)
				r.Get("/access-grants", s.listGrants)
				r.Post("/access-grants", s.createGrant)
				r.Patch("/access-grants/{id}", s.updateGrant)
				r.Delete("/access-grants/{id}", s.deleteGrant)
				r.Get("/conflicts", s.listConflicts)
				r.Post("/conflicts/{id}/resolve", s.resolveConflict)
				r.Get("/users", s.listUsers)
				r.Post("/users", s.createUser)
				r.Patch("/users/{id}", s.updateUser)
				r.Delete("/users/{id}", s.removeMember)
				r.Post("/teams", s.createTeam)
				r.Patch("/teams/{id}", s.updateTeam)
				r.Delete("/teams/{id}", s.deleteTeam)
				r.With(s.requireWritable).Post("/integrations", s.createIntegration)
				r.Patch("/integrations/{id}", s.updateIntegration)
				r.Delete("/integrations/{id}", s.deleteIntegration)
				r.Get("/jobs", s.listJobs)
				r.Get("/plugins", s.listPlugins)
				// Feeds are shared by every workspace: switching one off
				// stops detection for all of them.
				r.With(requireInstanceAdmin).Patch("/feeds/{name}", s.updateFeed)
				r.Put("/risk-policy", s.putRiskPolicy)
				r.Put("/settings/fix-grouping", s.putFixGrouping)
				r.Post("/risk-policy/preview", s.previewRiskPolicy)
				r.Post("/channels", s.createChannel)
				r.Patch("/channels/{id}", s.updateChannel)
				r.Delete("/channels/{id}", s.deleteChannel)
				r.With(s.requireWritable).Post("/channels/{id}/test", s.testChannel)
				r.Post("/routes", s.createRoute)
				r.Put("/routes/{id}", s.updateRoute)
				r.Delete("/routes/{id}", s.deleteRoute)
				r.Post("/email-recipients/resend", s.resendEmailRecipient)
				r.With(s.requireWritable).Post("/integrations/slack/install", s.startSlackInstall)
				r.Post("/integrations/slack/oauth", s.finishSlackInstall)
				r.With(s.requireWritable).Post("/deliveries/{id}/retry", s.retryDelivery)
				s.proAdminRoutes(r)
				r.Get("/secrets", s.listSecrets)
				r.Put("/secrets/{name}", s.putSecret)
				r.Delete("/secrets/{name}", s.deleteSecret)
				r.Get("/onboarding", s.getOnboarding)
				r.Put("/onboarding", s.putOnboarding)
				r.Get("/invitations", s.listInvitations)
				r.Post("/invitations", s.createInvitation)
				r.Delete("/invitations/{id}", s.revokeInvitation)
				r.Get("/enrollments", s.listEnrollments)
				r.With(s.requireWritable).Post("/enrollments", s.createEnrollment)
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
	case errors.Is(err, store.ErrAssetLimit):
		writeError(w, 402, "asset_limit", err.Error())
	case errors.Is(err, store.ErrProjectLimit):
		writeError(w, 402, "project_limit", err.Error())
	case errors.Is(err, store.ErrReadOnly):
		writeError(w, 402, "read_only", err.Error())
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

// withinDays turns a "within N days" parameter into a day count capped at
// ten years; zero or negative means no limit.
func withinDays(d int64) int {
	switch {
	case d <= 0:
		return 0
	case d > 3650:
		return 3650
	}
	return int(d)
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

// openAIAppsChallenge answers OpenAI's domain verification for app
// submission with the configured token, or 404 (never the dashboard).
func (s *Server) openAIAppsChallenge(w http.ResponseWriter, r *http.Request) {
	if s.OpenAIAppsChallenge == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, s.OpenAIAppsChallenge)
}
