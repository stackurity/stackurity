// Package api serves the versioned REST API (/api/v1) and the embedded
// dashboard.
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/license"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/awsconnect"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/githubapp"
	"github.com/stackurity/stackurity/internal/gitlab"
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
	// TrustProxy takes the client address from TrustedProxyHeader on
	// requests whose TCP peer is in TrustedProxies (clientip.go). Other
	// forwarding headers are never read.
	TrustProxy bool
	// TrustedProxyHeader is the header the proxy overwrites with the client
	// address; empty is CF-Connecting-IP. X-Forwarded-For is read from the
	// right, taking the first hop that is not a trusted proxy.
	TrustedProxyHeader string
	// TrustedProxies are the peers allowed to set TrustedProxyHeader; empty
	// is loopback and the private ranges.
	TrustedProxies []netip.Prefix
	// untrustedPeerWarned limits the "header from an untrusted peer" warning
	// to once per process.
	untrustedPeerWarned atomic.Bool
	// Dispatcher sends channel test messages; nil disables them.
	Dispatcher        *notify.Dispatcher
	AllowHTTPWebhooks bool
	Plugins           *plugins.Runner // nil when no plugin directory is configured
	// Cloud is the server's identity towards customers' Google Cloud and
	// Azure accounts; nil offers only the credential fallbacks.
	Cloud *cloudconnect.Platform
	// Pro holds what the licensed edition needs (single sign-on, ...);
	// it is empty in the Community build.
	Pro ProConfig
	// DigitalOceanAPI is the DigitalOcean API base URL for fleet discovery;
	// empty is https://api.digitalocean.com. Tests point it at a fake.
	DigitalOceanAPI string
	// BaseURL is the public dashboard URL, used in the agent installer.
	BaseURL string
	// AgentDir holds agent builds served to new hosts (stackurity-linux-amd64,
	// stackurity-linux-arm64, stackurity-windows-amd64, each with its
	// .sha256); empty disables downloads.
	AgentDir string
	// InviteOnly refuses creating accounts directly (POST /users): people
	// join by invitation, which proves they own their address. Stackurity
	// Cloud sets it, so email sent by Stackurity cannot be pointed at an
	// address through a made-up account.
	InviteOnly bool
	// EmailPreferences: this server sends bulk email (product updates,
	// vulnerability news; internal/notify/bulk.go), so people get email
	// preferences under Your account and on the page their emails link
	// to. A hosted edition sets it.
	EmailPreferences bool
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
	// KeyRequirement holds back the dashboard and API of a self-hosted
	// server until a free Community key or a paid licence is installed
	// (keygate.go); nil requires none (Stackurity Cloud, tests).
	KeyRequirement *license.Requirement
	// Health checks the platform for instance admins; nil disables it.
	Health *health.Checker
	// CoverageGaps builds the instance-wide coverage-gap report
	// (intel.CoverageGaps; the api package cannot import intel); nil
	// disables GET /admin/coverage-gaps.
	CoverageGaps func(ctx context.Context) (any, error)
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
	// FeedbackQueue runs the Stackurity team's feedback queue on this
	// server (feedback_queue.go); nil turns it off, as on every other
	// installation.
	FeedbackQueue *FeedbackQueue
	// WidgetOrigins are origins the dashboard may load scripts and frames
	// from (a hosted edition's sign-up challenge); empty allows none.
	WidgetOrigins []string
	// SlackRespond posts an answer to a Slack response_url (already checked
	// to be Slack's); nil posts it over HTTPS. Tests capture answers here.
	SlackRespond func(ctx context.Context, responseURL string, body []byte) error
	// GitLab is Connect GitLab's OAuth application and GitLab; nil turns
	// it off (gitlab.go).
	GitLab *gitlab.Client
	// GitHubApp is the Stackurity GitHub App ("Install on GitHub"); nil
	// turns it off (github_app.go).
	GitHubApp *githubapp.App
	// OpenAIAppsChallenge is served as text/plain at
	// /.well-known/openai-apps-challenge, for OpenAI's domain check when an
	// app is submitted (STACKURITY_OPENAI_APPS_CHALLENGE); empty answers 404.
	OpenAIAppsChallenge string
	// ClientMetadataHTTP fetches OAuth client ID metadata documents; nil
	// uses a client through the outbound address guard. Tests set it.
	ClientMetadataHTTP *http.Client
	// CIAudience is the aud a CI job's ID token must carry to be exchanged
	// for a collector token (POST /ci/token; STACKURITY_CI_AUDIENCE); empty
	// uses BaseURL, and keyless CI scans are off without either.
	CIAudience string
	// CIOIDCHTTP fetches CI token issuers' discovery documents and keys;
	// nil uses a client through the outbound address guard.
	CIOIDCHTTP *http.Client
	// CIOIDCRootCAs replaces the system roots for those fetches (tests).
	CIOIDCRootCAs *x509.CertPool
	ciKeyCache    *ciKeyCache
	// limiter counts sign-in, setup and enrollment attempts in the database,
	// shared by every replica (ratelimit.go).
	limiter *rateLimiter
	// planCaps caches each organisation's API requests an hour
	// (plan_requests.go).
	planCaps planCapCache
	// router serves the API to the MCP tools in process (assistants.go).
	router http.Handler
	// AccountMail sends password reset links (password_reset.go): the
	// platform's mail on a hosted edition, STACKURITY_SMTP_* otherwise; nil
	// means administrators reset passwords.
	AccountMail notify.Mailer
	// AWS connects AWS accounts with a CloudFormation stack
	// (handlers_aws.go); nil or without a principal turns it off.
	AWS *awsconnect.Client
	// Breached refuses passwords found in data breaches (Pwned Passwords,
	// k-anonymity); nil turns the check off.
	Breached *auth.BreachChecker
	// relyingParty is the WebAuthn relying party for passkeys, made from
	// BaseURL on first use (webauthn.go).
	relyingParty relyingPartyOnce
	// Ask is the in-app assistant (ask.go); nil when no model provider is
	// configured.
	Ask *ask.Engine
	// ClientErrors keeps error reports: what the dashboard reports and the
	// API's own 5xx answers (client_errors.go). False (STACKURITY_CLIENT_ERRORS=off)
	// keeps nothing.
	ClientErrors bool
	serverErrs   serverErrors
	// TrustBadge turns the trust badge on (trust_badge.go): only on
	// Stackurity Cloud with STACKURITY_TRUST_BADGE=on. False registers none
	// of its routes.
	TrustBadge bool
	// TrustBadgePurge drops cached copies of these URLs at the CDN when a
	// badge changes or is turned off; nil relies on the cache headers.
	TrustBadgePurge func(ctx context.Context, urls []string) error
	// TrustPageBase is where trust pages are published
	// (STACKURITY_TRUST_PAGE_BASE); empty is https://stackurity.ai/trust.
	TrustPageBase string
	// mux is the router, for the pattern of an API path a report names.
	mux *chi.Mux
}

func (s *Server) Handler() http.Handler {
	if editionPrepare != nil {
		editionPrepare(s)
	}
	s.limiter = newRateLimiter(s.Store, s.Log)
	if s.Ask != nil && s.Ask.Alert == nil {
		s.Ask.Alert = s.askAlert
	}
	s.ciKeyCache = &ciKeyCache{sets: map[string]*ciIssuerKeys{}}
	r := chi.NewRouter()
	if s.TrustProxy {
		r.Use(s.realIP)
	}
	r.Use(sessionClient, s.instrument, middleware.RequestID, s.captureServerErrors, s.recoverer, s.securityHeaders, s.logRequests, assistantCORS)
	s.router, s.mux = r, r

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
	r.Get("/install/agent-macos.sh", s.installScriptMacOS)
	r.Get("/install/agent.ps1", s.installPowerShell)
	r.Get("/install/kubernetes.yaml", s.installKubernetes)
	// The CloudFormation template for connecting AWS (handlers_aws.go).
	r.Get("/aws/"+awsconnect.TemplateFile, s.awsTemplate)
	r.Get("/download/agent/{platform}", s.downloadAgent)

	// Slack's interactivity Request URL. Public, outside the session and
	// CSRF checks (Slack sends neither): every request is verified with the
	// signing secret of the channel it names (slack.go).
	r.With(s.limitAddress("slack-actions", limitSlackActions, "too many requests")).Post("/api/v1/integrations/slack/actions", s.slackActions)
	// The Stackurity Slack app's Event Subscriptions Request URL (uninstall
	// and revoked tokens), verified with the app's signing secret.
	r.With(s.limitAddress("slack-events", limitSlackEvents, "too many requests")).Post("/api/v1/integrations/slack/events", s.slackEvents)
	// A Launch Stack stack reporting its role. Public, outside the session
	// and CSRF checks (the stack has neither): its bearer token is signed,
	// single use and names the connection (handlers_aws.go).
	r.Post("/api/v1/aws/callback", s.awsCallback)
	// The Slack app's Direct install URL, for installs started from Slack
	// (the Slack Marketplace): signed out, a 302 to Slack's consent page as
	// Slack requires; signed in, the dashboard page that picks the
	// organisation and starts Add to Slack (notify_setup.go).
	r.Get("/integrations/slack/install", s.slackDirectInstall)
	// Connect GitLab: a connected group's webhook, verified with that
	// connection's secret token (gitlab.go).
	r.With(s.limitAddress("gitlab-webhook", limitGitLabWebhook, "too many requests")).Post("/api/v1/integrations/gitlab/webhook/{id}", s.gitlabWebhook)
	// The Stackurity Teams app's messaging endpoint (the Azure Bot's
	// Messaging endpoint): every request carries a Bot Framework JWT for
	// this app, verified before anything else (teams_app.go).
	r.With(s.limitAddress("teams-messages", limitTeamsMessages, "too many requests")).Post("/api/v1/integrations/teams/messages", s.teamsMessages)
	// The Stackurity GitHub App's webhook URL (installation, repositories
	// granted or removed, pushes), verified with the app's webhook secret
	// (github_app.go).
	r.With(s.limitAddress("github-webhook", limitGitHubWebhook, "too many requests")).Post("/api/v1/integrations/github/webhook", s.githubWebhook)
	// One-click unsubscribe and "never email me again" from mail clients
	// (RFC 8058), signed or single-use tokens in the address.
	r.With(s.limitAddress("email-links", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/unsubscribe/one-click", s.oneClick(s.answerUnsubscribe))
	r.With(s.limitAddress("email-links", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/block/one-click", s.oneClick(s.answerBlock))
	// One-click unsubscribe from a category of bulk email (RFC 8058),
	// signed for one person and category (email_preferences.go).
	r.With(s.limitAddress("email-links", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/preferences/one-click", s.oneClickEmailPreferences)

	// The feedback queue's relay intake, status lookups and signed
	// attachment downloads (feedback_queue.go).
	s.feedbackQueueRoutes(r)
	// The trust badge image, public (trust_badge.go; Stackurity Cloud only).
	s.trustBadgePublicRoutes(r)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.authenticate, noteWorkspace, csrfGuard, s.keyGate)
		r.Get("/meta", s.meta)
		r.Get("/openapi.json", s.openAPI)
		r.Route("/public/cves", func(r chi.Router) {
			r.Use(s.limitAddress("public-cves", limitPublicCVEs, "too many requests; wait a minute"))
			r.Get("/", s.publicCVEs)
			r.Get("/recent", s.recentCVEs)
		})
		// Error reports from the dashboard, signed in or not (client_errors.go).
		r.Post("/client-errors", s.clientErrors)
		r.Post("/setup", s.setup)
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)
		s.mfaPublicRoutes(r)
		// The trust page's data, public (trust_badge.go; Stackurity Cloud only).
		s.trustBadgeAPIPublicRoutes(r)
		// Reviewing Ask Stackurity feedback: operators and feedback review
		// tokens, which have no user or organisation (ask_feedback.go).
		s.askFeedbackReviewRoutes(r)
		s.passwordResetRoutes(r)
		r.Post("/enroll", s.enroll)
		// A CI job's OpenID Connect token for a collector token (ci_oidc.go).
		r.Post("/ci/token", s.ciToken)
		// Following an invitation link: the person may have no account yet.
		r.Post("/invitations/preview", s.previewInvitation)
		r.Post("/invitations/accept", s.acceptInvitation)
		// Following an email confirmation link (email sent by Stackurity):
		// the person may have no account.
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email-recipients/confirm", s.confirmEmailRecipient)
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email-recipients/block", s.blockEmail)
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/unsubscribe", s.unsubscribeEmail)
		// The bulk email preference page, from a signed link (no session).
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/preferences", s.linkEmailPreferences)
		r.With(s.limitAddress("email-confirm", limitEmailConfirm, "too many attempts; wait a minute")).Post("/email/preferences/update", s.updateLinkEmailPreferences)
		r.Group(func(r chi.Router) {
			// Single sign-on in the licensed build: the callback exchanges
			// the code with the identity provider, so the whole flow is
			// limited per address here as well.
			r.Use(s.limitAddress("sso-flow", limitSSOFlow, "too many sign-in attempts; wait a minute"))
			s.proPublicRoutes(r)
		})

		r.Group(func(r chi.Router) {
			r.Use(requireAuth, s.projectGate, s.planRequests)
			r.Get("/auth/me", s.me)
			r.Put("/auth/default-project", s.setDefaultProject)
			r.Post("/auth/password", s.changePassword)
			r.Get("/auth/email-preferences", s.myEmailPreferences)
			r.Put("/auth/email-preferences", s.setMyEmailPreferences)
			s.mfaAccountRoutes(r)
			s.accountSessionRoutes(r)
			if editionAccountRoutes != nil {
				editionAccountRoutes(s, r)
			}
			r.Post("/feedback", s.sendFeedback)
			r.Get("/feedback/mine", s.myFeedback)
			// The caller's saved views on dashboard pages (saved_views.go).
			r.Get("/saved-views", s.listSavedViews)
			r.Post("/saved-views", s.saveView)
			r.Delete("/saved-views/{id}", s.deleteSavedView)
			s.feedbackOperatorRoutes(r)
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
			// Ask Stackurity, the in-app assistant (ask.go).
			s.askRoutes(r)
			r.Get("/packs", s.listPacks)
			r.Get("/packs/{id}/archive", s.packArchive)
			r.Route("/admin/license", func(r chi.Router) {
				r.Use(requireInstanceAdmin)
				r.Get("/", s.adminLicense)
				r.Put("/", s.putLicense)
				r.Delete("/", s.deleteLicense)
				// "Get a free key" (keylink.go).
				r.Post("/link", s.startKeyLink)
				r.Post("/link/claim", s.claimKeyLink)
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
			r.With(requireInstanceAdmin).Get("/admin/coverage-gaps", s.adminCoverageGaps)
			r.With(requireInstanceAdmin).Get("/admin/client-errors", s.adminClientErrors)
			r.With(requireInstanceAdmin).Get("/updates", s.updatesStatus)
			r.Get("/workspaces", s.listMyWorkspaces)
			r.Post("/workspaces/{id}/activate", s.activateWorkspace)
			s.trustBadgeAdminRoutes(r)
			r.Route("/admin/workspaces", func(r chi.Router) {
				r.Use(requireInstanceAdmin)
				r.Get("/", s.adminListWorkspaces)
				r.Post("/", s.adminCreateWorkspace)
				r.Patch("/{id}", s.adminUpdateWorkspace)
			})

			r.With(requireIngest).Post("/ingest", s.ingest)
			r.With(requireIngest).Post("/kubernetes/report", s.kubernetesReport)
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
				r.Get("/assets/{id}/link-suggestions", s.assetLinkSuggestions)
				r.Get("/assets/{id}/leaks", s.assetLeaks)
				r.Get("/leaks", s.listLeaks)
				r.Get("/leaks/summary", s.leakSummary)
				r.Get("/assets/{id}/sbom", s.exportSBOM)
				r.Get("/components", s.listComponents)
				r.Get("/components/{id}", s.getComponent)
				r.Get("/components/{id}/intel", s.componentIntel)
				r.Get("/components/{id}/upgrade", s.componentUpgrade)
				r.Get("/findings", s.listFindings)
				r.Get("/findings/summary", s.findingSummary)
				r.Get("/findings/by-asset", s.listFindingsByAsset)
				r.Get("/dashboard/trend", s.dashboardTrend)
				r.Get("/findings/verify", s.verifySince)
				r.Get("/fix-groups", s.listFixGroups)
				r.Get("/fix-groups/summary", s.fixPlanSummary)
				r.Get("/fix-groups/work", s.fixGroupWork)
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
				r.Get("/checks/options", s.checkOptions)
				r.Get("/checks/{id}", s.getCheck)
				r.Get("/ignore-rules", s.listIgnoreRules)
				// VEX (handlers_vex.go): what was imported, and our own
				// decisions as OpenVEX or CycloneDX VEX.
				r.Get("/vex/documents", s.listVEXDocuments)
				r.Get("/vex/documents/{id}", s.getVEXDocument)
				r.Get("/vex/documents/{id}/statements", s.listVEXStatements)
				r.Get("/vex/export", s.exportVEX)
				// Anyone may ask for an ignore; security and admin decide.
				r.Get("/ignore-requests", s.listIgnoreRequests)
				r.Post("/ignore-requests", s.createIgnoreRequest)
				r.Get("/ignore-requests/{id}", s.getIgnoreRequest)
				s.proViewerRoutes(r)
				r.Get("/inventory", s.listInventory)
				r.Get("/inventory/updates", s.inventoryUpdates)
				r.Get("/coverage", s.listCoverage)
				r.Get("/coverage/unchecked", s.uncheckedSummary)
				r.Get("/coverage/overview", s.coverageOverview)
				r.Get("/coverage/assets", s.coverageAssets)
				r.Post("/coverage/support-requests", s.requestSupport)
				r.Get("/teams", s.listTeams)
				r.Get("/owner-rules", s.listOwnerRules)
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
				r.Post("/assets/{id}/link-suggestions/{other}/accept", s.acceptLinkSuggestion)
				r.Post("/assets/{id}/link-suggestions/{other}/dismiss", s.dismissLinkSuggestion)
				r.Get("/integrations", s.listIntegrations)
				r.Get("/integrations/gitlab", s.listGitLab)
				r.Get("/integrations/{id}/images", s.registryImages)
				r.Get("/integrations/github", s.listGitHubInstallations)
				r.With(s.requireWritable).Post("/integrations/{id}/run", s.runIntegration)
				r.Post("/feeds/{name}/refresh", s.refreshFeed)
				r.With(s.requireWritable).Post("/evaluate", s.reevaluate)
				// security-only actions are checked per action inside
				r.Post("/findings/{id}/actions", s.findingAction)
				r.Post("/findings/actions", s.bulkFindingAction)
				// security-only, checked inside like finding actions
				r.Post("/leaks/{id}/dismiss", s.dismissLeak)
				r.Post("/leaks/{id}/undismiss", s.undismissLeak)
				// engineer, checked on the leak's asset like Check again
				r.Post("/leaks/{id}/assign", s.assignLeak)
				r.Post("/leaks/{id}/rotated", s.leakRotated)
				r.With(s.requireWritable).Post("/leaks/{id}/check-again", s.leakCheckAgain)
				r.Post("/incidents/{id}/actions", s.incidentAction)
				r.With(s.requireWritable).Post("/assets/{id}/check", s.checkAsset)
				r.With(s.requireWritable).Post("/fix-groups/{id}/check", s.checkFixGroup)
				r.Post("/fix-groups/{id}/applied", s.fixApplied)
				// A VEX import only asks: its not_affected statements wait
				// for a security or admin user, unless a trusted source's
				// pins all hold (handlers_vex.go).
				r.With(s.requireWritable).Post("/vex/import", s.importVEX)
				r.Get("/users/directory", s.userDirectory)
				r.Get("/jobs/{id}", s.getJob)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleSecurity))
				r.Get("/deliveries", s.listDeliveries)
				r.Get("/channels", s.listChannels)
				r.Get("/routes", s.listRoutes)
				r.Get("/settings/notifications", s.getNotificationSettings)
				// A project's or asset's notifications: security on it reads
				// (the handler checks the role on that project or asset).
				r.Get("/projects/{id}/notifications", s.getScopeNotifications)
				r.Get("/assets/{id}/notifications", s.getScopeNotifications)
				r.Get("/notification-options", s.notificationOptions)
				r.Get("/email-recipients", s.listEmailRecipients)
				r.Post("/ignore-requests/{id}/decision", s.decideIgnoreRequest)
				r.Delete("/ignore-rules/{id}", s.endIgnoreRule)
				r.Post("/vex/documents/{id}/decision", s.decideVEXDocument)
				r.Get("/vex/sources", s.listVEXSources)
				s.proSecurityRoutes(r)
			})
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleAdmin))
				// Trust badges: organisation admins, and project admins for
				// badges within their projects or assets (trust_badge.go).
				s.trustBadgeSettingsRoutes(r)
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
				s.mfaAdminRoutes(r)
				r.Post("/teams", s.createTeam)
				r.Patch("/teams/{id}", s.updateTeam)
				r.Delete("/teams/{id}", s.deleteTeam)
				r.Get("/credentials/health", s.credentialHealth)
				r.Post("/owner-rules", s.createOwnerRule)
				r.Post("/owner-rules/apply", s.applyOwnerRules)
				r.Put("/owner-rules/{id}", s.updateOwnerRule)
				r.Delete("/owner-rules/{id}", s.deleteOwnerRule)
				r.With(s.requireWritable).Post("/integrations", s.createIntegration)
				r.Post("/integrations/registry/discover", s.discoverRegistry)
				r.Patch("/integrations/{id}", s.updateIntegration)
				r.Delete("/integrations/{id}", s.deleteIntegration)
				r.Get("/jobs", s.listJobs)
				r.Get("/plugins", s.listPlugins)
				r.Get("/cloud-setup/gcp", s.cloudSetup("gcp"))
				r.Get("/cloud-setup/azure", s.cloudSetup("azure"))
				// Feeds are shared by every workspace: switching one off
				// stops detection for all of them.
				r.With(requireInstanceAdmin).Patch("/feeds/{name}", s.updateFeed)
				r.Put("/risk-policy", s.putRiskPolicy)
				r.Put("/settings/fix-grouping", s.putFixGrouping)
				r.Put("/settings/notifications", s.putNotificationSettings)
				// A project's or asset's notifications: admin on it changes them
				// (the handlers check the role on that project or asset).
				r.Post("/projects/{id}/notifications/routes", s.createScopeRoute)
				r.Put("/projects/{id}/notifications/routes/{rid}", s.updateScopeRoute)
				r.Delete("/projects/{id}/notifications/routes/{rid}", s.deleteScopeRoute)
				r.Put("/projects/{id}/notifications/inherited/{rid}", s.setInheritedRule)
				r.Post("/projects/{id}/notifications/channels", s.createScopeChannel)
				r.Patch("/projects/{id}/notifications/channels/{cid}", s.updateScopeChannel)
				r.Delete("/projects/{id}/notifications/channels/{cid}", s.deleteScopeChannel)
				r.With(s.requireWritable).Post("/projects/{id}/notifications/channels/{cid}/test", s.testScopeChannel)
				r.Post("/assets/{id}/notifications/routes", s.createScopeRoute)
				r.Put("/assets/{id}/notifications/routes/{rid}", s.updateScopeRoute)
				r.Delete("/assets/{id}/notifications/routes/{rid}", s.deleteScopeRoute)
				r.Put("/assets/{id}/notifications/inherited/{rid}", s.setInheritedRule)
				r.Post("/assets/{id}/notifications/channels", s.createScopeChannel)
				r.Patch("/assets/{id}/notifications/channels/{cid}", s.updateScopeChannel)
				r.Delete("/assets/{id}/notifications/channels/{cid}", s.deleteScopeChannel)
				r.With(s.requireWritable).Post("/assets/{id}/notifications/channels/{cid}/test", s.testScopeChannel)
				r.With(s.requireWritable).Post("/projects/{id}/notifications/slack/install", s.startProjectSlackInstall)
				r.With(s.requireWritable).Post("/projects/{id}/notifications/teams/install", s.startProjectTeamsInstall)
				// Which VEX sources may apply on their own is the admins' call.
				r.Post("/vex/sources", s.saveVEXSource(true))
				r.Patch("/vex/sources/{id}", s.saveVEXSource(false))
				r.Delete("/vex/sources/{id}", s.deleteVEXSource)
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
				r.With(s.requireWritable).Post("/integrations/slack/oauth", s.finishSlackInstall)
				r.With(s.requireWritable).Post("/integrations/gitlab/connect", s.startGitLab)
				r.With(s.requireWritable, s.limitAddress("gitlab-oauth", limitGitLabOAuth, "too many attempts; wait a minute")).Post("/integrations/gitlab/oauth", s.finishGitLabOAuth)
				r.With(s.requireWritable, s.limitAddress("gitlab-oauth", limitGitLabOAuth, "too many attempts; wait a minute")).Post("/integrations/gitlab/connections", s.connectGitLabGroup)
				r.With(s.requireWritable).Post("/integrations/gitlab/connections/{id}/authorize", s.authorizeGitLabConnection)
				r.With(s.requireWritable).Post("/integrations/gitlab/connections/{id}/sync", s.syncGitLabConnection)
				r.Patch("/integrations/gitlab/connections/{id}", s.updateGitLabConnection)
				r.Delete("/integrations/gitlab/connections/{id}", s.disconnectGitLab)
				r.With(s.requireWritable).Post("/integrations/pagerduty/connect", s.startPagerDutyConnect)
				r.With(s.requireWritable).Post("/integrations/pagerduty/oauth", s.finishPagerDutyOAuth)
				r.With(s.requireWritable).Post("/integrations/pagerduty/services", s.listPagerDutyServices)
				r.With(s.requireWritable).Post("/integrations/pagerduty/finish", s.finishPagerDutyConnect)
				r.Post("/integrations/pagerduty/cancel", s.cancelPagerDutyConnect)
				r.With(s.requireWritable).Post("/integrations/teams/install", s.startTeamsInstall)
				r.Get("/integrations/teams/install/{id}", s.teamsInstallStatus)
				r.With(s.requireWritable).Post("/integrations/jira/install", s.startJiraConnect)
				r.With(s.requireWritable).Post("/integrations/jira/oauth", s.finishJiraConnect)
				r.Get("/integrations/jira/connections", s.listJiraConnections)
				r.Delete("/integrations/jira/connections/{id}", s.deleteJiraConnection)
				r.Get("/integrations/jira/connections/{id}/projects", s.listJiraProjects)
				r.Get("/integrations/jira/connections/{id}/projects/{key}", s.getJiraProject)
				r.With(s.requireWritable).Post("/integrations/github/install", s.startGitHubInstall)
				r.With(s.requireWritable).Post("/integrations/github/setup", s.finishGitHubInstall)
				r.With(s.requireWritable).Post("/integrations/github/installations/{installation_id}/sync", s.syncGitHubInstallation)
				r.Delete("/integrations/github/installations/{installation_id}", s.disconnectGitHubInstallation)
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
				r.Get("/enrollments/{id}/uses", s.enrollmentUses)
				r.Get("/integrations/digitalocean", s.doStatus)
				r.With(s.requireWritable).Put("/integrations/digitalocean/token", s.doConnect)
				r.Delete("/integrations/digitalocean/token", s.doDisconnect)
				r.Get("/integrations/digitalocean/droplets", s.doListDroplets)
				r.Delete("/enrollments/{id}", s.revokeEnrollment)
				r.Get("/ci-trusts", s.listCITrusts)
				r.With(s.requireWritable).Post("/ci-trusts", s.createCITrust)
				r.Delete("/ci-trusts/{id}", s.deleteCITrust)
				r.Get("/aws/connections", s.listAWSConnections)
				r.With(s.requireWritable).Post("/aws/connections", s.createAWSConnection)
				r.Get("/aws/connections/{id}", s.getAWSConnection)
				r.Delete("/aws/connections/{id}", s.deleteAWSConnection)
				r.Post("/aws/connections/{id}/launch", s.relaunchAWSConnection)
				r.With(s.requireWritable).Post("/aws/connections/{id}/verify", s.verifyAWSConnection)
				r.Get("/aws/connections/{id}/instances", s.listAWSInstances)
				r.Get("/aws/connections/{id}/installs", s.listAWSInstalls)
				r.With(s.requireWritable).Post("/aws/connections/{id}/installs", s.installAWSAgents)
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
	var refusal *instanceAdminRefusal
	var weak *auth.ErrWeakPassword
	var cooldown *store.CheckCooldownError
	switch {
	case errors.As(err, &refusal):
		refusal.write(w)
	case errors.Is(err, store.ErrPasskeyCounter):
		// A session with a passkey marked meanwhile as possibly copied
		// (store.CreateSessionWith): refused like the sign-in itself.
		passkeyFailed(w, "clone")
	case errors.Is(err, store.ErrSessionEnded):
		// The session was signed out while this request was in flight
		// (rotateSession): it is not given a new ID.
		writeError(w, 401, "unauthorized", "your session has ended; sign in again")
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
	case planLimit(err) != nil:
		writeError(w, 402, "plan_limit", planLimit(err).Error())
	case errors.As(err, &cooldown):
		secs := int(time.Until(cooldown.At).Seconds()) + 1
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, "check_cooldown", err.Error(), "retry_at="+cooldown.At.UTC().Format(time.RFC3339))
	case errors.Is(err, errForbidden):
		writeError(w, 403, "forbidden", err.Error())
	case errors.As(err, &ve):
		writeError(w, 400, "invalid", "validation failed", ve.Problems...)
	case errors.Is(err, errBadRequest):
		writeError(w, 400, "bad_request", err.Error())
	case errors.As(err, &weak):
		// The rules a new password misses (docs/api.md, password_too_weak).
		writeError(w, 400, "password_too_weak", err.Error(), weak.Missing...)
	case errors.Is(err, auth.ErrBadPassword):
		writeError(w, 400, "bad_request", err.Error())
	case errors.Is(err, context.Canceled) && r.Context().Err() != nil:
		// The browser went away (a reload, a closed tab) before the answer:
		// nothing failed here, so it is no server error to log or report.
		// 499 is nginx's "client closed request".
		writeError(w, 499, "client_closed", "request cancelled")
	default:
		s.Log.Error("request failed", "path", r.URL.Path, "err", err, "request_id", middleware.GetReqID(r.Context()))
		noteError(r, "error", err.Error(), "")
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

// planLimit is the plan limit err ran into (store.AsPlanLimit), or nil.
func planLimit(err error) *store.PlanLimitError {
	if pl, ok := store.AsPlanLimit(err); ok {
		return pl
	}
	return nil
}
