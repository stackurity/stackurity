package api

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

// The trust badge's public image and trust data, its settings and the
// operators' evidence viewer (docs/trust-badge.md). A Stackurity Cloud
// feature: none of these routes exist unless the server runs as Stackurity
// Cloud with STACKURITY_TRUST_BADGE=on (Server.TrustBadge), so a self-hosted
// server answers 404 to all of them.

// TrustBadgeTermsVersion names the badge terms the acceptance checkbox
// shows: draft 2 of the legal review brief, signed off for launch on
// 11 Nov 2026. Change the version whenever the wording changes; every badge
// then needs the new terms accepted before it is turned on again.
const TrustBadgeTermsVersion = "2026-11"

// TrustBadgeTermsText is the acceptance checkbox (draft 2 of the legal
// review brief, signed off 11 Nov 2026).
const TrustBadgeTermsText = "I'm authorised to publish this badge for my organisation and I accept the Trust badge terms " +
	"(section 14 of the Terms of Service). I understand the badge is a monitoring status, not a security certification, " +
	"and we won't describe it as one, or as a guarantee, audit or endorsement by Stackurity. We're responsible for how we " +
	"display and describe it, and for removing it when it ends. Stackurity may change or turn off the badge at any time."

// trustBadgeAlt is the badge image's title and the snippets' alt text.
const (
	trustBadgeAlt          = "Monitored by Stackurity. Not a security certification."
	trustBadgeNotActiveAlt = "Stackurity badge not active."
)

// trustStatusMaxAge: a last decision older than this is not trusted, and
// the badge shows as not active (the evaluator decides hourly).
const trustStatusMaxAge = 2 * time.Hour

// TrustBadgePlan is what the organisation's plan allows. The Community
// build (and Stackurity Cloud's Free plan) gets freeTrustBadgePlan; the
// licensed Cloud build sets trustBadgePlan.
type TrustBadgePlan struct {
	// HideMarketing: the "Monitor yours, free →" line and the trust page's
	// sign-up button may be switched off.
	HideMarketing bool `json:"hide_marketing"`
	// MaxBadges is how many badges the organisation may have.
	MaxBadges int `json:"max_badges"`
	// Logo: the trust page may show the customer's logo.
	Logo bool `json:"logo"`
}

var freeTrustBadgePlan = TrustBadgePlan{MaxBadges: 1}

// trustBadgePlan returns the plan of the workspace in ctx; nil is the
// Free plan for everyone. The licensed Cloud build sets it.
var trustBadgePlan func(s *Server, ctx context.Context) TrustBadgePlan

func (s *Server) trustPlan(ctx context.Context) TrustBadgePlan {
	if trustBadgePlan == nil {
		return freeTrustBadgePlan
	}
	p := trustBadgePlan(s, ctx)
	if p.MaxBadges < 1 {
		p.MaxBadges = 1
	}
	return p
}

// trustBadgeRoutes registers the public routes outside /api/v1.
// Off, /badge/ answers 404 rather than the dashboard's page.
func (s *Server) trustBadgePublicRoutes(r chi.Router) {
	if !s.TrustBadge {
		r.Get("/badge/{file}", func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "not_found", "not found") })
		return
	}
	r.With(s.limitAddress("trust-badge", limitTrustBadge, "too many requests; wait a minute")).Get("/badge/{file}", s.trustBadgeSVG)
}

// trustBadgeAPIPublicRoutes registers the public routes under /api/v1.
func (s *Server) trustBadgeAPIPublicRoutes(r chi.Router) {
	if !s.TrustBadge {
		return
	}
	r.Route("/public/trust", func(r chi.Router) {
		r.Use(s.limitAddress("public-trust", limitTrustBadge, "too many requests; wait a minute"))
		r.Get("/", s.listedTrustPages)
		r.Get("/{slug}", s.publicTrustPage)
		r.Get("/{slug}/logo", s.publicTrustLogo)
	})
}

// trustBadgeSettingsRoutes registers the settings routes (organisation
// admins, and project admins for badges within their projects or assets).
func (s *Server) trustBadgeSettingsRoutes(r chi.Router) {
	if !s.TrustBadge {
		return
	}
	r.Get("/trust-badges", s.listTrustBadges)
	r.Post("/trust-badges", s.createTrustBadge)
	r.Put("/trust-badges/{id}", s.updateTrustBadge)
	r.Delete("/trust-badges/{id}", s.deleteTrustBadge)
	r.Post("/trust-badges/{id}/terms", s.acceptTrustBadgeTerms)
	r.Post("/trust-badges/{id}/enabled", s.setTrustBadgeEnabled)
	r.Put("/trust-badges/{id}/logo", s.putTrustBadgeLogo)
	r.Delete("/trust-badges/{id}/logo", s.deleteTrustBadgeLogo)
	r.Get("/trust-badges/{id}/preview", s.previewTrustBadge)
	r.Get("/trust-badges/{id}/history", s.trustBadgeHistory)
}

// trustBadgeAdminRoutes registers the operators' evidence viewer.
func (s *Server) trustBadgeAdminRoutes(r chi.Router) {
	if !s.TrustBadge {
		return
	}
	r.With(requireInstanceAdmin).Get("/admin/trust-badges", s.adminTrustBadges)
	r.With(requireInstanceAdmin).Get("/admin/trust-badges/{id}/history", s.adminTrustBadgeHistory)
}

// --- public output

// trustPublic is the trust page's data (GET /api/v1/public/trust/{slug}),
// the contract the website renders. It never carries ids, counts, package,
// host, repository or image names, or an item the customer switched off.
type trustPublic struct {
	Slug             string     `json:"slug"`
	Name             string     `json:"name"`
	WebsiteURL       *string    `json:"website_url"`
	LogoURL          *string    `json:"logo_url"`
	State            string     `json:"state"`
	LastEvaluatedAt  *time.Time `json:"last_evaluated_at"`
	Kinds            []string   `json:"kinds"`
	UnsupportedKinds []string   `json:"unsupported_kinds"`
	ShowMarketing    bool       `json:"show_marketing"`
	Listed           bool       `json:"listed"`
	RuleVersion      string     `json:"rule_version"`
}

// trustKindNames turns asset kinds into the kinds the trust page may name.
var trustKindNames = map[string]string{
	"host": "servers", "repository": "repositories", "image": "images", "application": "applications", "workload": "applications",
}

var trustKindOrder = []string{"servers", "repositories", "images", "applications"}

// trustUnsupportedPhrase makes a broad kind of software read after
// "including some …" on the trust page; "" drops it.
func trustUnsupportedPhrase(k string) string {
	k = strings.TrimSpace(k)
	switch k {
	case "":
		return ""
	case "WordPress core":
		k = "WordPress core releases"
	}
	if len(k) > 60 || strings.ContainsAny(k, "<>{}\n") {
		return ""
	}
	return k
}

// trustActive reports whether the badge says "Monitored by Stackurity" now:
// on, its last decision active, recent, and with a real evaluation time.
func trustActive(p *store.PublicTrustBadge, now time.Time) bool {
	return p.Badge.Enabled && p.Decision != nil && p.DecidedAt != nil && p.Decision.Result == trustbadge.Active &&
		now.Sub(*p.DecidedAt) <= trustStatusMaxAge && p.Decision.OldestEvaluated != nil
}

// trustAnswer builds the public answer for a badge; the plan limits what
// may be shown whatever the switches say.
func (s *Server) trustAnswer(p *store.PublicTrustBadge, plan TrustBadgePlan, now time.Time) trustPublic {
	b := p.Badge
	out := trustPublic{Slug: b.Slug, Name: b.DisplayName, State: trustbadge.NotActive, UnsupportedKinds: []string{},
		ShowMarketing: b.ShowMarketing || !plan.HideMarketing, Listed: b.Listed, RuleVersion: trustbadge.RuleVersion}
	if out.Name == "" {
		out.Name = p.WorkspaceName
	}
	if b.ShowLogo {
		if b.WebsiteURL != "" {
			u := b.WebsiteURL
			out.WebsiteURL = &u
		}
		if b.HasLogo && plan.Logo {
			u := strings.TrimRight(s.BaseURL, "/") + "/api/v1/public/trust/" + b.Slug + "/logo"
			out.LogoURL = &u
		}
	}
	if p.Decision != nil && p.Decision.RuleVersion != "" {
		out.RuleVersion = p.Decision.RuleVersion
	}
	if !trustActive(p, now) {
		return out
	}
	out.State = trustbadge.Active
	t := p.Decision.OldestEvaluated.UTC()
	out.LastEvaluatedAt = &t
	for _, k := range p.Decision.UnsupportedKinds {
		if ph := trustUnsupportedPhrase(k); ph != "" && !slices.Contains(out.UnsupportedKinds, ph) {
			out.UnsupportedKinds = append(out.UnsupportedKinds, ph)
		}
	}
	if b.ShowKinds {
		seen := map[string]bool{}
		for _, k := range p.ScopeKinds {
			if n := trustKindNames[k]; n != "" {
				seen[n] = true
			}
		}
		out.Kinds = []string{}
		for _, k := range trustKindOrder {
			if seen[k] {
				out.Kinds = append(out.Kinds, k)
			}
		}
	}
	return out
}

// planFor is the plan of the badge's organisation.
func (s *Server) planFor(ctx context.Context, ws int64) TrustBadgePlan {
	return s.trustPlan(tenant.WithWorkspace(ctx, ws))
}

// publicTrustPage answers GET /api/v1/public/trust/{slug}: 404 when the
// slug is unknown or the badge is off.
func (s *Server) publicTrustPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.PublicTrustBadge(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p == nil || !p.Badge.Enabled {
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeError(w, 404, "not_found", "no trust page at this address")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=900")
	writeJSON(w, 200, s.trustAnswer(p, s.planFor(r.Context(), p.WorkspaceID), time.Now()))
}

// listedTrustPages answers GET /api/v1/public/trust?listed=1: the slugs of
// badges that are on, listed in search engines and active (the website's
// sitemap).
func (s *Server) listedTrustPages(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("listed") != "1" {
		writeError(w, 400, "bad_request", "only ?listed=1 is supported")
		return
	}
	all, err := s.Store.ListedTrustBadges(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now()
	slugs := []string{}
	for _, p := range all {
		if trustActive(p, now) {
			slugs = append(slugs, p.Badge.Slug)
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=900")
	writeJSON(w, 200, map[string][]string{"slugs": slugs})
}

// publicTrustLogo answers GET /api/v1/public/trust/{slug}/logo.
func (s *Server) publicTrustLogo(w http.ResponseWriter, r *http.Request) {
	p, err := s.Store.PublicTrustBadge(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p == nil || !p.Badge.Enabled || !p.Badge.ShowLogo || !p.Badge.HasLogo || !s.planFor(r.Context(), p.WorkspaceID).Logo {
		writeError(w, 404, "not_found", "no logo")
		return
	}
	data, typ, err := s.Store.TrustBadgeLogo(r.Context(), p.Badge.Slug)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if data == nil {
		writeError(w, 404, "not_found", "no logo")
		return
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Cache-Control", "public, max-age=900")
	_, _ = w.Write(data)
}

// trustBadgeSVG answers GET /badge/{slug}.svg?theme=light|dark&time=1.
// An unknown, switched-off or not active badge is the grey "not active"
// image, never an error page, so an embed never breaks.
func (s *Server) trustBadgeSVG(w http.ResponseWriter, r *http.Request) {
	slug, ok := strings.CutSuffix(chi.URLParam(r, "file"), ".svg")
	if !ok {
		writeError(w, 404, "not_found", "not found")
		return
	}
	p, err := s.Store.PublicTrustBadge(r.Context(), slug)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	dark := r.URL.Query().Get("theme") == "dark"
	now := time.Now()
	var svg string
	if p != nil && trustActive(p, now) {
		plan := s.planFor(r.Context(), p.WorkspaceID)
		var when *time.Time
		if r.URL.Query().Get("time") == "1" && p.Badge.ShowCheckedTime {
			when = p.Decision.OldestEvaluated
		}
		svg = trustBadgeImage(true, p.Badge.ShowMarketing || !plan.HideMarketing, when, dark)
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		svg = trustBadgeImage(false, false, nil, dark)
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	_, _ = io.WriteString(w, svg)
}

// trustBadgeImage draws the badge: about 44 px high, brand blue when
// active, grey when not; no verdict colours. when, if set, is the oldest
// evaluation time, shown as an absolute UTC time so a cached image never
// understates its age.
func trustBadgeImage(active, marketing bool, when *time.Time, dark bool) string {
	const h = 44
	bg, fg, sub, line, mark := "#ffffff", "#1f2937", "#4b5563", "#d6dbe6", "#2952cc"
	if dark {
		bg, fg, sub, line, mark = "#111827", "#f3f4f6", "#c7cdd8", "#374151", "#3f63d4"
	}
	title := "Monitored by Stackurity"
	alt := trustBadgeAlt
	if !active {
		title, alt, mark = "Stackurity badge not active", trustBadgeNotActiveAlt, "#8a8f98"
		marketing, when = false, nil
	}
	detail := ""
	if when != nil {
		detail = "evaluated " + when.UTC().Format("2 Jan 2006, 15:04") + " UTC"
	}
	// Text widths are estimated (no font metrics at hand): 7.3 px a
	// character at 13 px bold, 6 px at 11 px.
	textW := max(float64(len(title))*7.3, float64(len(detail))*6, float64(len("Monitor yours, free →"))*6)
	width := int(44 + textW + 14)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`,
		width, h, width, h, html.EscapeString(alt))
	fmt.Fprintf(&b, `<title>%s</title>`, html.EscapeString(alt))
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="6" fill="%s" stroke="%s"/>`, width-1, h-1, bg, line)
	// The mark: concentric arcs (a monitoring signal), never a shield or tick.
	fmt.Fprintf(&b, `<g fill="none" stroke="%s" stroke-width="2.2" stroke-linecap="round"><circle cx="22" cy="22" r="3" fill="%s" stroke="none"/>`+
		`<path d="M15.5 15.5a9.2 9.2 0 0 0 0 13"/><path d="M28.5 15.5a9.2 9.2 0 0 1 0 13"/></g>`, mark, mark)
	font := `font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"`
	switch {
	case marketing || detail != "":
		y1 := 19
		if marketing && detail != "" {
			y1 = 15
		}
		fmt.Fprintf(&b, `<text x="44" y="%d" %s font-size="13" font-weight="600" fill="%s">%s</text>`, y1, font, fg, html.EscapeString(title))
		y := y1
		if detail != "" {
			y += 12
			fmt.Fprintf(&b, `<text x="44" y="%d" %s font-size="10.5" fill="%s">%s</text>`, y, font, sub, html.EscapeString(detail))
		}
		if marketing {
			y += 5
			fmt.Fprintf(&b, `<line x1="44" y1="%d" x2="%d" y2="%d" stroke="%s"/>`, y, width-12, y, line)
			fmt.Fprintf(&b, `<text x="44" y="%d" %s font-size="10.5" fill="%s">%s</text>`, y+11, font, mark, html.EscapeString("Monitor yours, free →"))
		}
	default:
		fmt.Fprintf(&b, `<text x="44" y="27" %s font-size="13" font-weight="600" fill="%s">%s</text>`, font, fg, html.EscapeString(title))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// --- settings

// trustBadgeView is a badge as the settings page shows it.
type trustBadgeView struct {
	store.TrustBadge
	// TermsCurrent: the badge terms accepted are the current version.
	TermsCurrent bool `json:"terms_current"`
	// CanManage: the caller may change this badge.
	CanManage bool `json:"can_manage"`
}

type trustBadgeInput struct {
	Slug            string  `json:"slug"`
	ScopeKind       string  `json:"scope_kind"`
	ProjectIDs      []int64 `json:"project_ids"`
	AssetIDs        []int64 `json:"asset_ids"`
	DisplayName     string  `json:"display_name"`
	WebsiteURL      string  `json:"website_url"`
	ShowMarketing   *bool   `json:"show_marketing"`
	ShowCheckedTime *bool   `json:"show_checked_time"`
	ShowKinds       *bool   `json:"show_kinds"`
	ShowLogo        *bool   `json:"show_logo"`
	Listed          *bool   `json:"listed"`
}

func boolOr(p *bool, d bool) bool {
	if p == nil {
		return d
	}
	return *p
}

// apply copies the input onto b (defaults from b), keeping what the plan
// does not allow at its Free value.
func (in trustBadgeInput) apply(b store.TrustBadge, plan TrustBadgePlan) store.TrustBadge {
	b.Slug, b.ScopeKind, b.ProjectIDs, b.AssetIDs = in.Slug, in.ScopeKind, in.ProjectIDs, in.AssetIDs
	b.DisplayName, b.WebsiteURL = in.DisplayName, in.WebsiteURL
	b.ShowMarketing = boolOr(in.ShowMarketing, b.ShowMarketing)
	if !plan.HideMarketing {
		b.ShowMarketing = true
	}
	b.ShowCheckedTime = boolOr(in.ShowCheckedTime, b.ShowCheckedTime)
	b.ShowKinds = boolOr(in.ShowKinds, b.ShowKinds)
	b.ShowLogo = boolOr(in.ShowLogo, b.ShowLogo)
	b.Listed = boolOr(in.Listed, b.Listed)
	return b
}

// trustCtx is the request's context with the whole workspace in view: a
// badge's rule reads every asset in its scope.
func trustCtx(r *http.Request) context.Context { return tenant.WithoutProject(r.Context()) }

// canManageTrustScope reports whether the caller may change a badge with
// this scope: an organisation admin, or an admin of every project (or of
// every asset) it names.
func (s *Server) canManageTrustScope(r *http.Request, kind string, projectIDs, assetIDs []int64) (bool, error) {
	p := principal(r)
	if p == nil || p.User == nil || p.Assistant != nil || p.Ask {
		return false, nil
	}
	role := p.Role
	if p.Restricted {
		role = ""
	}
	if role.AtLeast(auth.RoleAdmin) {
		return true, nil
	}
	ctx := trustCtx(r)
	var grant auth.Role
	switch {
	case kind == "projects" && len(projectIDs) > 0:
		for i, id := range projectIDs {
			g, err := s.Store.ProjectGrantRole(ctx, p.User.ID, id)
			if err != nil {
				return false, err
			}
			if i == 0 {
				grant = g
			} else {
				grant = auth.Lower(grant, g)
			}
		}
	case kind == "assets" && len(assetIDs) > 0:
		g, err := s.Store.GrantRoleOn(ctx, p.User.ID, assetIDs)
		if err != nil {
			return false, err
		}
		grant = g
	default:
		return false, nil
	}
	if p.Token != nil {
		grant = auth.Lower(grant, p.Token.Role)
	}
	return grant.AtLeast(auth.RoleAdmin), nil
}

// checkTrustScope makes sure every project or asset a badge names is one
// of the workspace's (404 otherwise, as for any object the caller cannot
// see).
func (s *Server) checkTrustScope(ctx context.Context, kind string, projectIDs, assetIDs []int64) error {
	if kind == "projects" {
		for _, id := range projectIDs {
			if _, err := s.Store.GetProject(ctx, id); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range assetIDs {
		if _, err := s.Store.GetAsset(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// loadTrustBadge reads the badge the route names and checks the caller may
// change it (404 when it may not even see it).
func (s *Server) loadTrustBadge(w http.ResponseWriter, r *http.Request) (store.TrustBadge, bool) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return store.TrustBadge{}, false
	}
	b, err := s.Store.TrustBadgeByID(trustCtx(r), id)
	if err != nil {
		s.fail(w, r, err)
		return store.TrustBadge{}, false
	}
	ok, err := s.canManageTrustScope(r, b.ScopeKind, b.ProjectIDs, b.AssetIDs)
	if err != nil {
		s.fail(w, r, err)
		return store.TrustBadge{}, false
	}
	if !ok {
		writeError(w, 404, "not_found", "not found")
		return store.TrustBadge{}, false
	}
	return b, true
}

func (s *Server) listTrustBadges(w http.ResponseWriter, r *http.Request) {
	ctx := trustCtx(r)
	all, err := s.Store.ListTrustBadges(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	views := []trustBadgeView{}
	for _, b := range all {
		ok, err := s.canManageTrustScope(r, b.ScopeKind, b.ProjectIDs, b.AssetIDs)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if ok {
			views = append(views, trustBadgeView{TrustBadge: b, TermsCurrent: b.TermsVersion == TrustBadgeTermsVersion, CanManage: true})
		}
	}
	p := principal(r)
	writeJSON(w, 200, map[string]any{
		"badges":     views,
		"total":      len(all),
		"plan":       s.trustPlan(ctx),
		"terms":      map[string]string{"version": TrustBadgeTermsVersion, "text": TrustBadgeTermsText},
		"base_url":   strings.TrimRight(s.BaseURL, "/"),
		"trust_base": s.trustPageBase(),
		"org_admin":  p != nil && !p.Restricted && p.Role.AtLeast(auth.RoleAdmin),
	})
}

// trustPageBase is where trust pages are published.
func (s *Server) trustPageBase() string {
	if s.TrustPageBase != "" {
		return strings.TrimRight(s.TrustPageBase, "/")
	}
	return "https://stackurity.ai/trust"
}

func (s *Server) createTrustBadge(w http.ResponseWriter, r *http.Request) {
	var in trustBadgeInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	ok, err := s.canManageTrustScope(r, in.ScopeKind, in.ProjectIDs, in.AssetIDs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		writeError(w, 403, "forbidden", "a badge can be made by an organisation admin, or by an admin of every project or asset it covers")
		return
	}
	ctx := trustCtx(r)
	if err := s.checkTrustScope(ctx, in.ScopeKind, in.ProjectIDs, in.AssetIDs); err != nil {
		s.fail(w, r, err)
		return
	}
	plan := s.trustPlan(ctx)
	n, err := s.Store.CountTrustBadges(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if n >= plan.MaxBadges {
		writeError(w, 402, "plan_limit", fmt.Sprintf("your plan allows %d trust badge(s); remove one or upgrade for more", plan.MaxBadges))
		return
	}
	def := store.TrustBadge{ShowMarketing: true, ShowCheckedTime: true, ShowLogo: true, Listed: true}
	b := in.apply(def, plan)
	out, err := s.Store.CreateTrustBadge(ctx, b, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, trustErr(err))
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "trust_badge.create", "trust_badge", itoa(out.ID), auditableBadge(out))
	writeJSON(w, 201, trustBadgeView{TrustBadge: out, TermsCurrent: false, CanManage: true})
}

// auditableBadge is what an audit entry records about a badge (no logo
// bytes).
func auditableBadge(b store.TrustBadge) map[string]any {
	return map[string]any{"slug": b.Slug, "enabled": b.Enabled, "scope_kind": b.ScopeKind, "project_ids": b.ProjectIDs,
		"asset_ids": b.AssetIDs, "display_name": b.DisplayName, "website_url": b.WebsiteURL, "show_marketing": b.ShowMarketing,
		"show_checked_time": b.ShowCheckedTime, "show_kinds": b.ShowKinds, "show_logo": b.ShowLogo, "listed": b.Listed,
		"has_logo": b.HasLogo, "terms_version": b.TermsVersion}
}

func trustErr(err error) error {
	if errors.Is(err, store.ErrTrustBadgeSlugTaken) {
		return fmt.Errorf("that address is taken; choose another: %w", store.ErrConflict)
	}
	return err
}

func (s *Server) updateTrustBadge(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	var in trustBadgeInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	// The new scope must be one the caller may manage too.
	if ok, err := s.canManageTrustScope(r, in.ScopeKind, in.ProjectIDs, in.AssetIDs); err != nil || !ok {
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeError(w, 403, "forbidden", "you may cover only projects or assets you administer")
		return
	}
	ctx := trustCtx(r)
	if err := s.checkTrustScope(ctx, in.ScopeKind, in.ProjectIDs, in.AssetIDs); err != nil {
		s.fail(w, r, err)
		return
	}
	next := in.apply(b, s.trustPlan(ctx))
	out, err := s.Store.UpdateTrustBadge(ctx, next)
	if err != nil {
		s.fail(w, r, trustErr(err))
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "trust_badge.update", "trust_badge", itoa(out.ID),
		map[string]any{"before": auditableBadge(b), "after": auditableBadge(out)})
	if b.Enabled {
		// A new scope or address takes effect at once.
		if err := s.decideTrustBadge(ctx, out); err != nil {
			s.Log.Warn("trust badge decision after update failed", "badge", out.ID, "err", err)
		}
		if b.Slug != out.Slug {
			s.purgeTrustBadge(b.Slug)
		}
		s.purgeTrustBadge(out.Slug)
	}
	writeJSON(w, 200, trustBadgeView{TrustBadge: out, TermsCurrent: out.TermsVersion == TrustBadgeTermsVersion, CanManage: true})
}

func (s *Server) deleteTrustBadge(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	ctx := trustCtx(r)
	if err := s.Store.DeleteTrustBadge(ctx, b.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "trust_badge.delete", "trust_badge", itoa(b.ID), auditableBadge(b))
	s.purgeTrustBadge(b.Slug)
	w.WriteHeader(204)
}

func (s *Server) acceptTrustBadgeTerms(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	var in struct {
		Version  string `json:"version"`
		Accepted bool   `json:"accepted"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if !in.Accepted || in.Version != TrustBadgeTermsVersion {
		s.fail(w, r, badRequest("tick the box to accept the current badge terms (version "+TrustBadgeTermsVersion+")"))
		return
	}
	p := principal(r)
	if p.User == nil || p.Token != nil {
		writeError(w, 403, "forbidden", "the badge terms are accepted by a person, in the dashboard")
		return
	}
	ctx := trustCtx(r)
	if err := s.Store.AcceptTrustBadgeTerms(ctx, b.ID, p.User.ID, TrustBadgeTermsVersion); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, p.Actor(r), "trust_badge.terms.accept", "trust_badge", itoa(b.ID),
		map[string]any{"terms_version": TrustBadgeTermsVersion, "user_id": p.User.ID, "email": p.User.Email, "text": TrustBadgeTermsText})
	out, err := s.Store.TrustBadgeByID(ctx, b.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, trustBadgeView{TrustBadge: out, TermsCurrent: true, CanManage: true})
}

func (s *Server) setTrustBadgeEnabled(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Enabled && b.TermsVersion != TrustBadgeTermsVersion {
		s.fail(w, r, badRequest("accept the current badge terms before turning the badge on"))
		return
	}
	ctx := trustCtx(r)
	if err := s.Store.SetTrustBadgeEnabled(ctx, b.ID, in.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	action := "trust_badge.disable"
	if in.Enabled {
		action = "trust_badge.enable"
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), action, "trust_badge", itoa(b.ID), map[string]any{"slug": b.Slug})
	out, err := s.Store.TrustBadgeByID(ctx, b.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Decide at once, so the badge does not wait for the hourly run, and
	// a turned-off badge has its decision in the history.
	if err := s.decideTrustBadge(ctx, out); err != nil {
		s.Log.Warn("trust badge decision failed", "badge", out.ID, "err", err)
	}
	s.purgeTrustBadge(out.Slug)
	writeJSON(w, 200, trustBadgeView{TrustBadge: out, TermsCurrent: out.TermsVersion == TrustBadgeTermsVersion, CanManage: true})
}

// decideTrustBadge evaluates the badge now and appends the decision to its
// history (as the hourly evaluator does).
func (s *Server) decideTrustBadge(ctx context.Context, b store.TrustBadge) error {
	in, err := s.Store.TrustBadgeInputs(ctx, b)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = s.Store.AppendTrustBadgeStatus(ctx, b.ID, now, trustbadge.Evidence{Inputs: in, Decision: trustbadge.Evaluate(in, now)})
	return err
}

// purgeTrustBadge asks the CDN to drop the badge's cached image and trust
// data, when a purger is configured; it never blocks the request.
func (s *Server) purgeTrustBadge(slug string) {
	if s.TrustBadgePurge == nil || slug == "" {
		return
	}
	base := strings.TrimRight(s.BaseURL, "/")
	urls := []string{base + "/api/v1/public/trust/" + slug, base + "/api/v1/public/trust/" + slug + "/logo",
		base + "/api/v1/public/trust?listed=1", s.trustPageBase() + "/" + slug}
	for _, q := range []string{"", "?theme=light", "?theme=dark", "?time=1", "?theme=light&time=1", "?theme=dark&time=1"} {
		urls = append(urls, base+"/badge/"+slug+".svg"+q)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.TrustBadgePurge(ctx, urls); err != nil {
			s.Log.Warn("trust badge cache purge failed", "slug", slug, "err", err)
		}
	}()
}

// sniffTrustLogo checks the logo's type from its first bytes.
func sniffTrustLogo(b []byte) string {
	switch {
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return "image/png"
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return "image/jpeg"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "image/webp"
	}
	return ""
}

func (s *Server) putTrustBadgeLogo(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	ctx := trustCtx(r)
	if !s.trustPlan(ctx).Logo {
		writeError(w, 402, "plan_limit", "a logo on the trust page needs a paid plan")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, store.TrustBadgeMaxLogo+1))
	if err != nil {
		s.fail(w, r, badRequest("could not read the logo"))
		return
	}
	if len(data) > store.TrustBadgeMaxLogo {
		writeError(w, 413, "too_large", "the logo must be at most 256 KiB")
		return
	}
	typ := sniffTrustLogo(data)
	if typ == "" {
		s.fail(w, r, badRequest("the logo must be a PNG, JPEG or WebP image"))
		return
	}
	if err := s.Store.SetTrustBadgeLogo(ctx, b.ID, data, typ); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "trust_badge.logo.set", "trust_badge", itoa(b.ID),
		map[string]any{"type": typ, "bytes": len(data)})
	if b.Enabled {
		s.purgeTrustBadge(b.Slug)
	}
	w.WriteHeader(204)
}

func (s *Server) deleteTrustBadgeLogo(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	ctx := trustCtx(r)
	if err := s.Store.SetTrustBadgeLogo(ctx, b.ID, nil, ""); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "trust_badge.logo.remove", "trust_badge", itoa(b.ID), nil)
	if b.Enabled {
		s.purgeTrustBadge(b.Slug)
	}
	w.WriteHeader(204)
}

// previewTrustBadge answers what the public would see if the badge were
// on now: the rule is run live (nothing is written) and its result goes
// through the same code as the public endpoints.
func (s *Server) previewTrustBadge(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	ctx := trustCtx(r)
	pb := b
	pb.Enabled = true
	in, err := s.Store.TrustBadgeInputs(ctx, pb)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now()
	d := trustbadge.Evaluate(in, now)
	kinds := []string{}
	for _, a := range in.Assets {
		if !slices.Contains(kinds, a.Kind) {
			kinds = append(kinds, a.Kind)
		}
	}
	ws, _ := tenant.Workspace(ctx)
	name := ""
	if b.DisplayName == "" {
		if w, err := s.Store.GetWorkspace(ctx, ws); err == nil {
			name = w.Name
		}
	}
	p := &store.PublicTrustBadge{Badge: pb, WorkspaceID: ws, Decision: &d, DecidedAt: &now, ScopeKinds: kinds, WorkspaceName: name}
	plan := s.trustPlan(ctx)
	answer := s.trustAnswer(p, plan, now)
	active := trustActive(p, now)
	marketing := pb.ShowMarketing || !plan.HideMarketing
	var when *time.Time
	if pb.ShowCheckedTime {
		when = d.OldestEvaluated
	}
	reasons := []string{}
	for _, f := range d.Failed {
		if t := trustbadge.ReasonText[f]; t != "" {
			reasons = append(reasons, t)
		}
	}
	writeJSON(w, 200, map[string]any{
		"trust":       answer,
		"svg_light":   trustBadgeImage(active, marketing, nil, false),
		"svg_dark":    trustBadgeImage(active, marketing, nil, true),
		"svg_time":    trustBadgeImage(active, marketing, when, false),
		"reason":      d.Reason,
		"reason_text": trustbadge.ReasonText[d.Reason],
		"failed":      reasons,
		"systems":     len(in.Assets),
		"states":      d.States,
	})
}

func (s *Server) trustBadgeHistory(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadTrustBadge(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.TrustBadgeHistory(trustCtx(r), principal(r).Actor(r), b.ID, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The customer's own timeline: result, reason and time; the full
	// evidence is in the operators' viewer.
	type entry struct {
		DecidedAt   time.Time `json:"decided_at"`
		Result      string    `json:"result"`
		Reason      string    `json:"reason"`
		ReasonText  string    `json:"reason_text"`
		RuleVersion string    `json:"rule_version"`
	}
	out := []entry{}
	for _, e := range rows {
		out = append(out, entry{e.DecidedAt, e.Result, e.Reason, trustbadge.ReasonText[e.Reason], e.RuleVersion})
	}
	writeJSON(w, 200, all(out))
}

// --- operators' evidence viewer

func (s *Server) adminTrustBadges(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.AdminTrustBadges(r.Context(), principal(r).Actor(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(rows))
}

func (s *Server) adminTrustBadgeHistory(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.AdminTrustBadgeHistory(r.Context(), principal(r).Actor(r), id, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": rows, "reasons": trustbadge.ReasonText})
}
