package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Notifications of projects and assets (docs/design/projects.md,
// "Notifications of projects and assets"), like groups and projects in
// GitLab: the organisation's rules apply to every project and asset; a
// project or asset sees them as inherited and can turn one off for itself
// or replace it with its own copy, and can add rules and channels of its
// own. A project's inherited rules are the organisation's; an asset's are
// the organisation's and its projects'.
//
// Admins of the project or asset (an organisation-wide admin, or an admin
// grant on it) manage them; security and above can read them.

// notifyScope is the project or asset a request names.
type notifyScope struct {
	kind     string // "project" or "asset"
	id       int64
	name     string
	owner    store.Owner
	projects []int64 // an asset's active projects
	manage   bool    // the caller may change its notifications
}

// orgAdmin reports whether the caller has an organisation-wide admin role.
func orgAdmin(r *http.Request) bool {
	p := principal(r)
	return p != nil && !p.Restricted && p.Role.AtLeast(auth.RoleAdmin)
}

// scopeRole is the caller's role on the project or asset: their
// organisation-wide role, or the role their grants give on it (capped by
// the token's role).
func (s *Server) scopeRole(r *http.Request, sc *notifyScope) (auth.Role, error) {
	p := principal(r)
	role := p.Role
	if p.Restricted {
		role = ""
	}
	if p.User == nil || role.AtLeast(auth.RoleAdmin) {
		return role, nil
	}
	var grant auth.Role
	var err error
	if sc.kind == "project" {
		grant, err = s.Store.ProjectGrantRole(r.Context(), p.User.ID, sc.id)
	} else {
		grant, err = s.Store.GrantRoleOn(r.Context(), p.User.ID, []int64{sc.id})
	}
	if err != nil {
		return "", err
	}
	if p.Token != nil {
		grant = auth.Lower(grant, p.Token.Role)
	}
	return auth.Higher(role, grant), nil
}

// loadScope reads the project or asset the request names (404 when the
// caller cannot see it) and checks the caller's role on it: at least
// security to read, admin to change (manage).
func (s *Server) loadScope(w http.ResponseWriter, r *http.Request, manage bool) (*notifyScope, bool) {
	if principal(r).Assistant != nil {
		writeError(w, 403, "forbidden", "notification settings are changed in the dashboard")
		return nil, false
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	ctx := tenant.WithoutProject(r.Context())
	sc := &notifyScope{id: id}
	if pattern := chi.RouteContext(r.Context()).RoutePattern(); strings.HasPrefix(pattern, "/api/v1/projects/") {
		sc.kind = "project"
		pr, err := s.Store.GetProject(ctx, id)
		if err != nil {
			s.fail(w, r, err)
			return nil, false
		}
		if manage && pr.ArchivedAt != nil {
			s.fail(w, r, badRequest("this project is archived; restore it to change its notifications"))
			return nil, false
		}
		sc.name, sc.owner = pr.Name, store.Owner{ProjectID: &sc.id}
	} else {
		sc.kind = "asset"
		a, err := s.Store.GetAsset(ctx, id)
		if err != nil {
			s.fail(w, r, err)
			return nil, false
		}
		if sc.projects, err = s.Store.AssetProjects(ctx, id); err != nil {
			s.fail(w, r, err)
			return nil, false
		}
		sc.name, sc.owner = a.Name, store.Owner{AssetID: &sc.id}
	}
	role, err := s.scopeRole(r, sc)
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	sc.manage = role.AtLeast(auth.RoleAdmin)
	need := auth.RoleSecurity
	if manage {
		need = auth.RoleAdmin
	}
	if !role.AtLeast(need) {
		writeError(w, 403, "forbidden", "managing the notifications of this "+sc.kind+" needs the admin role on it; reading them needs security")
		return nil, false
	}
	return sc, true
}

// channelRef names a channel without its settings: what a project's or
// asset's page shows of channels that are not its own.
type channelRef struct {
	ID             int64  `json:"id"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	OwnerProjectID *int64 `json:"owner_project_id"`
	OwnerAssetID   *int64 `json:"owner_asset_id"`
}

func refOf(c store.Channel) channelRef {
	return channelRef{ID: c.ID, Kind: c.Kind, Name: c.Name, Enabled: c.Enabled, OwnerProjectID: c.OwnerProjectID, OwnerAssetID: c.OwnerAssetID}
}

// inheritedRule is a rule a project or asset inherits, and what it did
// with it here: on, off (turned off) or edited (replaced by CopyID).
type inheritedRule struct {
	ID             int64    `json:"id"`
	Name           string   `json:"name"`
	ChannelID      int64    `json:"channel_id"`
	Enabled        bool     `json:"enabled"`
	Events         []string `json:"events"`
	MinPriority    string   `json:"min_priority"`
	NewMinPriority string   `json:"new_min_priority"`
	SummaryTime    string   `json:"summary_time"`
	SummaryDay     string   `json:"summary_day"`
	Timezone       string   `json:"timezone"`
	// From: "organisation", or "project" (an asset's project, FromProjectID).
	From          string `json:"from"`
	FromProjectID *int64 `json:"from_project_id,omitempty"`
	State         string `json:"state"`
	CopyID        *int64 `json:"copy_id,omitempty"`
	// Tracker: the rule sends to Jira, PagerDuty or ServiceNow.
	Tracker bool `json:"tracker"`
}

// inherited lists the rules the scope inherits: the organisation's that
// reach it (not limited to other projects), and for an asset its
// projects' rules too.
func (s *Server) inherited(r *http.Request, sc *notifyScope, routes []store.Route) []store.Route {
	var out []store.Route
	for _, rt := range routes {
		switch {
		case rt.Owner().Org():
			if len(rt.ProjectIDs) > 0 {
				reach := false
				for _, p := range rt.ProjectIDs {
					reach = reach || sc.kind == "project" && p == sc.id || slices.Contains(sc.projects, p)
				}
				if !reach {
					continue
				}
			}
		case sc.kind == "asset" && rt.OwnerProjectID != nil && slices.Contains(sc.projects, *rt.OwnerProjectID):
		default:
			continue
		}
		out = append(out, rt)
	}
	return out
}

func (s *Server) getScopeNotifications(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScope(w, r, false)
	if !ok {
		return
	}
	s.writeScopeNotifications(w, r, sc, 200)
}

func (s *Server) writeScopeNotifications(w http.ResponseWriter, r *http.Request, sc *notifyScope, status int) {
	ctx := tenant.WithoutProject(r.Context())
	routes, err := s.Store.ListRoutes(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	excl, err := s.Store.RouteExclusions(ctx, sc.owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	off := map[int64]bool{}
	for _, e := range excl {
		off[e.RouteID] = true
	}
	chans, err := s.Store.ListChannels(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tracker := map[int64]bool{}
	var own []store.Channel
	usable := []channelRef{}
	names := map[int64]string{}
	for _, c := range chans {
		tracker[c.ID] = notify.IsTracker(c.Kind)
		if c.Owner().Same(sc.owner) {
			own = append(own, c)
		}
		if channelServes(&c, sc.owner, sc.projects) {
			usable = append(usable, refOf(c))
		}
		names[c.ID] = c.Name
	}
	mine := []store.Route{}
	copies := map[int64]int64{}
	for _, rt := range routes {
		if rt.Owner().Same(sc.owner) {
			mine = append(mine, rt)
			if rt.InheritsRouteID != nil {
				copies[*rt.InheritsRouteID] = rt.ID
			}
		}
	}
	inh := []inheritedRule{}
	for _, rt := range s.inherited(r, sc, routes) {
		ir := inheritedRule{ID: rt.ID, Name: rt.Name, ChannelID: rt.ChannelID, Enabled: rt.Enabled, Events: rt.Events,
			MinPriority: rt.MinPriority, NewMinPriority: rt.NewMinPriority, SummaryTime: rt.SummaryTime, SummaryDay: rt.SummaryDay,
			Timezone: rt.Timezone, From: "organisation", FromProjectID: rt.OwnerProjectID, State: "on", Tracker: tracker[rt.ChannelID]}
		if rt.OwnerProjectID != nil {
			ir.From = "project"
		}
		if id, ok := copies[rt.ID]; ok {
			ir.State, ir.CopyID = "edited", &id
		} else if off[rt.ID] {
			ir.State = "off"
		}
		inh = append(inh, ir)
	}
	if own == nil {
		own = []store.Channel{}
	}
	allowed, err := s.Store.ProjectChatApps(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	admins, err := s.Store.OrgAdmins(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if admins == nil {
		admins = []string{}
	}
	writeJSON(w, status, map[string]any{
		"scope":             map[string]any{"kind": sc.kind, "id": sc.id, "name": sc.name, "project_ids": sc.projects},
		"can_manage":        sc.manage,
		"inherited":         inh,
		"routes":            mine,
		"channels":          own,
		"usable_channels":   usable,
		"channel_names":     names,
		"project_chat_apps": allowed,
		"platform_email":    s.Dispatcher != nil && s.Dispatcher.PlatformEmail(),
		"slack_app":         s.slackApp() != nil,
		"teams_app":         s.teamsApp() != nil,
		"org_admins":        admins,
	})
}

func (s *Server) createScopeRoute(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.saveRouteAs(w, r, 0, sc)
	}
}

func (s *Server) updateScopeRoute(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScope(w, r, true)
	if !ok {
		return
	}
	id, err := idParam(r, "rid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.saveRouteAs(w, r, id, sc)
}

func (s *Server) deleteScopeRoute(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.deleteRouteAs(w, r, sc)
	}
}

// setInheritedRule turns an inherited rule on or off for the project or
// asset, or replaces it with the project's or asset's own copy ("edit").
// Turning it on again removes the copy.
func (s *Server) setInheritedRule(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScope(w, r, true)
	if !ok {
		return
	}
	rid, err := idParam(r, "rid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		State string `json:"state"` // on, off or edit
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithoutProject(r.Context())
	routes, err := s.Store.ListRoutes(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var rt *store.Route
	for _, x := range s.inherited(r, sc, routes) {
		if x.ID == rid {
			rt = &x
			break
		}
	}
	if rt == nil {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	var copyID int64
	for _, x := range routes {
		if x.InheritsRouteID != nil && *x.InheritsRouteID == rid && x.Owner().Same(sc.owner) {
			copyID = x.ID
		}
	}
	ch, err := s.Store.GetChannel(ctx, rt.ChannelID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tracker := notify.IsTracker(ch.Kind)
	actor := principal(r).Actor(r)
	detail := map[string]any{sc.kind + "_id": sc.id, "state": req.State}
	switch req.State {
	case "off":
		if sc.kind == "asset" && tracker && rt.Limited() {
			s.fail(w, r, badRequest("a project's Jira rule describes the project's part of each incident; turn it off for the whole project instead"))
			return
		}
		if copyID > 0 {
			s.fail(w, r, badRequest("this rule was edited here: delete the edited copy, or turn it back on, first"))
			return
		}
		if err := s.Store.SetRouteExcluded(ctx, rid, sc.owner, true, userID(principal(r))); err != nil {
			s.fail(w, r, err)
			return
		}
	case "on":
		if copyID > 0 {
			err = s.Store.DeleteRoute(ctx, copyID)
		} else {
			err = s.Store.SetRouteExcluded(ctx, rid, sc.owner, false, 0)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
	case "edit":
		if copyID > 0 {
			break
		}
		switch {
		case tracker && sc.kind == "asset":
			s.fail(w, r, badRequest("a rule to Jira, PagerDuty or ServiceNow cannot be edited for one asset, as their records describe whole incidents; you can turn it off here"))
			return
		case ch.Kind == notify.KindPagerDuty || ch.Kind == notify.KindServiceNow:
			s.fail(w, r, badRequest("a rule to PagerDuty or ServiceNow cannot be edited for one project, as their records describe whole incidents; you can turn it off here"))
			return
		}
		cp := *rt
		cp.ID, cp.OwnerProjectID, cp.OwnerAssetID, cp.InheritsRouteID = 0, sc.owner.ProjectID, sc.owner.AssetID, &rid
		cp.ProjectAssets, cp.AssetProject, cp.Excluded = nil, nil, nil
		if cp.OwnerProjectID != nil {
			cp.ProjectIDs = []int64{sc.id}
		} else {
			cp.ProjectIDs = nil
		}
		out, err := s.Store.CustomiseRoute(ctx, cp, userID(principal(r)))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.Store.Audit(r.Context(), actor, "route.create", "route", itoa(out.ID), out)
	default:
		s.fail(w, r, badRequest("state must be on, off or edit"))
		return
	}
	_ = s.Store.Audit(r.Context(), actor, "route.inherited", "route", itoa(rid), detail)
	s.writeScopeNotifications(w, r, sc, 200)
}

func (s *Server) createScopeChannel(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.createChannelAs(w, r, sc)
	}
}

func (s *Server) updateScopeChannel(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.updateChannelAs(w, r, sc)
	}
}

func (s *Server) deleteScopeChannel(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.deleteChannelAs(w, r, sc)
	}
}

func (s *Server) testScopeChannel(w http.ResponseWriter, r *http.Request) {
	if sc, ok := s.loadScope(w, r, true); ok {
		s.testChannelAs(w, r, sc)
	}
}

// projectChatAppsRefused is the answer when the organisation does not let
// projects connect their own Slack or Teams workspace.
func (s *Server) projectChatAppsRefused(r *http.Request) error {
	msg := "your organisation does not let projects connect their own Slack or Teams workspace; ask an organisation admin to turn on " +
		"\"Projects can connect their own Slack or Teams\" under Integrations"
	if admins, err := s.Store.OrgAdmins(tenant.WithoutProject(r.Context())); err == nil && len(admins) > 0 {
		msg += " (" + strings.Join(admins, ", ") + ")"
	}
	return forbidden(msg)
}

// projectChatAppsOK checks that the organisation lets projects connect
// their own Slack or Teams workspace (organisation admins always may).
func (s *Server) projectChatAppsOK(r *http.Request) error {
	if orgAdmin(r) {
		return nil
	}
	on, err := s.Store.ProjectChatApps(r.Context())
	if err != nil {
		return err
	}
	if !on {
		return s.projectChatAppsRefused(r)
	}
	return nil
}

func (s *Server) startProjectSlackInstall(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScope(w, r, true)
	if !ok {
		return
	}
	if err := s.projectChatAppsOK(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.startSlackInstallFor(w, r, &sc.id)
}

func (s *Server) startProjectTeamsInstall(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.loadScope(w, r, true)
	if !ok {
		return
	}
	if err := s.projectChatAppsOK(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.startTeamsInstallFor(w, r, &sc.id)
}

// mayInstallFor checks, when an install finishes, that the person may
// still connect a channel for the project it was started for (nil: the
// organisation, which needs an organisation-wide admin).
func (s *Server) mayInstallFor(r *http.Request, project *int64) error {
	if project == nil {
		if !orgAdmin(r) {
			return forbidden("connecting a channel for the whole organisation needs an organisation-wide admin role")
		}
		return nil
	}
	role, err := s.scopeRole(r, &notifyScope{kind: "project", id: *project})
	if err != nil {
		return err
	}
	if !role.AtLeast(auth.RoleAdmin) {
		return forbidden("connecting a channel for this project needs the admin role on it")
	}
	return s.projectChatAppsOK(r)
}

// --- the organisation's setting

func (s *Server) getNotificationSettings(w http.ResponseWriter, r *http.Request) {
	on, err := s.Store.ProjectChatApps(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"project_chat_apps": on})
}

func (s *Server) putNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectChatApps *bool `json:"project_chat_apps"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ProjectChatApps == nil {
		s.fail(w, r, badRequest("project_chat_apps is required"))
		return
	}
	if err := s.Store.SetProjectChatApps(r.Context(), *req.ProjectChatApps); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "settings.notifications", "settings", "notifications",
		map[string]bool{"project_chat_apps": *req.ProjectChatApps})
	writeJSON(w, 200, map[string]bool{"project_chat_apps": *req.ProjectChatApps})
}
