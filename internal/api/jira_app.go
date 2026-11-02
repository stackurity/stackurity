package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// Connect Jira: the Stackurity Atlassian app (OAuth 2.0 3LO). An
// administrator starts it from the dashboard (a single-use state bound to
// the organisation and the person), approves on Atlassian's consent page,
// and comes back to /integrations/jira/oauth/callback, whose page posts the
// code and state here. The tokens are sealed in the connection and never
// returned; the setup lists (projects, issue types, statuses) are read
// with them. See docs/jira-app.md.

func (s *Server) jiraApp() *notify.JiraApp {
	if s.Dispatcher == nil {
		return nil
	}
	return s.Dispatcher.JiraApp
}

func (s *Server) jiraRedirectURL() string { return s.baseURL() + "/integrations/jira/oauth/callback" }

// jiraAppReady reports why Connect Jira cannot be used, or nil.
func (s *Server) jiraAppReady() error {
	switch {
	case s.jiraApp() == nil:
		return &wrapped{"Connect Jira is not set up on this server; use an API token", errNotConfigured}
	case s.baseURL() == "":
		return badRequest("Connect Jira needs STACKURITY_BASE_URL")
	case s.SecretBox == nil:
		return badRequest("Connect Jira needs stored secrets (STACKURITY_SECRET_KEY)")
	}
	return nil
}

var errNotConfigured = errors.New("not configured")

func (s *Server) failJira(w http.ResponseWriter, r *http.Request, err error) {
	var pe *notify.PermanentError
	var re *store.JiraReconnectError
	switch {
	case errors.Is(err, errNotConfigured):
		writeError(w, 404, "not_configured", err.Error())
	case errors.As(err, &re):
		writeError(w, 409, "jira_reconnect", re.Error())
	case errors.As(err, &pe):
		writeError(w, 502, "jira_refused", pe.Error())
	case errors.Is(err, store.ErrNotFound), errors.Is(err, errBadRequest), errors.Is(err, errForbidden):
		s.fail(w, r, err)
	default:
		s.Log.Warn("jira request failed", "path", r.URL.Path, "err", err)
		writeError(w, 502, "jira_unavailable", "Jira could not be reached; try again")
	}
}

// startJiraConnect begins Connect Jira, or reconnects connection_id.
func (s *Server) startJiraConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.jiraAppReady(); err != nil {
		s.failJira(w, r, err)
		return
	}
	if userID(principal(r)) == 0 {
		s.fail(w, r, forbidden("Connect Jira is done signed in, from the dashboard"))
		return
	}
	var req struct {
		ReturnTo     string `json:"return_to"`
		ConnectionID int64  `json:"connection_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ConnectionID != 0 {
		if _, err := s.Store.GetJiraConnection(r.Context(), req.ConnectionID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	state, err := s.Store.CreateJiraOAuthState(r.Context(), userID(principal(r)), safeReturn(req.ReturnTo), req.ConnectionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"url": s.jiraApp().AuthorizeURL(state, s.jiraRedirectURL())})
}

// finishJiraConnect completes Connect Jira after Atlassian sent the person
// back: the state must be theirs, in this organisation, unused and fresh,
// before the code is exchanged.
func (s *Server) finishJiraConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.jiraAppReady(); err != nil {
		s.failJira(w, r, err)
		return
	}
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	p := principal(r)
	returnTo, connID, err := s.Store.ClaimJiraOAuthState(ctx, req.State, userID(p))
	if err != nil {
		if errors.Is(err, store.ErrJiraStateInvalid) {
			writeError(w, 400, "jira_state", err.Error())
			return
		}
		s.fail(w, r, err)
		return
	}
	if req.Code == "" || len(req.Code) > 2000 {
		s.fail(w, r, badRequest("missing code"))
		return
	}
	app := s.jiraApp()
	tok, scopes, err := app.Exchange(ctx, req.Code, s.jiraRedirectURL())
	if err != nil {
		s.Log.Warn("connect jira: code exchange failed", "err", err)
		writeError(w, 502, "jira_refused", "Atlassian did not complete the connection; try Connect Jira again")
		return
	}
	sites, err := app.AccessibleSites(ctx, tok.Access)
	if err != nil {
		s.Log.Warn("connect jira: accessible-resources failed", "err", err)
		writeError(w, 502, "jira_refused", "Atlassian did not say which Jira sites were allowed; try Connect Jira again")
		return
	}
	if len(sites) == 0 {
		writeError(w, 400, "jira_no_site", "the connection reaches no Jira site: pick a Jira Cloud site on Atlassian's page (for Jira Data Center or Server, use a personal access token)")
		return
	}
	id, err := s.Store.SaveJiraConnection(ctx, s.SecretBox, connID, sites, scopes, tok, userID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	conn, err := s.Store.GetJiraConnection(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	action := "jira_connection.create"
	if connID != 0 {
		action = "jira_connection.reconnect"
	}
	names := make([]string, len(sites))
	for i, site := range sites {
		names[i] = site.URL
	}
	_ = s.Store.Audit(ctx, p.Actor(r), action, "jira_connection", itoa(id), map[string]string{"sites": strings.Join(names, " ")})
	status := 201
	if connID != 0 {
		status = 200
	}
	writeJSON(w, status, map[string]any{"connection": conn, "return_to": returnTo, "reconnected": connID != 0})
}

func (s *Server) listJiraConnections(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.JiraConnections(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(cs))
}

// deleteJiraConnection forgets a connection and its tokens; the channels
// using it are switched off with a note. Atlassian has no API to revoke a
// 3LO grant: the answer says where the person removes the app from their
// Atlassian account.
func (s *Server) deleteJiraConnection(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := s.Store.DeleteJiraConnection(r.Context(), id, "Jira was disconnected. Connect Jira again and pick it in this integration.")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "jira_connection.delete", "jira_connection", itoa(id), map[string]int{"channels_disabled": n})
	writeJSON(w, 200, map[string]any{"channels_disabled": n, "revoke_url": "https://id.atlassian.com/manage-profile/apps"})
}

func (s *Server) jiraSetup(w http.ResponseWriter, r *http.Request) (*notify.JiraSetup, bool) {
	if err := s.jiraAppReady(); err != nil {
		s.failJira(w, r, err)
		return nil, false
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	js, err := s.Dispatcher.JiraSetup(r.Context(), id, r.URL.Query().Get("site"))
	if err != nil {
		s.failJira(w, r, err)
		return nil, false
	}
	return js, true
}

// listJiraProjects is GET /integrations/jira/connections/{id}/projects?site=&q=.
func (s *Server) listJiraProjects(w http.ResponseWriter, r *http.Request) {
	js, ok := s.jiraSetup(w, r)
	if !ok {
		return
	}
	ps, err := js.Projects(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.failJira(w, r, err)
		return
	}
	writeJSON(w, 200, all(ps))
}

// getJiraProject is GET /integrations/jira/connections/{id}/projects/{key}?site=.
func (s *Server) getJiraProject(w http.ResponseWriter, r *http.Request) {
	js, ok := s.jiraSetup(w, r)
	if !ok {
		return
	}
	m, err := js.ProjectMeta(r.Context(), chi.URLParam(r, "key"))
	if err != nil {
		s.failJira(w, r, err)
		return
	}
	writeJSON(w, 200, m)
}

// jiraChannelConfig checks a Connect Jira channel's connection and site
// and sets its address from the site, so the issue links are right
// whatever the request said. Other configurations pass unchanged.
func (s *Server) jiraChannelConfig(r *http.Request, kind string, cfgRaw json.RawMessage) (json.RawMessage, error) {
	if kind != notify.KindJira || len(cfgRaw) == 0 {
		return cfgRaw, nil
	}
	var cfg notify.ChannelConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil || cfg.Auth != notify.JiraAuthOAuth {
		return cfgRaw, nil
	}
	if s.jiraApp() == nil {
		return nil, badRequest("Connect Jira is not set up on this server; use an API token")
	}
	conn, err := s.Store.GetJiraConnection(r.Context(), cfg.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, badRequest("connection_id is not a Jira connection of this organisation")
	}
	if err != nil {
		return nil, err
	}
	site, ok := conn.Site(cfg.CloudID)
	if !ok {
		return nil, badRequest("cloud_id is not a site of this Jira connection")
	}
	var m map[string]any
	if err := json.Unmarshal(cfgRaw, &m); err != nil {
		return nil, badRequest("invalid config")
	}
	m["url"] = site.URL
	m["deployment"] = notify.JiraCloud
	return json.Marshal(m)
}
