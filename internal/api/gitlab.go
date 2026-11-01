package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/gitlab"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Connect GitLab (internal/gitlab, docs/gitlab.md).
//
//  1. Connect GitLab (POST /integrations/gitlab/connect, admins) stores a
//     random state, only its SHA-256, bound to the organisation and the
//     person, valid once for 10 minutes, and sends the browser to GitLab's
//     consent page for the api scope.
//  2. GitLab sends the browser back to /integrations/gitlab/callback with
//     the code and the state; that dashboard page posts them to POST
//     /integrations/gitlab/oauth. The state is claimed before GitLab is
//     called. The token is kept sealed on the state, for at most 10
//     minutes, and the groups the person is at least a Reporter of are
//     listed with a single-use pick handle.
//  3. POST /integrations/gitlab/connections with the handle and a group:
//     the group id from the browser is not trusted; the person's token
//     must show them a member of it (Reporter or above). A group belongs
//     to one organisation, and a group above or below one connected
//     elsewhere is refused. As Owner, a read-only group access token and a
//     push webhook are created; the person's token is then revoked.
//     Without a group access token the dashboard asks for a second,
//     read-only authorisation (purpose readonly), whose OAuth credential is
//     kept sealed and refreshed.
//  4. Disconnect: DELETE removes the connection here and revokes what the
//     stored credential can revoke; the cleanup authorisation (purpose
//     cleanup) also deletes the webhook and the group access token on
//     GitLab with the person's token, then disconnects.
//  5. Webhooks (POST /api/v1/integrations/gitlab/webhook/{id}) are
//     verified with the connection's secret token (X-Gitlab-Token, compared
//     in constant time against its SHA-256) before anything is read, and
//     handled once per X-Gitlab-Event-UUID and per body.

// limitGitLabWebhook: GitLab's deliveries share GitLab's addresses.
var limitGitLabWebhook = rateLimit{1200, time.Minute}

// limitGitLabOAuth bounds code exchanges and picks per address.
var limitGitLabOAuth = rateLimit{30, time.Minute}

// gitlabMaxBody bounds a webhook body (push payloads past this are dropped
// and the schedule picks the change up).
const gitlabMaxBody = 10 << 20

var gitlabDeliveryRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)

func (s *Server) gitlabRedirect() string { return s.baseURL() + "/integrations/gitlab/callback" }

// gitlabReady answers 404 when Connect GitLab is not set up, and 409 when
// stored secrets are off (the credential is kept sealed).
func (s *Server) gitlabReady(w http.ResponseWriter) bool {
	if s.GitLab == nil {
		writeError(w, 404, "not_configured", "Connect GitLab is not set up on this server; add a Git repository with a token, or scan in CI")
		return false
	}
	if s.SecretBox == nil {
		writeError(w, 409, "secrets_disabled", "Connect GitLab keeps its credential encrypted: the server needs STACKURITY_SECRET_KEY")
		return false
	}
	return true
}

// listGitLab tells the dashboard whether Connect GitLab is offered and
// lists the organisation's connected groups.
func (s *Server) listGitLab(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"configured": s.GitLab != nil && s.SecretBox != nil, "connections": []store.GitLabConnection{}}
	if s.GitLab != nil {
		out["gitlab_url"] = s.GitLab.Base
	}
	cs, err := s.Store.ListGitLabConnections(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cs != nil {
		out["connections"] = cs
	}
	writeJSON(w, 200, out)
}

// startGitLab begins Connect GitLab: a single-use state and GitLab's
// consent page for the api scope (used once, then revoked).
func (s *Server) startGitLab(w http.ResponseWriter, r *http.Request) {
	if !s.gitlabReady(w) {
		return
	}
	var req struct {
		ReturnTo string `json:"return_to"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	s.gitlabAuthorize(w, r, "setup", nil, req.ReturnTo)
}

func (s *Server) gitlabAuthorize(w http.ResponseWriter, r *http.Request, purpose string, connID *int64, returnTo string) {
	uid := userID(principal(r))
	if uid == 0 {
		s.fail(w, r, forbidden("Connect GitLab is done signed in, from the dashboard"))
		return
	}
	state, err := s.Store.CreateGitLabState(r.Context(), uid, purpose, connID, safeReturn(returnTo))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scopes := gitlab.SetupScopes
	if purpose == "readonly" {
		scopes = gitlab.ReadScopes
	}
	writeJSON(w, 200, map[string]string{"url": s.GitLab.AuthorizeURL(state, s.gitlabRedirect(), scopes)})
}

// authorizeGitLabConnection starts the read-only authorisation (readonly)
// or the cleanup on GitLab (cleanup) of a connection.
func (s *Server) authorizeGitLabConnection(w http.ResponseWriter, r *http.Request) {
	if !s.gitlabReady(w) {
		return
	}
	id, err := idParam(r, "id")
	if err == nil {
		_, err = s.Store.GetGitLabConnection(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Purpose  string `json:"purpose"`
		ReturnTo string `json:"return_to"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Purpose != "readonly" && req.Purpose != "cleanup" {
		s.fail(w, r, badRequest("purpose must be readonly or cleanup"))
		return
	}
	s.gitlabAuthorize(w, r, req.Purpose, &id, req.ReturnTo)
}

// revokeLater revokes a person's OAuth token at GitLab after the request,
// whatever happened.
func (s *Server) revokeGitLabToken(ctx context.Context, token string) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.GitLab.Revoke(rctx, token); err != nil {
		s.Log.Warn("gitlab: revoking a person's token failed", "err", err)
	}
}

// finishGitLabOAuth is where the callback page posts GitLab's code.
func (s *Server) finishGitLabOAuth(w http.ResponseWriter, r *http.Request) {
	if !s.gitlabReady(w) {
		return
	}
	var req struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	p := principal(r)
	st, err := s.Store.ClaimGitLabState(ctx, req.State, userID(p))
	if err != nil {
		if errors.Is(err, store.ErrGitLabStateInvalid) {
			writeError(w, 400, "gitlab_state", err.Error())
			return
		}
		s.fail(w, r, err)
		return
	}
	if req.Code == "" || len(req.Code) > 500 {
		s.fail(w, r, badRequest("GitLab did not send the authorisation code back; start Connect GitLab again"))
		return
	}
	tok, err := s.GitLab.Exchange(ctx, req.Code, s.gitlabRedirect())
	if err != nil {
		s.Log.Warn("gitlab: code exchange failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not confirm the authorisation; start again")
		return
	}
	want := gitlab.SetupScopes
	if st.Purpose == "readonly" {
		want = gitlab.ReadScopes
	}
	if !tok.HasScopes(want) {
		s.revokeGitLabToken(ctx, tok.AccessToken)
		writeError(w, 400, "gitlab_scopes", "GitLab granted other scopes than asked ("+strings.Join(want, ", ")+"); check the OAuth application's scopes (docs/gitlab.md)")
		return
	}
	switch st.Purpose {
	case "setup":
		s.gitlabSetupGroups(w, r, st, tok)
	case "readonly":
		s.gitlabReadOnly(w, r, st, tok)
	case "cleanup":
		s.gitlabCleanup(w, r, st, tok)
	default:
		s.revokeGitLabToken(ctx, tok.AccessToken)
		writeError(w, 400, "gitlab_state", store.ErrGitLabStateInvalid.Error())
	}
}

type gitlabGroupChoice struct {
	ID          int64  `json:"id"`
	FullPath    string `json:"full_path"`
	Name        string `json:"name"`
	Owner       bool   `json:"owner"`
	AccessLevel int    `json:"access_level"`
}

// gitlabSetupGroups lists the groups the person can connect and keeps
// their token, sealed, for the pick.
func (s *Server) gitlabSetupGroups(w http.ResponseWriter, r *http.Request, st *store.GitLabState, tok *gitlab.Token) {
	ctx := r.Context()
	keep := false
	defer func() {
		if !keep {
			s.revokeGitLabToken(ctx, tok.AccessToken)
		}
	}()
	groups, err := s.GitLab.Groups(ctx, tok.AccessToken, gitlab.AccessReporter)
	if err != nil {
		s.Log.Warn("gitlab: listing groups failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not list your groups; try again in a minute")
		return
	}
	owned, err := s.GitLab.Groups(ctx, tok.AccessToken, gitlab.AccessOwner)
	if err != nil {
		s.Log.Warn("gitlab: listing groups failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not list your groups; try again in a minute")
		return
	}
	isOwner := map[int64]bool{}
	for _, g := range owned {
		isOwner[g.ID] = true
	}
	choices := []gitlabGroupChoice{}
	for _, g := range groups {
		choices = append(choices, gitlabGroupChoice{ID: g.ID, FullPath: g.FullPath, Name: truncate(g.Name, 255), Owner: isOwner[g.ID]})
	}
	if len(choices) == 0 {
		writeError(w, 404, "gitlab_no_groups", "Your GitLab account is not a member (Reporter or above) of any group. Projects in a personal namespace cannot be connected: scan them in CI, or add them as Git repositories.")
		return
	}
	pick, err := s.Store.SetGitLabPick(ctx, s.SecretBox, st.ID, tok.AccessToken)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	keep = true
	writeJSON(w, 200, map[string]any{"pick": pick, "groups": choices, "return_to": st.ReturnTo,
		"expires_at": time.Now().Add(store.GitLabStateTTL).UTC()})
}

// connectGitLabGroup binds the picked group, once the person's token shows
// them a member of it, and creates the group access token and webhook
// where GitLab allows.
func (s *Server) connectGitLabGroup(w http.ResponseWriter, r *http.Request) {
	if !s.gitlabReady(w) {
		return
	}
	var req struct {
		Pick    string          `json:"pick"`
		GroupID json.RawMessage `json:"group_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	p := principal(r)
	userTok, returnTo, err := s.Store.TakeGitLabPick(ctx, s.SecretBox, req.Pick, userID(p))
	if err != nil {
		if errors.Is(err, store.ErrGitLabStateInvalid) {
			writeError(w, 400, "gitlab_state", err.Error())
			return
		}
		s.fail(w, r, err)
		return
	}
	// The person's token is revoked whatever happens below.
	defer s.revokeGitLabToken(ctx, userTok)
	groupID, err := strconv.ParseInt(strings.Trim(string(req.GroupID), `"`), 10, 64)
	if err != nil || groupID <= 0 {
		s.fail(w, r, badRequest("group_id must be the GitLab group's id; start Connect GitLab again"))
		return
	}
	record := func(reason string) {
		s.Log.Warn("gitlab: group refused", "group", groupID, "reason", reason)
		_ = s.Store.Audit(ctx, p.Actor(r), "gitlab.refused", "gitlab_group", strconv.FormatInt(groupID, 10), map[string]string{"reason": reason})
	}
	me, err := s.GitLab.CurrentUser(ctx, userTok)
	if err != nil {
		s.Log.Warn("gitlab: reading the user failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not answer; start Connect GitLab again")
		return
	}
	access, err := s.GitLab.MemberAccess(ctx, userTok, groupID, me.ID)
	if err != nil {
		s.Log.Warn("gitlab: reading the membership failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not answer; start Connect GitLab again")
		return
	}
	if access < gitlab.AccessReporter {
		record("the GitLab user is not a Reporter or above of the group")
		writeError(w, 403, "gitlab_group", "Your GitLab account is not a member (Reporter or above) of that group, so it was not connected.")
		return
	}
	g, err := s.GitLab.Group(ctx, userTok, groupID)
	if err != nil {
		s.Log.Warn("gitlab: reading the group failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not answer; start Connect GitLab again")
		return
	}
	conn, err := s.Store.BindGitLabGroup(ctx, g.ID, g.FullPath, g.Name, userID(p))
	if errors.Is(err, store.ErrGitLabGroupTaken) {
		record("connected to another organisation")
		writeError(w, 409, "gitlab_group_taken", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Connecting again: what Stackurity created before.
	prev, _ := s.Store.GitLabConnectionSecrets(ctx, s.SecretBox, conn.ID)
	notes := []string{}
	// The group access token: Owner only, and GitLab.com's Premium or
	// Ultimate (or a self-managed GitLab).
	tokenKind := "none"
	if access >= gitlab.AccessOwner {
		gt, expires, err := s.GitLab.CreateGroupToken(ctx, userTok, g.ID, time.Now())
		switch {
		case err == nil:
			id := gt.ID
			if err := s.Store.SetGitLabCredential(ctx, s.SecretBox, conn.ID, "group_token", store.GitLabCredential{Token: gt.Token, ExpiresAt: expires},
				&id, &expires); err != nil {
				_ = s.GitLab.RevokeGroupToken(context.WithoutCancel(ctx), userTok, g.ID, gt.ID)
				_ = s.Store.DisconnectGitLab(context.WithoutCancel(ctx), conn.ID, gitlab.NoteDisconnected)
				s.fail(w, r, err)
				return
			}
			tokenKind = "group_token"
			if prev != nil && prev.TokenID != nil && *prev.TokenID != gt.ID {
				_ = s.GitLab.RevokeGroupToken(context.WithoutCancel(ctx), userTok, g.ID, *prev.TokenID)
			}
		case gt != nil:
			// More access than asked: never kept.
			_ = s.GitLab.RevokeGroupToken(context.WithoutCancel(ctx), userTok, g.ID, gt.ID)
			s.Log.Warn("gitlab: group access token refused", "err", err)
		default:
			s.Log.Info("gitlab: group access token not allowed; falling back to a read-only OAuth credential", "group", g.ID, "err", err)
		}
	}
	if tokenKind == "none" && prev != nil && prev.Credential != nil && conn.Status == "active" {
		// Connected again by someone who cannot create a token: the
		// working credential stays.
		tokenKind = prev.Kind
	} else if tokenKind == "none" {
		notes = append(notes, "GitLab did not allow a group access token (it needs the group's Owner role, and GitLab.com or your instance may restrict it by tier or setting): authorise read-only access to finish.")
		_ = s.Store.SetGitLabStatus(ctx, conn.ID, "needs_credential", notes[0])
	}
	// The webhook: Owner, and a tier with group webhooks.
	webhook := "not_permitted"
	switch base := s.baseURL(); {
	case conn.Webhook == "active":
		webhook = "active" // created when it was first connected
	case !strings.HasPrefix(base, "https://"):
		webhook = "none"
		notes = append(notes, "No webhook: the server's address (STACKURITY_BASE_URL) is not https, so projects are scanned on the schedule only.")
	case access >= gitlab.AccessOwner:
		secret, err := gitlabWebhookSecret()
		if err == nil {
			var hookID int64
			hookID, err = s.GitLab.CreateGroupHook(ctx, userTok, g.ID, base+"/api/v1/integrations/gitlab/webhook/"+strconv.FormatInt(conn.ID, 10), secret)
			if err == nil {
				if err = s.Store.SetGitLabWebhook(ctx, conn.ID, "active", &hookID, secret); err == nil {
					webhook = "active"
				} else {
					_ = s.GitLab.DeleteGroupHook(context.WithoutCancel(ctx), userTok, g.ID, hookID)
				}
			}
		}
		if err != nil {
			s.Log.Info("gitlab: group webhook not created", "group", g.ID, "err", err)
		}
	}
	if webhook != "active" {
		_ = s.Store.SetGitLabWebhook(ctx, conn.ID, webhook, nil, "")
		if webhook == "not_permitted" {
			notes = append(notes, "No webhook: GitLab did not allow a group webhook (it needs the group's Owner role and a tier with group webhooks), so projects are scanned on the schedule only.")
		}
	}
	if tokenKind != "none" {
		if err := s.queueGitLabSync(ctx, conn.ID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	_ = s.Store.Audit(ctx, p.Actor(r), "gitlab.connect", "gitlab_group", strconv.FormatInt(g.ID, 10),
		map[string]string{"group": g.FullPath, "credential": tokenKind, "webhook": webhook})
	conn, _ = s.Store.GetGitLabConnection(ctx, conn.ID)
	writeJSON(w, 201, map[string]any{"connection": conn, "needs_readonly": tokenKind == "none", "notes": notes, "return_to": returnTo})
}

// gitlabReadOnly stores the read-only OAuth credential of a connection
// that has no group access token, once the person shows they can read the
// group.
func (s *Server) gitlabReadOnly(w http.ResponseWriter, r *http.Request, st *store.GitLabState, tok *gitlab.Token) {
	ctx := r.Context()
	kept := false
	defer func() {
		if !kept {
			s.revokeGitLabToken(ctx, tok.AccessToken)
		}
	}()
	if st.ConnectionID == nil {
		writeError(w, 400, "gitlab_state", store.ErrGitLabStateInvalid.Error())
		return
	}
	conn, err := s.Store.GetGitLabConnection(ctx, *st.ConnectionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	me, err := s.GitLab.CurrentUser(ctx, tok.AccessToken)
	var access int
	if err == nil {
		access, err = s.GitLab.MemberAccess(ctx, tok.AccessToken, conn.GroupID, me.ID)
	}
	if err != nil {
		s.Log.Warn("gitlab: checking the read-only authorisation failed", "err", err)
		writeError(w, 502, "gitlab_refused", "GitLab did not answer; try again in a minute")
		return
	}
	if access < gitlab.AccessReporter {
		writeError(w, 403, "gitlab_group", "That GitLab account is not a member (Reporter or above) of "+conn.GroupPath+".")
		return
	}
	if tok.RefreshToken == "" {
		writeError(w, 502, "gitlab_refused", "GitLab did not issue a refresh token; check the OAuth application (docs/gitlab.md)")
		return
	}
	if err := s.Store.SetGitLabCredential(ctx, s.SecretBox, conn.ID, "oauth",
		store.GitLabCredential{Token: tok.AccessToken, RefreshToken: tok.RefreshToken, ExpiresAt: tok.ExpiresAt}, nil, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	kept = true
	if err := s.queueGitLabSync(ctx, conn.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "gitlab.authorize", "gitlab_group", strconv.FormatInt(conn.GroupID, 10),
		map[string]string{"group": conn.GroupPath, "credential": "oauth"})
	conn, _ = s.Store.GetGitLabConnection(ctx, conn.ID)
	writeJSON(w, 201, map[string]any{"connection": conn, "return_to": st.ReturnTo})
}

// gitlabCleanup deletes, with the person's token, the webhook and the
// group access token Stackurity created, revokes its OAuth credential, and
// disconnects.
func (s *Server) gitlabCleanup(w http.ResponseWriter, r *http.Request, st *store.GitLabState, tok *gitlab.Token) {
	ctx := r.Context()
	defer s.revokeGitLabToken(ctx, tok.AccessToken)
	if st.ConnectionID == nil {
		writeError(w, 400, "gitlab_state", store.ErrGitLabStateInvalid.Error())
		return
	}
	conn, err := s.Store.GetGitLabConnection(ctx, *st.ConnectionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sec, err := s.Store.GitLabConnectionSecrets(ctx, s.SecretBox, conn.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	result := map[string]any{"webhook_deleted": sec.HookID == nil, "token_revoked": sec.Credential == nil && sec.TokenID == nil}
	if sec.HookID != nil {
		if err := s.GitLab.DeleteGroupHook(ctx, tok.AccessToken, sec.GroupID, *sec.HookID); err != nil {
			s.Log.Warn("gitlab: deleting the group webhook failed", "err", err)
		} else {
			result["webhook_deleted"] = true
		}
	}
	switch {
	case sec.TokenID != nil:
		if err := s.GitLab.RevokeGroupToken(ctx, tok.AccessToken, sec.GroupID, *sec.TokenID); err != nil {
			s.Log.Warn("gitlab: revoking the group access token failed", "err", err)
		} else {
			result["token_revoked"] = true
		}
	case sec.Credential != nil:
		result["token_revoked"] = s.revokeGitLabOAuth(ctx, sec.Credential) == nil
	}
	if err := s.Store.DisconnectGitLab(ctx, conn.ID, gitlab.NoteDisconnected); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "gitlab.disconnect", "gitlab_group", strconv.FormatInt(conn.GroupID, 10),
		map[string]any{"group": conn.GroupPath, "cleanup": result})
	result["disconnected"] = true
	result["return_to"] = st.ReturnTo
	writeJSON(w, 200, result)
}

// disconnectGitLab removes a connection here (its credential and webhook
// secret are deleted with it) and revokes at GitLab what the stored
// credential can: an OAuth credential is revoked; a group access token
// revokes itself. The webhook stays on GitLab (deleting it needs the
// group's Owner: use the cleanup authorisation); its deliveries are
// refused from now on.
func (s *Server) disconnectGitLab(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	conn, err := s.Store.GetGitLabConnection(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sec, err := s.Store.GitLabConnectionSecrets(ctx, s.SecretBox, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DisconnectGitLab(ctx, id, gitlab.NoteDisconnected); err != nil {
		s.fail(w, r, err)
		return
	}
	revoked := sec.Credential == nil
	if s.GitLab != nil && sec.Credential != nil {
		var err error
		if sec.Kind == "oauth" {
			err = s.revokeGitLabOAuth(ctx, sec.Credential)
		} else {
			err = s.GitLab.RevokeSelf(ctx, sec.Credential.Token)
		}
		if err != nil {
			s.Log.Warn("gitlab: revoking the connection's credential failed", "connection", id, "err", err)
		} else {
			revoked = true
		}
	}
	_ = s.Store.Audit(ctx, principal(r).Actor(r), "gitlab.disconnect", "gitlab_group", strconv.FormatInt(conn.GroupID, 10),
		map[string]any{"group": conn.GroupPath, "credential_revoked": revoked})
	writeJSON(w, 200, map[string]any{"credential_revoked": revoked, "webhook_left_on_gitlab": sec.HookID != nil})
}

// revokeGitLabOAuth revokes a stored OAuth credential: the refresh token
// and the access token (GitLab's documentation does not say whether
// revoking one revokes the other).
func (s *Server) revokeGitLabOAuth(ctx context.Context, c *store.GitLabCredential) error {
	return errors.Join(s.GitLab.Revoke(ctx, c.RefreshToken), s.GitLab.Revoke(ctx, c.Token))
}

func (s *Server) queueGitLabSync(ctx context.Context, connID int64) error {
	_, err := s.Store.Enqueue(ctx, "gitlab.sync", map[string]int64{"connection_id": connID}, "gitlab-sync:"+strconv.FormatInt(connID, 10), time.Time{})
	return err
}

// syncGitLabConnection lists the group's projects again now.
func (s *Server) syncGitLabConnection(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err == nil {
		_, err = s.Store.GetGitLabConnection(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.queueGitLabSync(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "gitlab.sync", "gitlab_connection", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 202, map[string]bool{"queued": true})
}

// gitlabWebhook is a connection's webhook URL.
func (s *Server) gitlabWebhook(w http.ResponseWriter, r *http.Request) {
	if s.GitLab == nil {
		writeError(w, 404, "not_found", "no such endpoint")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, gitlabMaxBody+1))
	if err != nil || len(body) > gitlabMaxBody {
		writeError(w, 413, "too_large", "request too large")
		return
	}
	// Nothing is read, and nothing said, before the secret token verifies.
	id, _ := idParam(r, "id")
	ws, err := s.Store.GitLabHookOwner(r.Context(), id, r.Header.Get("X-Gitlab-Token"))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err)
			return
		}
		writeError(w, 401, "unauthorized", "the request could not be verified")
		return
	}
	event, delivery := r.Header.Get("X-Gitlab-Event"), r.Header.Get("X-Gitlab-Event-UUID")
	if event == "" || !gitlabDeliveryRE.MatchString(delivery) {
		writeError(w, 400, "bad_request", "missing X-Gitlab-Event or X-Gitlab-Event-UUID")
		return
	}
	sum := sha256.Sum256(body)
	fresh, err := s.Store.GitLabDeliveryFresh(r.Context(), delivery, sum[:], event)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !fresh {
		writeJSON(w, 200, map[string]string{"result": "duplicate"})
		return
	}
	result, err := s.handleGitLabEvent(tenant.WithWorkspace(r.Context(), ws), id, event, body)
	if err != nil {
		// Let GitLab's retry be handled.
		_ = s.Store.ForgetGitLabDelivery(context.WithoutCancel(r.Context()), delivery)
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"result": result})
}

// handleGitLabEvent acts on a verified delivery; it answers what it did.
func (s *Server) handleGitLabEvent(ctx context.Context, connID int64, event string, body []byte) (string, error) {
	if event != "Push Hook" {
		// Other events (a test delivery, or project and subgroup events
		// where GitLab sends them) may mean the group changed: list it
		// again, from GitLab's API.
		return "sync queued", s.queueGitLabSync(ctx, connID)
	}
	var p gitlab.PushEvent
	if err := json.Unmarshal(body, &p); err != nil {
		return "", badRequest("invalid JSON")
	}
	pid := p.ProjectIDOf()
	if pid <= 0 {
		return "ignored", nil
	}
	proj, err := s.Store.GitLabProjectByID(ctx, connID, pid)
	if errors.Is(err, store.ErrNotFound) {
		// A project Stackurity does not know yet: new in the group.
		return "sync queued", s.queueGitLabSync(ctx, connID)
	}
	if err != nil {
		return "", err
	}
	switch {
	case proj.ConnectionStatus != "active" || proj.Removed || proj.IntegrationID == nil || !proj.IntegrationEnabled:
		return "ignored: project not scanned", nil
	case !p.ToDefaultBranch(proj.DefaultBranch):
		return "ignored: not the default branch", nil
	}
	var exts []lockfile.Extension
	if s.Packs != nil {
		exts = s.Packs.Active(ctx)
	}
	if !p.TouchesInventory(exts) {
		return "ignored: no lockfile or manifest changed", nil
	}
	// A few seconds' delay folds a burst of pushes into one scan.
	if err := s.Store.QueueIntegrationRun(ctx, *proj.IntegrationID, 10*time.Second); err != nil {
		return "", err
	}
	return "scan queued", nil
}

// gitlabWebhookSecret is a group webhook's secret token: 32 random bytes.
func gitlabWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
