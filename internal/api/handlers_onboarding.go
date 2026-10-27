package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Onboarding (0.9): the first-run flow, the waiting screen, and
// invitations by project. See docs/install.md, "Your first ten minutes".

// limitInvites caps the invitations one organisation sends in an hour, so
// a stolen admin session cannot use its mail server to send spam.
var limitInvites = rateLimit{30, time.Hour}

func (s *Server) getOnboarding(w http.ResponseWriter, r *http.Request) {
	o, err := s.Store.GetOnboarding(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) putOnboarding(w http.ResponseWriter, r *http.Request) {
	var u store.OnboardingUpdate
	if err := decode(r, &u); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateOnboarding(r.Context(), u); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "onboarding.update", "settings", "onboarding", u)
	s.getOnboarding(w, r)
}

// firstResults is the waiting screen's poll: the assets created since
// `since` (in the project chosen, by row-level security), whether their
// first check is done, and what it found.
func (s *Server) firstResults(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			s.fail(w, r, badRequest("since must be an RFC 3339 time"))
			return
		}
		since = t
	}
	list, err := s.Store.FirstResults(r.Context(), since)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(list) > 0 {
		pol, err := s.Store.RiskPolicy(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		focus, err := s.Store.SummarizeFixFocus(r.Context(), 0, pol.ProductionEnvironments, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		now := map[int64]int{}
		for _, a := range focus.Assets {
			now[a.AssetID] = int(a.Groups)
		}
		for i := range list {
			list[i].FixesNow = now[list[i].ID]
		}
	}
	writeJSON(w, 200, all(list))
}

// --- invitations

type invitationRequest struct {
	Email string    `json:"email"`
	Name  string    `json:"name"`
	Role  auth.Role `json:"role"`
	// ProjectID: a role on this project (0: an organisation-wide role).
	ProjectID int64 `json:"project_id"`
}

// createInvitation invites someone by email. Someone who is already a
// member is given the project role at once. The link is emailed through
// the organisation's first email channel; without one (or when sending
// fails) it is returned to copy.
func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if s.limited(w, r, "too many invitations from this organisation; try again in an hour",
		limitHit{"invite-create", itoa(p.Workspace), limitInvites}) {
		return
	}
	var req invitationRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	var project *int64
	if req.ProjectID > 0 {
		project = &req.ProjectID
	} else if req.ProjectID < 0 {
		s.fail(w, r, badRequest("project_id must be a project, or 0 for an organisation-wide role"))
		return
	}
	if !req.Role.ValidUser() {
		s.fail(w, r, badRequest("role must be viewer, engineer, security or admin"))
		return
	}
	uid, member, err := s.Store.MemberByEmail(r.Context(), email)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if member {
		if project == nil {
			writeError(w, 409, "conflict", "this person is already a member; change their role under Settings, Users")
			return
		}
		g, isNew, err := s.Store.SaveGrant(r.Context(), store.GrantInput{ProjectID: project, UserID: &uid, Role: req.Role}, actorUserID(p))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.Store.Audit(r.Context(), p.Actor(r), "access.grant", "access_grant", itoa(g.ID), g)
		status := 200
		if isNew {
			status = 201
		}
		writeJSON(w, status, map[string]any{"granted": true, "grant": g})
		return
	}
	inv, token, err := s.Store.CreateInvitation(r.Context(), email, req.Name, project, req.Role, actorUserID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	link := s.publicURL(r) + "/invite#" + token
	emailed, why := s.emailInvitation(r, inv, link)
	if emailed {
		_ = s.Store.MarkInvitationEmailed(r.Context(), inv.ID)
		inv.EmailedAt = new(time.Time)
		*inv.EmailedAt = time.Now()
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "invitation.create", "invitation", itoa(inv.ID),
		map[string]any{"email": inv.Email, "project_id": inv.ProjectID, "role": inv.Role, "emailed": emailed, "expires_at": inv.ExpiresAt})
	out := map[string]any{"invitation": inv, "emailed": emailed}
	if !emailed {
		// Shown once, to copy; it is not stored.
		out["link"] = link
		out["email_problem"] = why
	}
	writeJSON(w, 201, out)
}

// emailInvitation sends the link through the organisation's first enabled
// email channel. It reports whether it was sent, and if not, why.
func (s *Server) emailInvitation(r *http.Request, inv *store.Invitation, link string) (bool, string) {
	if s.Dispatcher == nil {
		return false, "notifications are not running on this server"
	}
	ch, err := s.Store.FirstEmailChannel(r.Context())
	if err != nil {
		s.Log.Warn("invitation: email channel", "err", err)
		return false, "the email settings could not be read"
	}
	if ch == nil {
		return false, "no email channel is set up; add one under Settings, Notifications to send invitations by email"
	}
	ws, err := s.Store.GetWorkspace(r.Context(), inv.WorkspaceID)
	if err != nil {
		return false, "the organisation could not be read"
	}
	inviter := "An administrator"
	if p := principal(r); p.User != nil {
		inviter = p.User.Email
		if p.User.Name != "" {
			inviter = p.User.Name + " (" + p.User.Email + ")"
		}
	}
	what := "the organisation " + ws.Name
	if inv.ProjectName != "" {
		what = "the project " + inv.ProjectName + " in " + ws.Name
	}
	m := notify.Message{Event: "invitation", Title: "You are invited to " + ws.Name + " on Stackurity", At: time.Now().UTC(),
		Summary: []string{
			fmt.Sprintf("%s invited you to %s, as %s.", inviter, what, inv.Role),
			"Stackurity lists the software on your servers and code, and tells you which fixes matter.",
			fmt.Sprintf("Open the link to accept. It works once, and until %s.", inv.ExpiresAt.UTC().Format("2 January 2006 15:04 MST")),
			"If you did not expect this, ignore this email.",
		},
		Link: link}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := s.Dispatcher.SendEmail(ctx, ch, inv.Email, m); err != nil {
		s.Log.Warn("invitation email failed", "invitation", inv.ID, "channel", ch.ID, "err", err)
		return false, "sending the email failed: " + err.Error()
	}
	return true, ""
}

func (s *Server) listInvitations(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListInvitations(r.Context(), qInt(r, "project_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(list))
}

func (s *Server) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RevokeInvitation(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "invitation.revoke", "invitation", itoa(id), nil)
	w.WriteHeader(204)
}

// --- following an invitation link (no membership needed)

type invitationToken struct {
	Token string `json:"token"`
}

// previewInvitation says what a link is for, so the person can accept it.
// The token travels in the body, never in a URL that could be logged.
func (s *Server) previewInvitation(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"invite", clientIP(r), limitPerAddress}) {
		return
	}
	var req invitationToken
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	pv, err := s.Store.PreviewInvitation(r.Context(), strings.TrimSpace(req.Token))
	if errors.Is(err, store.ErrInvitationInvalid) {
		writeError(w, 410, "invitation_invalid", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"invitation": pv, "signed_in_as": ""}
	if p := principal(r); p != nil && p.User != nil && p.Session {
		out["signed_in_as"] = p.User.Email
	}
	writeJSON(w, 200, out)
}

type acceptRequest struct {
	Token    string `json:"token"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// acceptInvitation joins the organisation the invitation is for, with the
// role it names; nothing in the request can change either. A new account
// is created with the password given; an existing account must be signed
// in. The browser session then works in that organisation.
func (s *Server) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"invite", clientIP(r), limitPerAddress}) {
		return
	}
	var req acceptRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	if p != nil && p.Token != nil {
		writeError(w, 403, "forbidden", "accept an invitation in the browser, not with an API token")
		return
	}
	var signedIn int64
	if p != nil && p.User != nil {
		signedIn = p.User.ID
	}
	res, err := s.Store.AcceptInvitation(r.Context(), strings.TrimSpace(req.Token), signedIn, req.Name, req.Password)
	switch {
	case errors.Is(err, store.ErrInvitationInvalid):
		writeError(w, 410, "invitation_invalid", err.Error())
		return
	case errors.Is(err, store.ErrSignInRequired):
		writeError(w, 409, "sign_in_required", err.Error())
		return
	case errors.Is(err, store.ErrWrongAccount):
		writeError(w, 409, "wrong_account", err.Error())
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithWorkspace(r.Context(), res.WorkspaceID)
	actor := store.Actor{Type: "user", ID: res.UserID, Name: res.Invitation.Email, RemoteAddr: clientIP(r)}
	if res.AccountCreated {
		_ = s.Store.Audit(ctx, actor, "user.create", "user", itoa(res.UserID), map[string]any{"email": res.Invitation.Email, "via": "invitation"})
	}
	_ = s.Store.Audit(ctx, actor, "invitation.accept", "invitation", itoa(res.Invitation.ID),
		map[string]any{"project_id": res.Invitation.ProjectID, "role": res.Invitation.Role, "joined": res.Joined, "account_created": res.AccountCreated})
	if res.Grant != nil {
		_ = s.Store.Audit(ctx, actor, "access.grant", "access_grant", itoa(res.Grant.ID), res.Grant)
	}
	// Work in the organisation just joined: a new session for a new
	// account, the current one switched for a signed-in person.
	if res.AccountCreated {
		secret, err := s.Store.CreateSession(r.Context(), res.UserID, res.WorkspaceID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: secret, Path: "/", HttpOnly: true, Secure: s.CookieSecure,
			SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(store.SessionTTL)})
		_ = s.Store.Audit(ctx, actor, "auth.login", "user", itoa(res.UserID), nil)
	} else if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.Store.SetSessionWorkspace(r.Context(), c.Value, res.UserID, res.WorkspaceID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var project int64
	if res.Invitation.ProjectID != nil {
		project = *res.Invitation.ProjectID
	}
	writeJSON(w, 200, map[string]any{"workspace_id": res.WorkspaceID, "project_id": project, "role": res.Invitation.Role,
		"account_created": res.AccountCreated, "joined": res.Joined})
}
