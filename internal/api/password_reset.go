package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Forgotten passwords (docs/install.md, "Forgotten passwords").
//
// POST /auth/password-reset emails a link when the address belongs to an
// account, and answers the same 202 whether or not it does; the lookup and
// the email happen after the answer, so its timing says nothing either.
// The link carries a single-use token (only its hash is stored) that works
// for 15 minutes. Setting a new password with it ends every session of the
// account, disconnects its AI assistants and, if the person chooses, revokes
// its API tokens. It does not sign in, and the account's second factor
// still applies.
//
// Email goes through AccountMail: the platform's mail on Stackurity Cloud,
// STACKURITY_SMTP_* on a self-hosted server. It also needs STACKURITY_BASE_URL:
// the link is never built from the request's Host header, which anyone can
// set. Without both, the sign-in page says to ask an administrator, who sets
// a temporary password the person must change.

var (
	limitResetPerAddress = rateLimit{5, 15 * time.Minute}
	limitResetPerEmail   = rateLimit{3, time.Hour}
)

// passwordResetByEmail reports whether reset links can be emailed.
func (s *Server) passwordResetByEmail() bool { return s.AccountMail != nil && s.BaseURL != "" }

func (s *Server) passwordResetMode() string {
	if s.passwordResetByEmail() {
		return "email"
	}
	return "admin"
}

func (s *Server) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(email, "@") || len(email) > 320 {
		s.fail(w, r, badRequest("a valid email is required"))
		return
	}
	if !s.passwordResetByEmail() {
		writeError(w, 404, "password_reset_unavailable", "this server cannot email password reset links; ask your administrator to set a temporary password")
		return
	}
	// Counted whether or not the account exists.
	if s.limited(w, r, "too many password reset requests; wait a while and try again",
		limitHit{"password-reset", clientIP(r), limitResetPerAddress}, limitHit{"password-reset-email", email, limitResetPerEmail}) {
		return
	}
	ip := clientIP(r)
	ctx := context.WithoutCancel(r.Context())
	go s.sendPasswordReset(ctx, email, ip)
	writeJSON(w, 202, map[string]string{"status": "If an account uses this address, a link to reset its password is on its way. It works for 15 minutes."})
}

// sendPasswordReset makes and emails a reset link for email's account, if
// there is one.
func (s *Server) sendPasswordReset(ctx context.Context, email, ip string) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	token, uid, err := s.Store.CreatePasswordReset(ctx, email)
	if err != nil {
		s.Log.Error("password reset", "err", err)
		return
	}
	if token == "" {
		return
	}
	link := strings.TrimRight(s.BaseURL, "/") + "/reset-password#" + token
	m := notify.Message{Event: "password_reset", Title: "Reset your Stackurity password", At: time.Now().UTC(),
		Summary: []string{
			"Someone (we hope you) asked to reset the password of the Stackurity account " + email + " on " + hostOf(s.BaseURL) + ".",
			"Choose a new password within 15 minutes: " + link,
			"The link works once. Your other sessions will be signed out.",
			"If you did not ask for this, ignore this email: your password stays as it is. The request came from " + ip + ".",
		}}
	actor := store.Actor{Type: "anonymous", Name: email, RemoteAddr: ip}
	wctx := s.userWorkspace(ctx, uid)
	if err := s.AccountMail.SendMail(ctx, []string{email}, m); err != nil {
		s.Log.Error("password reset email not sent", "err", err)
		_ = s.Store.Audit(wctx, actor, "auth.password_reset_email_failed", "user", itoa(uid), nil)
		return
	}
	_ = s.Store.Audit(wctx, actor, "auth.password_reset_requested", "user", itoa(uid), nil)
}

// userWorkspace scopes ctx to the user's first workspace, where account
// events are recorded.
func (s *Server) userWorkspace(ctx context.Context, uid int64) context.Context {
	ms, err := s.Store.Memberships(ctx, uid)
	if err != nil || len(ms) == 0 {
		return ctx
	}
	return tenant.WithWorkspace(ctx, ms[0].WorkspaceID)
}

// previewPasswordReset tells the reset page whose account the link is for
// and how many API tokens it has, so the person can choose to revoke them.
func (s *Server) previewPasswordReset(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"password-reset-link", clientIP(r), limitPerAddress}) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Store.PasswordResetUser(r.Context(), strings.TrimSpace(req.Token))
	if errors.Is(err, store.ErrResetInvalid) {
		writeError(w, 410, "reset_invalid", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tokens, assistants, err := s.Store.CountCredentials(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"email": u.Email, "tokens": tokens, "assistants": assistants})
}

// confirmPasswordReset sets the new password.
func (s *Server) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"password-reset-link", clientIP(r), limitPerAddress}) {
		return
	}
	var req struct {
		Token        string `json:"token"`
		NewPassword  string `json:"new_password"`
		RevokeTokens bool   `json:"revoke_tokens"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.checkNewPassword(r.Context(), req.NewPassword); err != nil {
		s.fail(w, r, err)
		return
	}
	uid, out, err := s.Store.ResetPassword(r.Context(), strings.TrimSpace(req.Token), req.NewPassword,
		store.Revoke{Tokens: req.RevokeTokens, Assistants: true})
	if errors.Is(err, store.ErrResetInvalid) {
		writeError(w, 410, "reset_invalid", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u, _ := s.Store.GetUser(r.Context(), uid)
	name := ""
	if u != nil {
		name = u.Email
	}
	_ = s.Store.Audit(s.userWorkspace(r.Context(), uid), store.Actor{Type: "user", ID: uid, Name: name, RemoteAddr: clientIP(r)},
		"auth.password_reset", "user", itoa(uid), out)
	writeJSON(w, 200, map[string]any{"revoked": out})
}

// checkNewPassword applies the password rules to a password someone
// chooses: 12 to 256 characters, and not in known data breaches when the
// check is on (STACKURITY_BREACHED_PASSWORD_CHECK). An unreachable check
// is logged and the password accepted.
func (s *Server) checkNewPassword(ctx context.Context, pw string) error {
	return auth.CheckNewPassword(ctx, s.Breached, pw, func(err error) {
		s.Log.Warn("breached-password check unavailable; password accepted without it", "err", err)
	})
}

func (s *Server) passwordResetRoutes(r chi.Router) {
	r.Post("/auth/password-reset", s.requestPasswordReset)
	r.Post("/auth/password-reset/preview", s.previewPasswordReset)
	r.Post("/auth/password-reset/confirm", s.confirmPasswordReset)
}

// passwordChangeAllows lists what a session with a temporary password may
// do: see who it is, change it, sign out.
func passwordChangeAllows(r *http.Request) bool {
	switch strings.TrimPrefix(r.URL.Path, "/api/v1") {
	case "/auth/me", "/auth/logout", "/auth/password", "/meta":
		return true
	}
	return false
}

// sessionGate refuses what a restricted session may not do (a temporary
// password to change, a second factor to set up) and reports whether it
// answered.
func sessionGate(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	switch {
	case p.PasswordChangeRequired && !passwordChangeAllows(r):
		writeError(w, 403, "password_change_required", "an administrator set a temporary password; choose your own to continue")
		return true
	case p.MFANeed == mfaEnrol && !mfaEnrolmentAllows(r):
		writeError(w, 403, "mfa_enrolment_required", "your organisation requires two-factor sign-in with "+methodNames(p.MFAAccepted)+"; set it up to continue")
		return true
	case p.MFANeed == mfaStepUp && !mfaStepUpAllows(r):
		writeError(w, 403, "mfa_step_up_required", "your organisation requires you to confirm with "+methodNames(p.MFAAccepted)+" to continue")
		return true
	}
	return false
}

// sessionEnded records a session found past its idle or absolute limit at
// a request (the request then continues signed out).
func (s *Server) sessionEnded(r *http.Request, err error) {
	var exp *store.SessionExpired
	if errors.As(err, &exp) {
		s.Store.AuditSessionExpired(r.Context(), exp, clientIP(r))
	}
}
