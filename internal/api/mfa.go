package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"rsc.io/qr"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Two-factor sign-in: TOTP (RFC 6238) with ten one-time recovery codes
// (docs/install.md, "Two-factor sign-in").
//
// A password sign-in is two requests when the account has a second factor:
// POST /auth/login checks the password and answers {"mfa_required": true}
// with a short-lived challenge cookie, and POST /auth/mfa/verify checks a
// code and starts the session. Single sign-on skips both: the identity
// provider does its own second factor. API tokens and assistants' OAuth
// tokens are not affected, as with GitHub: the page that turns two-factor
// sign-in on lists them.

const mfaCookie = "stackurity_mfa"

var (
	// limitMFAPerUser caps code attempts on one account, from any number of
	// challenges and addresses: guessing a six-digit code needs ~500,000
	// tries on average, so this allows about one success per 50,000 days.
	limitMFAPerUser = rateLimit{10, 15 * time.Minute}
	// mfaChallengeFailures wrong codes end a challenge; the password must
	// then be entered again (and is limited per account too).
	mfaChallengeFailures = 5
)

// completePasswordLogin finishes a sign-in whose password was just
// verified: when u has a second factor it answers {"mfa_required": true}
// and sets the challenge cookie, otherwise it starts the session. Every
// password sign-in must end here, including an edition's own (an owner's
// break-glass password sign-in while single sign-on is required), so the
// account's second factor and its workspace's "Require two-factor sign-in"
// always apply. Single sign-on calls startSession directly.
func (s *Server) completePasswordLogin(w http.ResponseWriter, r *http.Request, u *store.User) {
	has, err := s.Store.HasMFA(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !has {
		s.startSessionWith(w, r, u, store.SessionOpts{PasswordLogin: true}, nil)
		return
	}
	secret, err := s.Store.CreateMFAChallenge(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: secret, Path: "/api/v1/auth/mfa", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(store.MFAChallengeTTL.Seconds())})
	writeJSON(w, 200, map[string]any{"mfa_required": true, "methods": []string{"totp", "recovery_code"}})
}

func (s *Server) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: "", Path: "/api/v1/auth/mfa", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// userActor is the audit actor for u before a session exists.
func userActor(r *http.Request, u *store.User) store.Actor {
	return store.Actor{Type: "user", ID: u.ID, Name: u.Email, RemoteAddr: clientIP(r)}
}

// firstWorkspace scopes ctx to u's first workspace, where sign-in events
// are recorded (as startSession does).
func (s *Server) firstWorkspace(r *http.Request, userID int64) *http.Request {
	ms, err := s.Store.Memberships(r.Context(), userID)
	if err != nil || len(ms) == 0 {
		return r
	}
	return r.WithContext(tenant.WithWorkspace(r.Context(), ms[0].WorkspaceID))
}

// verifyMFA is the second step of a password sign-in.
func (s *Server) verifyMFA(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"mfa", clientIP(r), limitPerAddress}) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := r.Cookie(mfaCookie)
	if err != nil || c.Value == "" {
		writeError(w, 401, "mfa_expired", "the sign-in has expired; enter your email and password again")
		return
	}
	uid, err := s.Store.MFAChallengeUser(r.Context(), c.Value)
	if errors.Is(err, store.ErrNotFound) {
		s.clearMFACookie(w)
		writeError(w, 401, "mfa_expired", "the sign-in has expired; enter your email and password again")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.limited(w, r, "too many codes tried for this account; wait a few minutes", limitHit{"mfa-user", itoa(uid), limitMFAPerUser}) {
		return
	}
	u, err := s.Store.GetUser(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ar := s.firstWorkspace(r, uid)
	method, ok, why, err := s.checkSecondFactor(r, uid, req.Code)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		left, err := s.Store.FailMFAChallenge(r.Context(), c.Value, mfaChallengeFailures)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.Store.Audit(ar.Context(), userActor(r, u), "auth.mfa_failed", "user", itoa(uid), map[string]any{"reason": why})
		if left == 0 {
			s.clearMFACookie(w)
			writeError(w, 401, "mfa_expired", "too many wrong codes; enter your email and password again")
			return
		}
		msg := "that code is not valid"
		if why == "reused" {
			msg = "that code was already used; wait for the next one"
		}
		writeError(w, 401, "mfa_invalid", msg)
		return
	}
	_ = s.Store.DeleteMFAChallenge(r.Context(), c.Value)
	s.clearMFACookie(w)
	s.startSessionWith(w, r, u, store.SessionOpts{PasswordLogin: true, MFA: true}, map[string]any{"mfa": method})
}

// checkSecondFactor checks a TOTP or recovery code for uid. why is
// "invalid" or "reused" when it fails.
func (s *Server) checkSecondFactor(r *http.Request, uid int64, code string) (method string, ok bool, why string, err error) {
	ctx := r.Context()
	if auth.LooksLikeRecoveryCode(code) {
		ok, left, err := s.Store.UseRecoveryCode(ctx, uid, auth.HashRecoveryCode(code))
		if err != nil || !ok {
			return "recovery_code", false, "invalid", err
		}
		u, _ := s.Store.GetUser(ctx, uid)
		if u != nil {
			_ = s.Store.Audit(s.firstWorkspace(r, uid).Context(), userActor(r, u), "auth.mfa_recovery_code_used", "user", itoa(uid),
				map[string]any{"remaining": left})
		}
		return "recovery_code", true, "", nil
	}
	secret, err := s.openTOTP(ctx, uid)
	if errors.Is(err, store.ErrNotFound) {
		return "totp", false, "invalid", nil
	}
	if err != nil {
		return "totp", false, "", err
	}
	step := auth.CheckTOTP(secret, code, time.Now())
	if step == 0 {
		return "totp", false, "invalid", nil
	}
	fresh, err := s.Store.UseTOTPStep(ctx, uid, step)
	if err != nil {
		return "totp", false, "", err
	}
	if !fresh {
		return "totp", false, "reused", nil
	}
	return "totp", true, "", nil
}

func totpSecretName(uid int64) string { return "mfa-totp/" + itoa(uid) }

// errNoSecretKey: two-factor secrets are sealed with STACKURITY_SECRET_KEY.
var errNoSecretKey = errors.New("two-factor sign-in needs STACKURITY_SECRET_KEY on the server; ask your administrator")

// openTOTP decrypts uid's TOTP secret (confirmed or not).
func (s *Server) openTOTP(ctx context.Context, uid int64) (string, error) {
	sealed, _, err := s.Store.TOTPSecret(ctx, uid)
	if err != nil {
		return "", err
	}
	if s.SecretBox == nil {
		return "", errNoSecretKey
	}
	return s.SecretBox.Open(0, totpSecretName(uid), sealed)
}

// sessionUser is the signed-in person of a browser session; other callers
// (API tokens, assistants) get 403.
func (s *Server) sessionUser(w http.ResponseWriter, r *http.Request) *store.User {
	p := principal(r)
	if p == nil || p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "sign in with a session to change two-factor sign-in")
		return nil
	}
	return p.User
}

// recheckPassword asks for the account's password again before a change
// to its second factor, so an unlocked browser is not enough.
func (s *Server) recheckPassword(w http.ResponseWriter, r *http.Request, u *store.User, password string) bool {
	if s.limited(w, r, "too many attempts", limitHit{"password", clientIP(r), limitPerAddress},
		limitHit{"password-user", itoa(u.ID), limitPerAccount}) {
		return false
	}
	ok, err := s.Store.CheckOwnPassword(r.Context(), u.ID, password)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if !ok {
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.password_check_failed", "user", itoa(u.ID), nil)
		writeError(w, 400, "bad_password", "your password is incorrect")
		return false
	}
	return true
}

type mfaStatus struct {
	store.MFAState
	// Required: the current organisation requires two-factor sign-in.
	Required bool `json:"required"`
	// Available: the server can store secrets (STACKURITY_SECRET_KEY).
	Available bool `json:"available"`
	// Tokens and Assistants keep working without a second factor.
	Tokens     int `json:"tokens"`
	Assistants int `json:"assistants"`
}

func (s *Server) mfaStatusOf(r *http.Request, u *store.User) (*mfaStatus, error) {
	st, err := s.Store.MFAStatus(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	out := &mfaStatus{MFAState: st, Available: s.SecretBox != nil}
	if ws := principal(r).Workspace; ws > 0 {
		if out.Required, err = s.Store.WorkspaceRequiresMFA(r.Context(), ws); err != nil {
			return nil, err
		}
	}
	out.Tokens, out.Assistants, err = s.Store.CountCredentials(r.Context(), u.ID)
	return out, err
}

func (s *Server) getMFA(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	st, err := s.mfaStatusOf(r, u)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, st)
}

// startTOTP begins enrolment: a new secret, shown once as a QR code and as
// text, confirmed with a code before it is turned on.
func (s *Server) startTOTP(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.SecretBox == nil {
		writeError(w, 409, "unavailable", errNoSecretKey.Error())
		return
	}
	if !s.recheckPassword(w, r, u, req.Password) {
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sealed, err := s.SecretBox.Seal(0, totpSecretName(u.ID), secret)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.StartTOTPEnrolment(r.Context(), u.ID, sealed); err != nil {
		s.fail(w, r, err)
		return
	}
	issuer := "Stackurity"
	if host := hostOf(s.BaseURL); host != "" {
		issuer = "Stackurity (" + host + ")"
	}
	link := auth.TOTPURL(issuer, u.Email, secret)
	code, err := qr.Encode(link, qr.M)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	code.Scale = 6
	writeJSON(w, 200, map[string]any{"secret": secret, "otpauth_url": link,
		"qr_png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())})
}

func hostOf(base string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	h, _, _ = strings.Cut(h, "/")
	return h
}

// confirmTOTP turns two-factor sign-in on with a code from the app, and
// returns the recovery codes once. The person's other sessions end, and
// this one is replaced by a new one (a new session ID) that counts as
// signed in with a second factor.
func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.limited(w, r, "too many codes tried; wait a few minutes", limitHit{"mfa-user", itoa(u.ID), limitMFAPerUser}) {
		return
	}
	sealed, enabled, err := s.Store.TOTPSecret(r.Context(), u.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && enabled) {
		writeError(w, 409, "conflict", "start setting up two-factor sign-in first")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.SecretBox == nil {
		writeError(w, 409, "unavailable", errNoSecretKey.Error())
		return
	}
	secret, err := s.SecretBox.Open(0, totpSecretName(u.ID), sealed)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	step := auth.CheckTOTP(secret, req.Code, time.Now())
	if step == 0 {
		writeError(w, 400, "mfa_invalid", "that code is not valid; check the time on your phone and try the next code")
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.EnableTOTP(r.Context(), u.ID, step, hashes); err != nil {
		s.fail(w, r, err)
		return
	}
	ended, err := s.Store.EndSessions(r.Context(), u.ID, sessionSecret(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_enabled", "user", itoa(u.ID), map[string]any{"method": "totp", "other_sessions_ended": ended})
	if err := s.rotateSession(w, r, store.SessionOpts{PasswordLogin: true, MFA: true}); err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.mfaStatusOf(r, u)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"recovery_codes": codes, "status": st, "other_sessions_ended": ended})
}

// newRecoveryCodes replaces the recovery codes (the old ones stop working).
func (s *Server) newRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.recheckPassword(w, r, u, req.Password) {
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.ReplaceRecoveryCodes(r.Context(), u.ID, hashes); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_recovery_codes_replaced", "user", itoa(u.ID), nil)
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
}

// disableMFA turns the caller's second factor off, unless one of their
// organisations requires it.
func (s *Server) disableMFA(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.recheckPassword(w, r, u, req.Password) {
		return
	}
	if names, err := s.Store.WorkspacesRequiringMFA(r.Context(), u.ID); err != nil {
		s.fail(w, r, err)
		return
	} else if len(names) > 0 {
		writeError(w, 409, "mfa_required", "two-factor sign-in is required by "+strings.Join(names, ", ")+"; it cannot be turned off")
		return
	}
	had, err := s.Store.DisableMFA(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if had {
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_disabled", "user", itoa(u.ID), nil)
	}
	w.WriteHeader(204)
}

// resetMemberMFA lets an admin remove another member's second factor (a
// lost phone and lost recovery codes). Their sessions end; they sign in
// with their password and, where it is required, set up a new one.
func (s *Server) resetMemberMFA(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	target, err := s.Store.ResetMemberMFA(r.Context(), id, p.User != nil && p.User.InstanceAdmin)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "user.mfa_reset", "user", itoa(id), map[string]any{"email": target})
	w.WriteHeader(204)
}

// Workspace security settings (admin): "Require two-factor sign-in for
// all members".
type securitySettings struct {
	RequireMFA bool `json:"require_mfa"`
	// MembersWithoutMFA is read-only: members who will be asked to set it
	// up at their next password sign-in.
	MembersWithoutMFA int `json:"members_without_mfa"`
}

func (s *Server) getSecuritySettings(w http.ResponseWriter, r *http.Request) {
	ws := principal(r).Workspace
	on, err := s.Store.WorkspaceRequiresMFA(r.Context(), ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := s.Store.MembersWithoutMFA(r.Context(), ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, securitySettings{RequireMFA: on, MembersWithoutMFA: n})
}

func (s *Server) putSecuritySettings(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		RequireMFA bool `json:"require_mfa"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	// Turning it on while signed in with a password and no second factor
	// would send the admin straight to enrolment: set it up first.
	if req.RequireMFA && p.User != nil && !p.User.MFAEnabled && (p.Token != nil || p.PasswordSession) {
		writeError(w, 409, "mfa_required", "set up two-factor sign-in for your own account first (Your account → Two-factor sign-in)")
		return
	}
	if err := s.Store.SetWorkspaceRequireMFA(r.Context(), p.Workspace, req.RequireMFA); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "settings.require_mfa", "workspace", itoa(p.Workspace), map[string]any{"require_mfa": req.RequireMFA})
	s.getSecuritySettings(w, r)
}

// mfaEnrolmentAllows lists what a session sent to enrolment may still do:
// see who it is, set up its second factor, switch organisation, sign out.
func mfaEnrolmentAllows(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/auth/me", path == "/auth/logout", path == "/meta",
		strings.HasPrefix(path, "/auth/mfa"),
		path == "/workspaces" && r.Method == http.MethodGet,
		strings.HasPrefix(path, "/workspaces/") && strings.HasSuffix(path, "/activate"):
		return true
	}
	return false
}

// Routes (server.go): the code step is public; the rest is the caller's
// own account; the admin pieces need the admin role.
func (s *Server) mfaPublicRoutes(r chi.Router) {
	r.Post("/auth/mfa/verify", s.verifyMFA)
}

func (s *Server) mfaAccountRoutes(r chi.Router) {
	r.Get("/auth/mfa", s.getMFA)
	r.Delete("/auth/mfa", s.disableMFA)
	r.Post("/auth/mfa/totp", s.startTOTP)
	r.Post("/auth/mfa/totp/confirm", s.confirmTOTP)
	r.Post("/auth/mfa/recovery-codes", s.newRecoveryCodes)
}

func (s *Server) mfaAdminRoutes(r chi.Router) {
	r.Delete("/users/{id}/mfa", s.resetMemberMFA)
	r.Get("/settings/security", s.getSecuritySettings)
	r.Put("/settings/security", s.putSecuritySettings)
}

func init() {
	// The caller's own second factor, whatever their access.
	for _, r := range []string{"GET /api/v1/auth/mfa", "DELETE /api/v1/auth/mfa", "POST /api/v1/auth/mfa/totp",
		"POST /api/v1/auth/mfa/totp/confirm", "POST /api/v1/auth/mfa/recovery-codes"} {
		projectRoutes[r] = accountScope
	}
}
