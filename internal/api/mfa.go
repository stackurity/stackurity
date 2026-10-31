package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"rsc.io/qr"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Two-factor sign-in (docs/install.md, "Two-factor sign-in"): passkeys and
// security keys (webauthn.go), an authenticator app (TOTP, RFC 6238), ten
// one-time recovery codes backing those up, and email codes as a fallback.
//
// A password sign-in is two requests when the account has a second factor:
// POST /auth/login checks the password and answers {"mfa_required": true}
// with the methods to choose from and a short-lived challenge cookie; then
// POST /auth/mfa/verify checks a code, or /auth/mfa/passkey/begin and
// /finish a passkey, and starts the session. A passkey can also sign in on
// its own (POST /auth/passkey/begin and /finish). Single sign-on skips all
// of this: the identity provider does its own second factor. API tokens and
// assistants' OAuth tokens are not affected, as with GitHub: the page that
// sets up two-factor sign-in lists them.

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
	methods, err := s.Store.MFAMethods(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(methods) == 0 {
		s.loginSucceeded(r, u)
		s.startSessionWith(w, r, u, store.SessionOpts{Login: store.LoginPassword}, nil)
		return
	}
	secret, err := s.Store.CreateMFAChallenge(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: secret, Path: "/api/v1/auth/mfa", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(store.MFAChallengeTTL.Seconds())})
	writeJSON(w, 200, map[string]any{"mfa_required": true, "methods": s.signInMethods(methods)})
}

// signInMethods lists what the second step of a sign-in offers, strongest
// first: a passkey (when this server has a relying party), the app,
// recovery codes for either, and email codes only for an account with
// nothing else.
func (s *Server) signInMethods(methods []string) []string {
	var out []string
	strong := false
	for _, m := range methods {
		switch m {
		case store.MFAPasskey:
			strong = true
			if wa, _ := s.relyingPartyFor(); wa != nil {
				out = append(out, m)
			}
		case store.MFATOTP:
			strong = true
			out = append(out, m)
		}
	}
	if strong {
		return append(out, store.MFARecovery)
	}
	if slices.Contains(methods, store.MFAEmail) {
		return []string{store.MFAEmail}
	}
	return out
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
	var method, why string
	var ok bool
	if on, err2 := s.Store.HasEmailMFA(r.Context(), uid); err2 != nil {
		err = err2
	} else if on {
		// Email codes are only ever an account's sole method.
		method, why = store.MFAEmail, "invalid"
		ok, err = s.Store.UseChallengeEmailCode(r.Context(), c.Value, store.EmailCodeHash(c.Value, normaliseCode(req.Code)))
	} else {
		method, ok, why, err = s.checkSecondFactor(r, uid, req.Code)
	}
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
		_ = s.Store.Audit(ar.Context(), userActor(r, u), "auth.mfa_failed", "user", itoa(uid), map[string]any{"reason": why, "method": method})
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
	s.loginSucceeded(r, u)
	if method == store.MFAEmail && s.emailCodesAvailable() {
		s.notifyEmailCodeSignIn(r, u)
	}
	s.startSessionWith(w, r, u, store.SessionOpts{Login: store.LoginPassword, MFA: method}, map[string]any{"mfa": method})
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
	// Passkeys are the account's passkeys and security keys.
	Passkeys []store.Passkey `json:"passkeys"`
	// Required: the current organisation requires a second factor of this
	// person; Accepted lists the methods that count there.
	Required bool     `json:"required"`
	Accepted []string `json:"accepted"`
	// Need is what the current session must do there: "" (nothing),
	// "enrol" (set up one of Accepted) or "step_up" (confirm with one).
	Need mfaNeed `json:"need"`
	// RequiredBy names the organisations whose policy the person's
	// factors must keep meeting (removing one below it is refused).
	RequiredBy []string `json:"required_by"`
	// Available: the server can store authenticator-app secrets
	// (STACKURITY_SECRET_KEY).
	Available bool `json:"available"`
	// PasskeysAvailable: passkeys work on this server (STACKURITY_BASE_URL
	// with a domain name over https); PasskeysUnavailable says why not.
	PasskeysAvailable   bool   `json:"passkeys_available"`
	PasskeysUnavailable string `json:"passkeys_unavailable,omitempty"`
	// RPID is the domain passkeys are registered for.
	RPID string `json:"rp_id,omitempty"`
	// EmailOffered: the person may turn email codes on (the fallback);
	// EmailUnavailable says why not.
	EmailOffered     bool   `json:"email_offered"`
	EmailUnavailable string `json:"email_unavailable,omitempty"`
	// Tokens and Assistants keep working without a second factor.
	Tokens     int `json:"tokens"`
	Assistants int `json:"assistants"`
}

func (s *Server) mfaStatusOf(r *http.Request, u *store.User) (*mfaStatus, error) {
	st, err := s.Store.MFAStatus(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	out := &mfaStatus{MFAState: st, Available: s.SecretBox != nil, Accepted: []string{}, RequiredBy: []string{}}
	if out.Passkeys, err = s.Store.ListPasskeys(r.Context(), u.ID); err != nil {
		return nil, err
	}
	if out.Passkeys == nil {
		out.Passkeys = []store.Passkey{}
	}
	if wa, why := s.relyingPartyFor(); wa != nil {
		out.PasskeysAvailable, out.RPID = true, wa.Config.RPID
	} else {
		out.PasskeysUnavailable = why
	}
	p := principal(r)
	if p.Workspace > 0 {
		pol, err := s.Store.MFAPolicyOf(r.Context(), p.Workspace)
		if err != nil {
			return nil, err
		}
		c := mfaCase{Policy: pol, Role: p.Role, ProjectRole: p.ProjectRole, InstanceAdmin: u.InstanceAdmin, Session: p.MFAMethod, Methods: st.Methods}
		out.Required, out.Accepted, out.Need = c.required(), c.accepted(), p.MFANeed
	}
	ms, err := s.Store.MFAMemberships(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		pol, err := s.Store.MFAPolicyOf(r.Context(), m.ID)
		if err != nil {
			return nil, err
		}
		if !pol.RequiresAny() {
			continue
		}
		access, err := s.Store.UserAccess(r.Context(), m.ID, u.ID)
		if err != nil {
			return nil, err
		}
		if (mfaCase{Policy: pol, Role: access.OrgRole, ProjectRole: access.ProjectRole}).required() {
			out.RequiredBy = append(out.RequiredBy, m.Name)
		}
	}
	if out.EmailOffered, out.EmailUnavailable, err = s.emailCodeOffer(r, u, st.Methods); err != nil {
		return nil, err
	}
	if st.Email {
		out.EmailOffered, out.EmailUnavailable = false, ""
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
	if !s.mayChangeFactors(w, r, u) || !s.recheckPassword(w, r, u, req.Password) {
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
	if !s.mayChangeFactors(w, r, u) {
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
	hadEmail, err := s.Store.HasEmailMFA(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	issued, err := s.Store.EnableTOTP(r.Context(), u.ID, step, hashes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if hadEmail {
		s.auditAccount(r, u, "auth.mfa_disabled", map[string]any{"methods": []string{store.MFAEmail}, "reason": "replaced by the authenticator app"})
	}
	if !issued {
		codes = nil
	}
	ended, err := s.factorChanged(w, r, sessionFactor{method: store.MFATOTP})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditAccount(r, u, "auth.mfa_enabled", map[string]any{"method": "totp", "other_sessions_ended": ended, "recovery_codes_issued": issued})
	change := "An authenticator app was set up for two-factor sign-in"
	if hadEmail {
		change += " (it replaces email codes, which were turned off)"
	}
	s.notifyFactorChange(r, u.Email, change, "")
	s.answerFactorChange(w, r, u, map[string]any{"recovery_codes": codes, "other_sessions_ended": ended})
}

// sessionFactor is what a session counts as signed in with after a factor
// change: a method and, for a passkey, which one.
type sessionFactor struct {
	method string
	cred   int64
}

// keepFactor keeps the session's own second factor.
func keepFactor(p *Principal) sessionFactor { return sessionFactor{p.MFAMethod, p.MFACredential} }

// factorChanged follows a second factor added or removed: the account's
// other sessions end, and this one gets a new ID, signed in with f (the
// factor just proved for an addition; for a removal its own, or none when
// the factor removed was the one it used).
func (s *Server) factorChanged(w http.ResponseWriter, r *http.Request, f sessionFactor) (int64, error) {
	p := principal(r)
	ended, err := s.Store.EndSessions(r.Context(), p.User.ID, sessionSecret(r))
	if err != nil {
		return 0, err
	}
	return ended, s.rotateSession(w, r, store.SessionOpts{Login: p.Login, MFA: f.method, MFACredential: f.cred})
}

// answerFactorChange answers with out and the account's new status.
func (s *Server) answerFactorChange(w http.ResponseWriter, r *http.Request, u *store.User, out map[string]any) {
	st, err := s.mfaStatusOf(r, u)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out["status"] = st
	writeJSON(w, 200, out)
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
	if !s.mayChangeFactors(w, r, u) || !s.recheckPassword(w, r, u, req.Password) {
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
	s.auditAccount(r, u, "auth.mfa_recovery_codes_replaced", nil)
	s.notifyFactorChange(r, u.Email, "New recovery codes were made, and the old ones stopped working,", "")
	writeJSON(w, 200, map[string]any{"recovery_codes": codes})
}

// disableMFA removes every second factor of the caller (passkeys, the app,
// email codes), unless one of their organisations requires one.
func (s *Server) disableMFA(w http.ResponseWriter, r *http.Request) {
	u, floor := s.removalChecks(w, r, "two-factor sign-in")
	if u == nil {
		return
	}
	had, err := s.Store.DisableMFA(r.Context(), u.ID, floor)
	if err != nil {
		s.failRemoval(w, r, err)
		return
	}
	if len(had) > 0 {
		ended, err := s.factorChanged(w, r, sessionFactor{})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.auditAccount(r, u, "auth.mfa_disabled", map[string]any{"methods": had, "other_sessions_ended": ended})
		s.notifyFactorChange(r, u.Email, "Two-factor sign-in was turned off (every passkey, authenticator app and email code removed)", "")
	}
	w.WriteHeader(204)
}

// removeTOTP removes the caller's authenticator app.
func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request) {
	u, floor := s.removalChecks(w, r, "the authenticator app")
	if u == nil {
		return
	}
	had, err := s.Store.RemoveTOTP(r.Context(), u.ID, floor)
	if err != nil {
		s.failRemoval(w, r, err)
		return
	}
	if had {
		f := keepFactor(principal(r))
		if f.method == store.MFATOTP {
			f = sessionFactor{}
		}
		ended, err := s.factorChanged(w, r, f)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.auditAccount(r, u, "auth.mfa_disabled", map[string]any{"methods": []string{store.MFATOTP}, "other_sessions_ended": ended})
		s.notifyFactorChange(r, u.Email, "The authenticator app was removed from two-factor sign-in", "")
	}
	w.WriteHeader(204)
}

// removalChecks checks a request to remove second factors: a session that
// may change them, and the password again. The floor it returns, which the
// store calls inside the removal's transaction, refuses when the factors
// kept would no longer meet the policy of an organisation of the caller.
// It answers and returns a nil user when the request may not go on.
func (s *Server) removalChecks(w http.ResponseWriter, r *http.Request, what string) (*store.User, store.MFAFloor) {
	u := s.sessionUser(w, r)
	if u == nil {
		return nil, nil
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return nil, nil
	}
	if !s.mayChangeFactors(w, r, u) || !s.recheckPassword(w, r, u, req.Password) {
		return nil, nil
	}
	return u, func(remaining []string) error {
		name, err := s.mfaRemovalBlocked(r, u, remaining)
		if err != nil {
			return err
		}
		if name != "" {
			return &mfaFloorError{workspace: name, what: what}
		}
		return nil
	}
}

// mfaFloorError: a removal would leave an organisation's policy unmet.
type mfaFloorError struct{ workspace, what string }

func (e *mfaFloorError) Error() string {
	return e.workspace + " requires two-factor sign-in that " + e.what + " is needed for; set up another method first"
}

// failRemoval answers a failed removal: 409 mfa_required when the policy
// floor refused it.
func (s *Server) failRemoval(w http.ResponseWriter, r *http.Request, err error) {
	var floor *mfaFloorError
	if errors.As(err, &floor) {
		writeError(w, 409, "mfa_required", floor.Error())
		return
	}
	s.fail(w, r, err)
}

// mayChangeFactors refuses (and answers) a change to the caller's second
// factors from a session that must first confirm with one it has in any of
// their organisations, not only the one it works in: otherwise a phished
// password and app code could add the attacker's passkey from a workspace
// with a weaker policy, then switch back to one where only passkeys count.
func (s *Server) mayChangeFactors(w http.ResponseWriter, r *http.Request, u *store.User) bool {
	name, err := s.mfaStepUpSomewhere(r, u)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if name != "" {
		writeError(w, 403, "mfa_step_up_required", name+" requires you to confirm this session with a second factor you have before you change your factors")
		return false
	}
	return true
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
	target, removed, err := s.Store.ResetMemberMFA(r.Context(), id, p.User != nil && p.User.InstanceAdmin)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "user.mfa_reset", "user", itoa(id), map[string]any{"email": target, "methods": removed})
	admin := "an administrator"
	if p.User != nil {
		admin = p.User.Email
	}
	s.notifyFactorChange(r, target, "Your two-factor sign-in was reset (every passkey, authenticator app, email code and recovery code removed)", admin)
	w.WriteHeader(204)
}

// Routes (server.go): the code step is public; the rest is the caller's
// own account; the admin pieces need the admin role.
func (s *Server) mfaPublicRoutes(r chi.Router) {
	r.Post("/auth/mfa/verify", s.verifyMFA)
	r.Post("/auth/mfa/passkey/begin", s.beginPasskeySecondFactor)
	r.Post("/auth/mfa/passkey/finish", s.finishPasskeySecondFactor)
	r.Post("/auth/mfa/email/send", s.sendSignInEmailCode)
	r.Post("/auth/passkey/begin", s.beginPasswordless)
	r.Post("/auth/passkey/finish", s.finishPasswordless)
}

func (s *Server) mfaAccountRoutes(r chi.Router) {
	r.Get("/auth/mfa", s.getMFA)
	r.Delete("/auth/mfa", s.disableMFA)
	r.Post("/auth/mfa/totp", s.startTOTP)
	r.Post("/auth/mfa/totp/confirm", s.confirmTOTP)
	r.Delete("/auth/mfa/totp", s.removeTOTP)
	r.Post("/auth/mfa/recovery-codes", s.newRecoveryCodes)
	r.Post("/auth/mfa/passkeys/begin", s.beginPasskeyRegistration)
	r.Post("/auth/mfa/passkeys/finish", s.finishPasskeyRegistration)
	r.Patch("/auth/mfa/passkeys/{id}", s.renamePasskey)
	r.Delete("/auth/mfa/passkeys/{id}", s.removePasskey)
	r.Post("/auth/mfa/email", s.beginEmailMFA)
	r.Post("/auth/mfa/email/confirm", s.confirmEmailMFA)
	r.Delete("/auth/mfa/email", s.removeEmailMFA)
	r.Post("/auth/mfa/step-up", s.stepUpCode)
	r.Post("/auth/mfa/step-up/email/send", s.sendStepUpEmailCode)
	r.Post("/auth/mfa/step-up/passkey/begin", s.beginPasskeyStepUp)
	r.Post("/auth/mfa/step-up/passkey/finish", s.finishPasskeyStepUp)
}

func (s *Server) mfaAdminRoutes(r chi.Router) {
	r.Delete("/users/{id}/mfa", s.resetMemberMFA)
	r.Get("/settings/security", s.getSecuritySettings)
	r.Put("/settings/security", s.putSecuritySettings)
}

func init() {
	// The caller's own second factor, whatever their access.
	for _, r := range []string{"GET /api/v1/auth/mfa", "DELETE /api/v1/auth/mfa", "POST /api/v1/auth/mfa/totp",
		"POST /api/v1/auth/mfa/totp/confirm", "DELETE /api/v1/auth/mfa/totp", "POST /api/v1/auth/mfa/recovery-codes",
		"POST /api/v1/auth/mfa/passkeys/begin", "POST /api/v1/auth/mfa/passkeys/finish", "PATCH /api/v1/auth/mfa/passkeys/{id}",
		"DELETE /api/v1/auth/mfa/passkeys/{id}", "POST /api/v1/auth/mfa/step-up", "POST /api/v1/auth/mfa/step-up/passkey/begin",
		"POST /api/v1/auth/mfa/step-up/passkey/finish", "POST /api/v1/auth/mfa/email", "POST /api/v1/auth/mfa/email/confirm",
		"DELETE /api/v1/auth/mfa/email", "POST /api/v1/auth/mfa/step-up/email/send"} {
		projectRoutes[r] = accountScope
	}
}
