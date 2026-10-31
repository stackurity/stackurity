package api

import (
	"context"
	"net/http"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// Email codes, the fallback second factor (docs/install.md, "Two-factor
// sign-in"): six digits sent by the transactional mail, valid for ten
// minutes, used once, limited like app codes. They are off unless a
// workspace allows them; a person turns them on themselves (confirmed with
// a code) only while they have no passkey or authenticator app, and only
// where they count for them: never for security, admin or instance-admin
// roles. Every sign-in with one is followed by a notification email.

var (
	// emailSends bounds the codes sent for one sign-in or confirmation:
	// one every 30 seconds, five in all.
	emailSends = store.SendLimits{Gap: 30 * time.Second, Max: 5}
	// limitEmailCodesPerUser caps codes emailed to one account from any
	// number of sign-ins.
	limitEmailCodesPerUser = rateLimit{6, 15 * time.Minute}
)

// emailCodesAvailable: this server can send email.
func (s *Server) emailCodesAvailable() bool { return s.AccountMail != nil }

// emailCodeOffer reports whether u may turn email codes on, and why not:
// mail must work, u must have no passkey or app, and a workspace of theirs
// must allow email codes and count them for u's role there.
func (s *Server) emailCodeOffer(r *http.Request, u *store.User, methods []string) (bool, string, error) {
	switch {
	case !s.emailCodesAvailable():
		return false, "this server cannot send email", nil
	case u.InstanceAdmin:
		return false, "email codes never count for instance administrators", nil
	}
	for _, m := range methods {
		if m == store.MFAPasskey || m == store.MFATOTP {
			return false, "you already have a passkey or an authenticator app, which are stronger", nil
		}
	}
	ms, err := s.Store.MFAMemberships(r.Context(), u.ID)
	if err != nil {
		return false, "", err
	}
	for _, m := range ms {
		pol, err := s.Store.MFAPolicyOf(r.Context(), m.ID)
		if err != nil {
			return false, "", err
		}
		access, err := s.Store.UserAccess(r.Context(), m.ID, u.ID)
		if err != nil {
			return false, "", err
		}
		if (mfaCase{Policy: pol, Role: access.OrgRole, ProjectRole: access.ProjectRole, InstanceAdmin: u.InstanceAdmin}).counts(store.MFAEmail) {
			return true, "", nil
		}
	}
	return false, "none of your organisations allows email codes for your role", nil
}

// sendEmailCode emails code to u for what ("signing in", "turning on email
// codes", "confirming"): the subject says someone is signing in.
func (s *Server) sendEmailCode(ctx context.Context, r *http.Request, u *store.User, code, what string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	host := hostOf(s.BaseURL)
	where := "Stackurity"
	if host != "" {
		where = "Stackurity (" + host + ")"
	}
	m := notify.Message{Event: "mfa_email_code", Title: "Someone is signing in to Stackurity", At: time.Now().UTC(),
		Summary: []string{
			"Your code for " + what + " to " + where + " as " + u.Email + ":",
			code,
			"It works once, for 10 minutes. Nobody from Stackurity will ask you for it.",
			"If this was not you, someone knows your password: change it now, and tell your administrator. The request came from " + clientIP(r) + ".",
		}}
	return s.AccountMail.SendMail(ctx, []string{u.Email}, m)
}

// notifyEmailCodeSignIn tells u, after the response, that their account was
// signed in to with an email code.
func (s *Server) notifyEmailCodeSignIn(r *http.Request, u *store.User) {
	ip := clientIP(r)
	ctx := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		host := hostOf(s.BaseURL)
		if host == "" {
			host = "Stackurity"
		}
		m := notify.Message{Event: "mfa_email_sign_in", Title: "You signed in to Stackurity with an email code", At: time.Now().UTC(),
			Summary: []string{
				"Your account " + u.Email + " signed in to " + host + " with an email code at " + time.Now().UTC().Format("2 Jan 2006 15:04 UTC") + ", from " + ip + ".",
				"If this was not you, change your password now and tell your administrator.",
				"A passkey or an authenticator app is stronger than email codes: set one up under Your account → Two-factor methods.",
			}}
		if err := s.AccountMail.SendMail(ctx, []string{u.Email}, m); err != nil {
			s.Log.Error("email-code sign-in notification not sent", "err", err)
		}
	}()
}

// sendSignInEmailCode emails a code for the second step of a password
// sign-in (the challenge cookie).
func (s *Server) sendSignInEmailCode(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"mfa", clientIP(r), limitPerAddress}) {
		return
	}
	if !s.emailCodesAvailable() {
		writeError(w, 409, "email_unavailable", "this server cannot send email")
		return
	}
	uid, challenge := s.mfaChallengeUserOf(w, r)
	if uid == 0 {
		return
	}
	u, err := s.Store.GetUser(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if on, err := s.Store.HasEmailMFA(r.Context(), uid); err != nil {
		s.fail(w, r, err)
		return
	} else if !on {
		writeError(w, 409, "no_email_codes", "this account does not use email codes")
		return
	}
	if s.limited(w, r, "too many codes sent to this account; wait a few minutes", limitHit{"mfa-email", itoa(uid), limitEmailCodesPerUser}) {
		return
	}
	code, err := store.NewEmailCode()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.SetChallengeEmailCode(r.Context(), challenge, store.EmailCodeHash(challenge, code), emailSends); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sendEmailCode(r.Context(), r, u, code, "signing in"); err != nil {
		s.Log.Error("email code not sent", "err", err)
		writeError(w, 503, "email_failed", "the email could not be sent; try again in a minute")
		return
	}
	_ = s.Store.Audit(s.firstWorkspace(r, uid).Context(), userActor(r, u), "auth.mfa_email_sent", "user", itoa(uid), map[string]any{"for": "sign_in"})
	w.WriteHeader(204)
}

// --- Your account → Two-factor methods: turning email codes on and off

// beginEmailMFA sends a code that turns email codes on.
func (s *Server) beginEmailMFA(w http.ResponseWriter, r *http.Request) {
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
	methods, err := s.Store.MFAMethods(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ok, why, err := s.emailCodeOffer(r, u, methods); err != nil {
		s.fail(w, r, err)
		return
	} else if !ok {
		writeError(w, 409, "email_codes_unavailable", "email codes are not available: "+why)
		return
	}
	if !s.mayChangeFactors(w, r, u) || !s.recheckPassword(w, r, u, req.Password) {
		return
	}
	s.sendAccountEmailCode(w, r, u, "turning on email codes")
}

// sendAccountEmailCode stores and emails a code bound to this session.
func (s *Server) sendAccountEmailCode(w http.ResponseWriter, r *http.Request, u *store.User, what string) {
	if s.limited(w, r, "too many codes sent to this account; wait a few minutes", limitHit{"mfa-email", itoa(u.ID), limitEmailCodesPerUser}) {
		return
	}
	code, err := store.NewEmailCode()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.SetAccountEmailCode(r.Context(), u.ID, store.EmailCodeHash(sessionSecret(r), code), emailSends); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.sendEmailCode(r.Context(), r, u, code, what); err != nil {
		s.Log.Error("email code not sent", "err", err)
		writeError(w, 503, "email_failed", "the email could not be sent; try again in a minute")
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_email_sent", "user", itoa(u.ID), map[string]any{"for": what})
	w.WriteHeader(204)
}

// confirmEmailMFA turns email codes on with the code sent.
func (s *Server) confirmEmailMFA(w http.ResponseWriter, r *http.Request) {
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
	ok, enabled, err := s.Store.UseAccountEmailCode(r.Context(), u.ID, store.EmailCodeHash(sessionSecret(r), normaliseCode(req.Code)), true, mfaChallengeFailures)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		writeError(w, 400, "mfa_invalid", "that code is not valid; ask for a new one if it is more than 10 minutes old")
		return
	}
	if !enabled {
		writeError(w, 409, "conflict", "email codes are already on")
		return
	}
	ended, err := s.factorChanged(w, r, sessionFactor{method: store.MFAEmail})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditAccount(r, u, "auth.mfa_enabled", map[string]any{"method": store.MFAEmail, "other_sessions_ended": ended})
	s.notifyFactorChange(r, u.Email, "Email codes were turned on for two-factor sign-in", "")
	s.answerFactorChange(w, r, u, map[string]any{"other_sessions_ended": ended})
}

// removeEmailMFA turns the caller's email codes off.
func (s *Server) removeEmailMFA(w http.ResponseWriter, r *http.Request) {
	u, floor := s.removalChecks(w, r, "email codes")
	if u == nil {
		return
	}
	had, err := s.Store.RemoveEmailMFA(r.Context(), u.ID, floor)
	if err != nil {
		s.failRemoval(w, r, err)
		return
	}
	if had {
		f := keepFactor(principal(r))
		if f.method == store.MFAEmail {
			f = sessionFactor{}
		}
		ended, err := s.factorChanged(w, r, f)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.auditAccount(r, u, "auth.mfa_disabled", map[string]any{"methods": []string{store.MFAEmail}, "other_sessions_ended": ended})
		s.notifyFactorChange(r, u.Email, "Email codes were turned off for two-factor sign-in", "")
	}
	w.WriteHeader(204)
}

// sendStepUpEmailCode emails a code that confirms this session.
func (s *Server) sendStepUpEmailCode(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	if !s.emailCodesAvailable() {
		writeError(w, 409, "email_unavailable", "this server cannot send email")
		return
	}
	if on, err := s.Store.HasEmailMFA(r.Context(), u.ID); err != nil {
		s.fail(w, r, err)
		return
	} else if !on {
		writeError(w, 409, "no_email_codes", "this account does not use email codes")
		return
	}
	s.sendAccountEmailCode(w, r, u, "confirming it is you")
}

// normaliseCode drops spaces from a typed code.
func normaliseCode(code string) string {
	out := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		if c := code[i]; c != ' ' && c != '-' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}
