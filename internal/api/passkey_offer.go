package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// passkeyOfferWindow is how long after a password sign-in the dashboard
// offers to add a passkey ("Sign in with Touch ID or Face ID next time"),
// and adding one then needs no second password: the person typed it a
// moment ago in this session. After it, Your account asks for it as before.
const passkeyOfferWindow = 5 * time.Minute

// justSignedInWithPassword reports whether the request's session was signed
// in with a password (and its second factor, if any) within
// passkeyOfferWindow. Other sign-ins (single sign-on, an invitation, a
// social provider, a passkey) never proved the password in this session.
func justSignedInWithPassword(p *Principal) bool {
	return p != nil && p.Session && p.User != nil && p.Login == store.LoginPassword &&
		!p.AuthAt.IsZero() && time.Since(p.AuthAt) <= passkeyOfferWindow
}

// passkeyOffer reports whether GET /auth/me should offer to add a passkey:
// a session just signed in with a password, an account without a passkey,
// a server where passkeys work, and nothing the organisation's policy asks
// first (that has its own page, which offers passkeys first).
func (s *Server) passkeyOffer(r *http.Request) bool {
	p := principal(r)
	if !justSignedInWithPassword(p) || p.MFANeed != mfaOK || p.PasswordChangeRequired {
		return false
	}
	wa, _ := s.relyingPartyFor()
	if wa == nil {
		return false
	}
	methods, err := s.Store.MFAMethods(r.Context(), p.User.ID)
	if err != nil || slices.Contains(methods, store.MFAPasskey) {
		return false
	}
	why, err := s.factorChangeBlocked(r, p.User)
	return err == nil && why == ""
}

// passwordRecheckSkippable: adding a passkey may skip asking for the
// password again only where the offer applies (passkeyOffer): the request
// sends none, its session signed in with that password moments ago
// (passkeyOfferWindow), and the account has no passkey yet. A stolen session
// cookie therefore cannot add a further passkey to an account that has one,
// and the addition is emailed to the account like any other.
func (s *Server) passwordRecheckSkippable(r *http.Request, password string) bool {
	return password == "" && s.passkeyOffer(r)
}
