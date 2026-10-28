package api

import (
	"context"
	"net/http"
	"time"
)

// Known addresses. The per-account cap on failed sign-ins (ratelimit.go,
// limitAccountFailures) stops guessing spread over many addresses, but
// on its own it would let a botnet keep the owner out by failing on
// purpose. An address (IPv4, or IPv6 /64) the account signed in from with
// the right password in the last knownAddressMemory is exempt from that
// cap. It still has its own per-address backoff, so a guesser who once
// signed in from an address gains nothing there, and a guesser who knows
// the password needs the second factor anyway.
const knownAddressMemory = 30 * 24 * time.Hour

func (s *Server) rememberAddress(r *http.Request, subject string) {
	if err := s.Store.RememberAddress(r.Context(), "login-known", subject, knownAddressMemory); err != nil {
		s.Log.Error("remembering a sign-in address", "err", err)
	}
}

// knownAddress reports whether subject (account and address) signed in
// recently. When it cannot be checked the cap applies (fail closed).
func (s *Server) knownAddress(ctx context.Context, subject string) bool {
	ok, err := s.Store.AddressKnown(ctx, "login-known", subject)
	if err != nil {
		s.Log.Error("checking a sign-in address", "err", err)
		return false
	}
	return ok
}
