package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
)

// "Get a free key": one click instead of signing up elsewhere and pasting
// the key. The server never calls out for it. The administrator's browser
// goes to Stackurity Cloud (license.KeyLinkURL) with this server's address,
// a one-time state and a hash of the server's id; they sign in there, the
// Cloud issues the key and sends the browser back to
// <base URL>/setup/community-key#key=…&state=…. The fragment never reaches
// any server's logs; the page posts both here, and the key is verified
// offline exactly like a pasted one.
//
// The state is what makes the key arriving this way trustworthy: it is
// random (256 bits), stored only as a hash, valid for keyLinkTTL, works
// once, and only for the instance administrator's browser session that
// asked for it. Without it a link made by someone else could install their
// key on this server.

// keyLinkTTL is how long the trip to Stackurity Cloud may take.
const keyLinkTTL = 15 * time.Minute

// limitKeyLink caps the states one administrator makes.
var limitKeyLink = rateLimit{20, time.Hour}

// keyLinkBase is the server's base URL when it can take a key back from
// Stackurity Cloud: http or https, a host, no credentials, query or
// fragment. "" when it cannot (no STACKURITY_BASE_URL): the dashboard
// then offers the paste flow only.
func (s *Server) keyLinkBase() string {
	if s.KeyRequirement == nil || s.BaseURL == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimRight(s.BaseURL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	return u.String()
}

// keyLinkRefused answers why this server cannot take a key from the
// button now, and reports whether it did.
func (s *Server) keyLinkRefused(w http.ResponseWriter) bool {
	switch {
	case s.KeyRequirement == nil:
		writeError(w, 404, "not_found", "this server does not need a key")
	case s.LicenceFromEnv:
		writeError(w, 409, "conflict", "the licence is set by STACKURITY_LICENSE on this server")
	case paidLicence(s.Licence):
		// A free key would replace it and turn paid features off.
		writeError(w, 409, "conflict", "a paid licence is installed; it already counts as this server's key")
	case s.keyLinkBase() == "":
		writeError(w, 409, "no_base_url", "set STACKURITY_BASE_URL to the dashboard's address to get the key in one click, or paste a key")
	default:
		return false
	}
	return true
}

func paidLicence(h *license.Holder) bool {
	l := h.License()
	return l != nil && l.Edition != license.Community
}

// sessionHash is the hash of the request's session cookie, nil without one.
func sessionHash(r *http.Request) []byte {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	return auth.HashToken(c.Value)
}

// serverIDHash is what the Cloud is told about this installation: a hash
// of its random id, never the id.
func serverIDHash(id string) string {
	if id == "" {
		return ""
	}
	h := sha256.Sum256([]byte("stackurity-server-id:" + id))
	return hex.EncodeToString(h[:16])
}

// startKeyLink makes a one-time state and returns the Cloud address the
// administrator's browser goes to.
func (s *Server) startKeyLink(w http.ResponseWriter, r *http.Request) {
	if s.keyLinkRefused(w) {
		return
	}
	p := principal(r)
	sess := sessionHash(r)
	if !p.Session || sess == nil {
		writeError(w, 403, "forbidden", "getting the key this way needs a browser session")
		return
	}
	if s.limited(w, r, "too many attempts; try again later or paste a key", limitHit{"key-link", strconv.FormatInt(p.User.ID, 10), limitKeyLink}) {
		return
	}
	state, _, err := auth.NewToken("cks")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	expires := time.Now().Add(keyLinkTTL)
	if err := s.Store.CreateKeyLink(r.Context(), auth.HashToken(state), p.User.ID, sess, expires); err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := s.Store.ServerID(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := url.Values{"return": {s.keyLinkBase()}, "state": {state}}
	if h := serverIDHash(id); h != "" {
		q.Set("server_id", h)
	}
	// The values go in the fragment, never a query string: browsers do not
	// send it, so this server's address and the state are in no access log
	// on the way (the Cloud page reads location.hash and posts them).
	writeJSON(w, 201, map[string]any{"url": license.KeyLinkURL + "#" + q.Encode(), "expires_at": expires.UTC()})
}

// errKeyLink is every way a state can fail; the reasons are not told apart.
var errKeyLink = errors.New("this key link was already used, has expired, or was started from another sign-in")

// claimKeyLink installs the key Stackurity Cloud sent back, after
// checking the state it came with.
func (s *Server) claimKeyLink(w http.ResponseWriter, r *http.Request) {
	if s.keyLinkRefused(w) {
		return
	}
	var req struct {
		Key   string `json:"key"`
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	sess := sessionHash(r)
	if !strings.HasPrefix(req.State, "cks_") || len(req.State) > 100 || !p.Session || sess == nil {
		writeError(w, 410, "key_link_invalid", errKeyLink.Error())
		return
	}
	// Taken (deleted) before anything else is checked: one try per state.
	link, err := s.Store.TakeKeyLink(r.Context(), auth.HashToken(req.State))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 410, "key_link_invalid", errKeyLink.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if link.UserID != p.User.ID || subtle.ConstantTimeCompare(link.SessionHash, sess) != 1 || !time.Now().Before(link.ExpiresAt) {
		writeError(w, 410, "key_link_invalid", errKeyLink.Error())
		return
	}
	key := strings.TrimSpace(req.Key)
	l, err := s.parseLicence(key)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	if l.Edition != license.Community {
		s.fail(w, r, badRequest("this is not a free Community key; paste a paid licence under Licence instead"))
		return
	}
	s.installLicence(w, r, key, l, "key_link")
}
