package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Rate limits on the unauthenticated and credential-checking endpoints are
// counted in the database, so every replica behind a load balancer shares
// them (store.RateLimitHit). Each replica also keeps its own counts as a
// pre-check: once it alone has seen more than the limit in a window, the
// shared count is over it too, and the request is refused without a write.
//
// Every limit fails closed: if the database cannot count a hit the request
// is refused with 503. Each endpoint limited here needs the database to do
// its work anyway (password hashes, the enrollment code, the setup state,
// single sign-on state), so failing open would gain nothing.

// rateLimit is at most n hits per fixed window.
type rateLimit struct {
	n      int
	window time.Duration
}

var (
	// limitPerAddress applies to each client address on sign-in, setup,
	// password change, enrollment and the start of single sign-on.
	limitPerAddress = rateLimit{10, time.Minute}
	// limitPerAccount caps sign-in attempts on one account from any number
	// of addresses, and password changes by one user. Successful attempts
	// count too, so the counter cannot be reset by an attacker; a user
	// locked out by someone else's guessing can sign in again when the
	// window ends, or through single sign-on.
	limitPerAccount = rateLimit{20, 15 * time.Minute}
	// limitSetupTotal caps setup attempts from all addresses together, in
	// case STACKURITY_SETUP_TOKEN was set to something guessable. It only
	// matters before the first admin exists.
	limitSetupTotal = rateLimit{100, time.Hour}
	// limitSSOFlow covers both steps of single sign-on (start and the
	// callback that exchanges the code), so about ten sign-ins a minute.
	limitSSOFlow = rateLimit{20, time.Minute}
)

// limitHit is one counter a request hits: subject (an address, an email, a
// user id) in bucket, under lim.
type limitHit struct {
	bucket, subject string
	lim             rateLimit
}

type rateLimiter struct {
	store *store.Store
	log   *slog.Logger
	local *localLimiter
}

func newRateLimiter(st *store.Store, log *slog.Logger) *rateLimiter {
	return &rateLimiter{store: st, log: log, local: &localLimiter{hits: map[string]*localWindow{}}}
}

// check counts h and reports whether it is within its limit. An error means
// the shared count is unavailable; callers refuse the request.
func (l *rateLimiter) check(ctx context.Context, h limitHit) (bool, error) {
	if !l.local.allow(h.bucket+"\x00"+h.subject, h.lim) {
		return false, nil
	}
	n, err := l.store.RateLimitHit(ctx, h.bucket, h.subject, h.lim.window)
	if err != nil {
		return false, err
	}
	return n <= h.lim.n, nil
}

// allow checks a per-address limit keyed "bucket:address" and fails closed.
// It is used where a request context is not at hand (single sign-on in the
// licensed build); handlers here use Server.limited, which answers 503 rather
// than 429 when the database is down.
func (l *rateLimiter) allow(key string) bool {
	bucket, subject, _ := strings.Cut(key, ":")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := l.check(ctx, limitHit{bucket, subject, limitPerAddress})
	if err != nil {
		l.log.Error("rate limit unavailable; refusing the request", "bucket", bucket, "err", err)
		return false
	}
	return ok
}

// limited counts every hit and, when one is over its limit, answers 429 with
// msg and returns true. It answers 503 and returns true when the limits
// cannot be checked. Every hit is counted even after one is over, so each
// counter sees every attempt.
func (s *Server) limited(w http.ResponseWriter, r *http.Request, msg string, hits ...limitHit) bool {
	over := false
	for _, h := range hits {
		ok, err := s.limiter.check(r.Context(), h)
		if err != nil {
			s.Log.Error("rate limit unavailable; refusing the request", "bucket", h.bucket, "err", err)
			writeError(w, http.StatusServiceUnavailable, "unavailable", "the server cannot check rate limits right now; try again shortly")
			return true
		}
		over = over || !ok
	}
	if over {
		writeError(w, http.StatusTooManyRequests, "rate_limited", msg)
	}
	return over
}

// limitAddress is middleware applying lim per client address.
func (s *Server) limitAddress(bucket string, lim rateLimit, msg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.limited(w, r, msg, limitHit{bucket, clientIP(r), lim}) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// localLimiter is this replica's own count of the same fixed windows, used
// only to refuse early. Windows are aligned to the Unix epoch like the
// shared ones; a replica whose clock is off by a few seconds can refuse a
// hit a few seconds before the shared window ends, never let one through.
type localLimiter struct {
	mu   sync.Mutex
	hits map[string]*localWindow
}

type localWindow struct {
	start time.Time
	end   time.Time
	n     int
}

func (l *localLimiter) allow(key string, lim rateLimit) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 10_000 {
		for k, v := range l.hits {
			if !now.Before(v.end) {
				delete(l.hits, k)
			}
		}
	}
	ms := now.UnixMilli()
	start := time.UnixMilli(ms - ms%lim.window.Milliseconds())
	w := l.hits[key]
	if w == nil || !w.start.Equal(start) {
		w = &localWindow{start: start, end: start.Add(lim.window)}
		l.hits[key] = w
	}
	w.n++
	return w.n <= lim.n
}
