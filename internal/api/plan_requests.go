package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
)

// The plan's API requests an hour (docs/asset-limits.md, "Plan limits"):
// people's and API tokens' requests to an organisation, counted in the
// database like the other rate limits (ratelimit.go), so every replica
// shares them. What agents and CI send is not counted: uploads,
// enrollment, the agent's own endpoints, and anything a collector token
// does. Organisations without the limit (every self-hosted one unless an
// instance administrator sets it) are not counted at all.

// uncountedPrefixes are the paths of what agents and CI send.
var uncountedPrefixes = []string{"/api/v1/ingest", "/api/v1/kubernetes/report", "/api/v1/collections/", "/api/v1/sbom/import",
	"/api/v1/agent/", "/api/v1/enroll", "/api/v1/ci/"}

// planCapCache keeps each organisation's cap for a minute, so a request
// costs no extra read of its plan.
type planCapCache struct {
	mu   sync.Mutex
	caps map[int64]planCap
}

type planCap struct {
	n    int64
	read time.Time
}

func (s *Server) planRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p == nil || p.Workspace == 0 || p.Role == auth.RoleCollector || uncounted(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		n, err := s.planCap(r, p.Workspace)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if n > 0 && s.limited(w, r, "your organisation has used its plan's API requests for this hour; try again when the hour ends, "+
			"or upgrade your plan for more", limitHit{"plan-api", itoa(p.Workspace), rateLimit{int(n), time.Hour}}) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func uncounted(path string) bool {
	for _, p := range uncountedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (s *Server) planCap(r *http.Request, ws int64) (int64, error) {
	c := &s.planCaps
	c.mu.Lock()
	got, ok := c.caps[ws]
	c.mu.Unlock()
	if ok && time.Since(got.read) < time.Minute {
		return got.n, nil
	}
	n, err := s.Store.APIRequestsPerHour(r.Context(), ws)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	if c.caps == nil {
		c.caps = map[int64]planCap{}
	}
	c.caps[ws] = planCap{n: n, read: time.Now()}
	c.mu.Unlock()
	return n, nil
}
