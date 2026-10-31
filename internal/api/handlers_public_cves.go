package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// The public log of new CVEs: when each CVE first reached Stackurity, from
// the feeds that cover every CVE whatever the workspaces run (FIRST's EPSS
// file and CISA's KEV catalogue; migration 0068). It holds public CVE IDs and
// times only, needs no sign-in, and the website shows it on stackurity.ai.

var publicCVEID = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

type publicCVEsResponse struct {
	// TrackingSince is when exact times began; CVEs that arrived earlier
	// have exact false and an added time they arrived on or before.
	TrackingSince *time.Time           `json:"tracking_since,omitempty"`
	CVEs          []store.CVEFirstSeen `json:"cves"`
}

func (s *Server) trackingSince(r *http.Request) (*time.Time, error) {
	t, err := s.Store.CVETrackingSince(r.Context())
	if err != nil || t.IsZero() {
		return nil, err
	}
	return &t, nil
}

// recentCVEs answers GET /public/cves/recent?limit=50&before=<RFC 3339>: the
// CVEs that most recently reached Stackurity, newest first. before pages
// back through older ones.
func (s *Server) recentCVEs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeError(w, 400, "bad_request", "limit must be 1 to 200")
			return
		}
		limit = n
	}
	var before time.Time
	if v := r.URL.Query().Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, 400, "bad_request", "before must be an RFC 3339 time")
			return
		}
		before = t
	}
	cves, err := s.Store.RecentCVEs(r.Context(), before, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	since, err := s.trackingSince(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cves == nil {
		cves = []store.CVEFirstSeen{}
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, 200, publicCVEsResponse{TrackingSince: since, CVEs: cves})
}

// publicCVEs answers GET /public/cves?id=CVE-…&id=CVE-… (or one id with a
// comma-separated list), up to 200 IDs: what is recorded for each. Unknown
// CVEs are left out.
func (s *Server) publicCVEs(w http.ResponseWriter, r *http.Request) {
	var ids []string
	seen := map[string]bool{}
	for _, v := range r.URL.Query()["id"] {
		for _, id := range strings.Split(v, ",") {
			id = strings.ToUpper(strings.TrimSpace(id))
			if id == "" || seen[id] {
				continue
			}
			if !publicCVEID.MatchString(id) {
				writeError(w, 400, "bad_request", "not a CVE ID: "+id)
				return
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 || len(ids) > 200 {
		writeError(w, 400, "bad_request", "give 1 to 200 CVE IDs as id")
		return
	}
	cves, err := s.Store.CVEsFirstSeen(r.Context(), ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	since, err := s.trackingSince(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cves == nil {
		cves = []store.CVEFirstSeen{}
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, publicCVEsResponse{TrackingSince: since, CVEs: cves})
}
