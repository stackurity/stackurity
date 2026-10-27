package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/store"
)

// Report mode (docs/asset-limits.md). In trial mode, set on an
// organisation by a hosted edition's trial and never by the core itself,
// reports and exports are shortened and watermarked rather than refused:
// every list keeps its first trialRows rows and says how many more there
// are, summary counts stay complete, and every report, rendered page and
// export carries reportWatermark.

// trialRows is how many rows of each list a trial report keeps.
const trialRows = 10

// ReportTrial goes with a report shortened in trial mode; nil in full mode.
type ReportTrial struct {
	Watermark   string `json:"watermark"`
	RowsPerList int    `json:"rows_per_list"`
	// Omitted counts, per list, the rows left out.
	Omitted map[string]int `json:"omitted"`
	// Notes say the same in words, one per shortened list: "exceptions:
	// trial: 5 more not shown".
	Notes []string `json:"notes"`
}

// reportTrial returns the trial marker for the caller's organisation, or
// nil when its reports are complete.
func (s *Server) reportTrial(r *http.Request) (*ReportTrial, error) {
	mode, err := s.Store.ReportMode(r.Context())
	if err != nil || mode != store.ReportTrial {
		return nil, err
	}
	return &ReportTrial{Watermark: reportWatermark, RowsPerList: trialRows, Omitted: map[string]int{}, Notes: []string{}}, nil
}

// omit records that n rows of list were left out.
func (t *ReportTrial) omit(list string, n int) {
	if n <= 0 {
		return
	}
	t.Omitted[list] += n
	t.Notes = append(t.Notes, list+": trial: "+itoa(int64(n))+" more not shown")
}

// trialClip keeps the first rows of list in trial mode (t not nil) and
// records how many were left out; in full mode it returns list unchanged.
func trialClip[T any](t *ReportTrial, name string, list []T) []T {
	if t == nil || len(list) <= t.RowsPerList {
		return list
	}
	t.omit(name, len(list)-t.RowsPerList)
	return list[:t.RowsPerList]
}
