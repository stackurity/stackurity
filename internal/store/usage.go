package store

import (
	"context"
	"fmt"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Usage counts (migration 0110): per organisation and UTC day, how often a
// locked paid-plan notice was seen or clicked, the plan refused something,
// or something was exported. Metadata only: an event and a key from the
// lists below, never a user or any content.
const (
	UsageTeaserView   = "teaser_view"
	UsageTeaserClick  = "teaser_click"
	UsageLimitRefused = "limit_refused"
	UsageExport       = "export"
)

// UsageCountRetention is how long usage counts are kept.
const UsageCountRetention = 400 * 24 * time.Hour

// Export kinds counted with UsageExport.
const (
	ExportSBOM          = "sbom_cyclonedx"
	ExportVEXOpenVEX    = "vex_openvex"
	ExportVEXCycloneDX  = "vex_cyclonedx"
	ExportEvidenceJSON  = "evidence_json"
	ExportEvidencePrint = "evidence_print"
	ExportOutcomesPrint = "outcomes_print"
)

// ClientExportKinds are the exports the web app reports itself (they are
// made in the browser, so the server never sees them).
var ClientExportKinds = map[string]bool{ExportEvidenceJSON: true, ExportEvidencePrint: true, ExportOutcomesPrint: true}

// CountUsage adds one to today's count of event and key for workspace ws.
// It runs in the system scope with the workspace named, so it works from
// any request (also one whose own transaction failed). Callers ignore its
// error: a count is never worth failing a request for.
func (s *Store) CountUsage(ctx context.Context, ws int64, event, key string) error {
	if ws <= 0 {
		return nil
	}
	if !UsageKeyOK(key) {
		return fmt.Errorf("%w: usage key %q", ErrInvalid, key)
	}
	_, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO usage_counts (workspace_id, day, event, key)
		VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2, $3)
		ON CONFLICT (workspace_id, day, event, key) DO UPDATE SET n = usage_counts.n + 1`, ws, event, key)
	return err
}

// UsageKeyOK reports whether k fits the table's check: a short lower-case
// identifier.
func UsageKeyOK(k string) bool {
	if len(k) == 0 || len(k) > 40 {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// PurgeUsageCounts deletes counts older than UsageCountRetention.
func (s *Store) PurgeUsageCounts(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM usage_counts WHERE day < (now() AT TIME ZONE 'UTC')::date - $1::int`,
		int(UsageCountRetention/(24*time.Hour)))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
