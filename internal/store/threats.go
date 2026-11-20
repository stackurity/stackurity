package store

// Threat notices (migration 0118, docs/threat-notices.md): the threats a
// server has known, each organisation's notice per threat with its verdict
// and delivery, and who hid the banner.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ThreatSeen is a catalogue entry the server has known.
type ThreatSeen struct {
	ID       string
	Name     string
	Revision int
	Source   string // embedded or feed
}

// RecordThreatsSeen adds or updates catalogue entries (system scope).
func (s *Store) RecordThreatsSeen(ctx context.Context, list []ThreatSeen) error {
	for _, t := range list {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO threats_seen (id, name, revision, source) VALUES ($1, $2, $3, $4)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, revision = EXCLUDED.revision, source = EXCLUDED.source, updated_at = now()
			WHERE threats_seen.revision <> EXCLUDED.revision OR threats_seen.name <> EXCLUDED.name OR threats_seen.source <> EXCLUDED.source`,
			t.ID, t.Name, t.Revision, t.Source); err != nil {
			return err
		}
	}
	return nil
}

// ThreatEvidence counts the workspace's open findings of these config rules
// and vulnerability ids (a CVE matches an advisory that has it as id, alias
// or group), and the assets they are on. assetIDs lists those assets, at
// most 1,000, for scoping notifications.
func (s *Store) ThreatEvidence(ctx context.Context, rules, vulns []string) (findings, assets int, assetIDs []int64, err error) {
	if rules == nil {
		rules = []string{}
	}
	if vulns == nil {
		vulns = []string{}
	}
	rows, err := s.Pool.Query(ctx, `WITH keys AS (
			SELECT unnest($2::text[]) AS key
			UNION SELECT a.id FROM advisories a WHERE cardinality($2::text[]) > 0
			  AND (a.id = ANY($2) OR a.group_key = ANY($2) OR a.aliases && $2::text[])),
		hits AS (
			SELECT c.asset_id FROM config_findings c JOIN assets x ON x.id = c.asset_id AND x.merged_into IS NULL
			WHERE c.status = 'open' AND c.rule = ANY($1)
			UNION ALL
			SELECT f.asset_id FROM findings f JOIN assets x ON x.id = f.asset_id AND x.merged_into IS NULL
			WHERE f.status = 'open' AND f.kind = 'vulnerability' AND f.verification <> 'rejected'
			  AND f.key IN (SELECT key FROM keys))
		SELECT asset_id, count(*) FROM hits GROUP BY asset_id ORDER BY asset_id`, rules, vulns)
	if err != nil {
		return 0, 0, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return 0, 0, nil, err
		}
		findings += n
		assets++
		if len(assetIDs) < 1000 {
			assetIDs = append(assetIDs, id)
		}
	}
	return findings, assets, assetIDs, rows.Err()
}

// ThreatConnections counts the workspace's live assets per connection a
// threat's check can read (threats.Connections): servers reporting through
// the agent, container images, repositories, cloud services and Kubernetes
// clusters.
func (s *Store) ThreatConnections(ctx context.Context) (map[string]int, error) {
	out := map[string]int{"host_agent": 0, "docker": 0, "repository": 0, "cloud_account": 0, "kubernetes": 0}
	var host, img, repo, cloud, kube int
	err := s.Pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE kind = 'host' AND report_source = 'agent'),
			count(*) FILTER (WHERE kind = 'image'),
			count(*) FILTER (WHERE kind = 'repository'),
			count(*) FILTER (WHERE kind = 'managed_service'),
			count(*) FILTER (WHERE kind = 'cluster')
		FROM assets WHERE merged_into IS NULL AND collection_status <> 'removed'`).Scan(&host, &img, &repo, &cloud, &kube)
	out["host_agent"], out["docker"], out["repository"], out["cloud_account"], out["kubernetes"] = host, img, repo, cloud, kube
	return out, err
}

// ThreatNotice is an organisation's notice about one threat.
type ThreatNotice struct {
	ID              int64          `json:"id"`
	ThreatID        string         `json:"threat_id"`
	Verdict         string         `json:"verdict"`
	NotifiedVerdict string         `json:"notified_verdict"`
	Findings        int            `json:"findings"`
	Assets          int            `json:"assets"`
	Connected       map[string]int `json:"connected"`
	Missing         []string       `json:"missing"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	BannerAt        time.Time      `json:"banner_at"`
	EmailAt         *time.Time     `json:"email_at"`
	EmailResult     string         `json:"email_result"`
	EmailRecipients int            `json:"email_recipients"`
	ChannelsAt      *time.Time     `json:"channels_at"`
	ChannelsQueued  int            `json:"channels_queued"`
	// Dismissed: the caller hid the banner for the current verdict
	// (ListThreatNotices only).
	Dismissed bool `json:"dismissed"`
}

const threatNoticeCols = `n.id, n.threat_id, n.verdict, n.notified_verdict, n.findings, n.assets, n.connected, n.missing, n.created_at,
	n.updated_at, n.banner_at, n.email_at, n.email_result, n.email_recipients, n.channels_at, n.channels_queued`

func scanThreatNotice(row pgx.Row, extra ...any) (*ThreatNotice, error) {
	var n ThreatNotice
	var conn []byte
	dest := []any{&n.ID, &n.ThreatID, &n.Verdict, &n.NotifiedVerdict, &n.Findings, &n.Assets, &conn, &n.Missing, &n.CreatedAt,
		&n.UpdatedAt, &n.BannerAt, &n.EmailAt, &n.EmailResult, &n.EmailRecipients, &n.ChannelsAt, &n.ChannelsQueued}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(conn, &n.Connected); err != nil {
		return nil, err
	}
	if n.Missing == nil {
		n.Missing = []string{}
	}
	return &n, nil
}

// GetThreatNotice returns the workspace's notice for a threat, or
// ErrNotFound.
func (s *Store) GetThreatNotice(ctx context.Context, threatID string) (*ThreatNotice, error) {
	n, err := scanThreatNotice(s.Pool.QueryRow(ctx, `SELECT `+threatNoticeCols+` FROM threat_notices n WHERE n.threat_id = $1`, threatID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return n, err
}

// SaveThreatNotice records the verdict and its evidence. With notify, the
// verdict is also the one people are told now: notified_verdict is set and
// the delivery of every channel starts again (a new banner, email and
// route messages). It returns the notice as stored.
func (s *Store) SaveThreatNotice(ctx context.Context, n ThreatNotice, notify bool) (*ThreatNotice, error) {
	if n.Connected == nil {
		n.Connected = map[string]int{}
	}
	if n.Missing == nil {
		n.Missing = []string{}
	}
	conn, err := json.Marshal(n.Connected)
	if err != nil {
		return nil, err
	}
	return scanThreatNotice(s.Pool.QueryRow(ctx, `INSERT INTO threat_notices AS n (threat_id, verdict, notified_verdict, findings, assets, connected, missing)
		VALUES ($1, $2, $2, $3, $4, $5, $6)
		ON CONFLICT (workspace_id, threat_id) DO UPDATE SET verdict = EXCLUDED.verdict, findings = EXCLUDED.findings,
		  assets = EXCLUDED.assets, connected = EXCLUDED.connected, missing = EXCLUDED.missing, updated_at = now(),
		  notified_verdict = CASE WHEN $7 THEN EXCLUDED.verdict ELSE n.notified_verdict END,
		  banner_at = CASE WHEN $7 THEN now() ELSE n.banner_at END,
		  email_at = CASE WHEN $7 THEN NULL ELSE n.email_at END,
		  email_result = CASE WHEN $7 THEN '' ELSE n.email_result END,
		  email_recipients = CASE WHEN $7 THEN 0 ELSE n.email_recipients END,
		  channels_at = CASE WHEN $7 THEN NULL ELSE n.channels_at END,
		  channels_queued = CASE WHEN $7 THEN 0 ELSE n.channels_queued END
		RETURNING `+threatNoticeCols, n.ThreatID, n.Verdict, n.Findings, n.Assets, conn, n.Missing, notify))
}

// ThreatNoticeEmailed records what happened to the notice's email.
func (s *Store) ThreatNoticeEmailed(ctx context.Context, id int64, result string, recipients int) error {
	_, err := s.Pool.Exec(ctx, `UPDATE threat_notices SET email_at = now(), email_result = $2, email_recipients = $3 WHERE id = $1`,
		id, result, recipients)
	return err
}

// ThreatNoticeQueued records that the notice was given to n notification
// routes.
func (s *Store) ThreatNoticeQueued(ctx context.Context, id int64, n int) error {
	_, err := s.Pool.Exec(ctx, `UPDATE threat_notices SET channels_at = now(), channels_queued = $2 WHERE id = $1`, id, n)
	return err
}

// ListThreatNotices lists the workspace's notices, newest first, each with
// whether userID hid it for its current verdict.
func (s *Store) ListThreatNotices(ctx context.Context, userID int64) ([]ThreatNotice, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+threatNoticeCols+`,
		EXISTS (SELECT 1 FROM threat_notice_dismissals d WHERE d.notice_id = n.id AND d.user_id = $1 AND d.verdict = n.verdict)
		FROM threat_notices n ORDER BY n.banner_at DESC, n.id DESC LIMIT 200`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatNotice{}
	for rows.Next() {
		var dismissed bool
		n, err := scanThreatNotice(rows, &dismissed)
		if err != nil {
			return nil, err
		}
		n.Dismissed = dismissed
		out = append(out, *n)
	}
	return out, rows.Err()
}

// DismissThreatNotice hides a notice's banner for userID, for its current
// verdict. ErrNotFound when the workspace has no such notice.
func (s *Store) DismissThreatNotice(ctx context.Context, id, userID int64) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO threat_notice_dismissals (notice_id, user_id, verdict)
		SELECT n.id, $2, n.verdict FROM threat_notices n WHERE n.id = $1
		ON CONFLICT (notice_id, user_id) DO UPDATE SET verdict = EXCLUDED.verdict, dismissed_at = now()`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ThreatCopyDue is a threat whose owner copy can be sent: every notice was
// first delivered at least a while ago (system scope).
type ThreatCopyDue struct {
	ThreatID string
	// Counts are notices per notified verdict, in every organisation.
	Counts map[string]int
	// Example is one notice of the most common verdict, for rendering an
	// example: its counts and missing connections only.
	Example ThreatNotice
}

// ThreatCopiesDue lists threats with notices, no copy sent yet, and no
// notice created in the last settle (so the first pass over every
// organisation has finished). System scope.
func (s *Store) ThreatCopiesDue(ctx context.Context, settle time.Duration) ([]ThreatCopyDue, error) {
	rows, err := s.Pool.Query(ctx, `SELECT t.id FROM threats_seen t
		WHERE t.copy_sent_at IS NULL AND EXISTS (SELECT 1 FROM threat_notices n WHERE n.threat_id = t.id)
		  AND NOT EXISTS (SELECT 1 FROM threat_notices n WHERE n.threat_id = t.id AND n.created_at > now() - make_interval(secs => $1))
		ORDER BY t.id`, settle.Seconds())
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []ThreatCopyDue
	for _, id := range ids {
		d := ThreatCopyDue{ThreatID: id, Counts: map[string]int{}}
		rows, err := s.Pool.Query(ctx, `SELECT notified_verdict, count(*) FROM threat_notices WHERE threat_id = $1 GROUP BY 1`, id)
		if err != nil {
			return nil, err
		}
		best := ""
		for rows.Next() {
			var v string
			var n int
			if err := rows.Scan(&v, &n); err != nil {
				rows.Close()
				return nil, err
			}
			d.Counts[v] = n
			if best == "" || n > d.Counts[best] || n == d.Counts[best] && v < best {
				best = v
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		ex, err := scanThreatNotice(s.Pool.QueryRow(ctx, `SELECT `+threatNoticeCols+` FROM threat_notices n
			WHERE n.threat_id = $1 AND n.notified_verdict = $2 ORDER BY n.id LIMIT 1`, id, best))
		if err != nil {
			return nil, err
		}
		// The example is rendered from counts only; a later verdict is not
		// the one that was sent.
		ex.Verdict = ex.NotifiedVerdict
		d.Example = *ex
		out = append(out, d)
	}
	return out, nil
}

// ClaimThreatCopy records the owner copy of a threat before it is sent
// (system scope), so that it is sent once. It returns false when it was
// claimed already; ReleaseThreatCopy undoes a claim whose email failed.
func (s *Store) ClaimThreatCopy(ctx context.Context, threatID string, counts map[string]int) (bool, error) {
	b, err := json.Marshal(counts)
	if err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE threats_seen SET copy_sent_at = now(), copy_counts = $2 WHERE id = $1 AND copy_sent_at IS NULL`, threatID, b)
	return tag.RowsAffected() > 0, err
}

// ReleaseThreatCopy makes a claimed copy due again.
func (s *Store) ReleaseThreatCopy(ctx context.Context, threatID string) error {
	_, err := s.Pool.Exec(context.WithoutCancel(ctx), `UPDATE threats_seen SET copy_sent_at = NULL, copy_counts = '{}' WHERE id = $1`, threatID)
	return err
}
