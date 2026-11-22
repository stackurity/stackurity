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

// ThreatsFirstSeen returns when this installation first knew each threat
// (threats_seen.first_seen_at).
func (s *Store) ThreatsFirstSeen(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, first_seen_at FROM threats_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = at
	}
	return out, rows.Err()
}

// ThreatEvidence counts the workspace's open findings of these config rules
// and vulnerability ids (a CVE matches an advisory that has it as id, alias
// or group), and the assets they are on. assetIDs lists those assets, at
// most 1,000, for scoping notifications. signals counts open findings of
// the signal rules (weaker evidence, never counted as findings).
func (s *Store) ThreatEvidence(ctx context.Context, rules, vulns, signalRules []string) (findings, assets, signals int, assetIDs []int64, err error) {
	if rules == nil {
		rules = []string{}
	}
	if vulns == nil {
		vulns = []string{}
	}
	if signalRules == nil {
		signalRules = []string{}
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
		return 0, 0, 0, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return 0, 0, 0, nil, err
		}
		findings += n
		assets++
		if len(assetIDs) < 1000 {
			assetIDs = append(assetIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, nil, err
	}
	if len(signalRules) > 0 {
		err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM config_findings c JOIN assets x ON x.id = c.asset_id AND x.merged_into IS NULL
			WHERE c.status = 'open' AND c.rule = ANY($1)`, signalRules).Scan(&signals)
	}
	return findings, assets, signals, assetIDs, err
}

// ConnectionVersion counts a workspace's live assets of one connection a
// threat's check can read (threats.Connections) by the collector version
// of their latest complete collection ("" when it recorded none, or the
// asset has no complete collection).
type ConnectionVersion struct {
	Connection string
	Collector  string // the collector id of that collection
	Version    string
	Assets     int
}

// ThreatConnectionVersions counts the workspace's live assets per
// connection and collector version: servers reporting through the agent,
// container images, repositories, cloud services and Kubernetes clusters.
// A check only ran on an asset whose collector had it, so the caller
// compares the version with the threat's min_version.
func (s *Store) ThreatConnectionVersions(ctx context.Context) ([]ConnectionVersion, error) {
	rows, err := s.Pool.Query(ctx, `SELECT x.conn, COALESCE(l.collector_id, ''), COALESCE(l.collector_version, ''), count(*) FROM (
			SELECT a.id, CASE WHEN a.kind = 'host' AND a.report_source = 'agent' THEN 'host_agent'
			            WHEN a.kind = 'image' THEN 'docker'
			            WHEN a.kind = 'repository' THEN 'repository'
			            WHEN a.kind = 'managed_service' THEN 'cloud_account'
			            WHEN a.kind = 'cluster' THEN 'kubernetes' END AS conn
			FROM assets a WHERE a.merged_into IS NULL AND a.collection_status <> 'removed') x
		LEFT JOIN LATERAL (SELECT c.collector_id, c.collector_version FROM collections c WHERE c.asset_id = x.id AND c.complete
			ORDER BY c.received_at DESC, c.id DESC LIMIT 1) l ON true
		WHERE x.conn IS NOT NULL GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ConnectionVersion])
}

// ToldFacts are a notice's facts as they were told.
type ToldFacts struct {
	Findings  int            `json:"findings"`
	Assets    int            `json:"assets"`
	Signals   int            `json:"signals"`
	Connected map[string]int `json:"connected"`
	Outdated  map[string]int `json:"outdated"`
	Missing   []string       `json:"missing"`
	AssetIDs  []int64        `json:"asset_ids"`
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
	Outdated        map[string]int `json:"outdated"`
	Signals         int            `json:"signals"`
	Missing         []string       `json:"missing"`
	// Told is what people were told with NotifiedVerdict (SaveThreatNotice
	// with NoticeTell records the notice as it is then).
	Told            ToldFacts  `json:"-"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	BannerAt        time.Time  `json:"banner_at"`
	EmailAt         *time.Time `json:"email_at"`
	EmailResult     string     `json:"email_result"`
	EmailRecipients int        `json:"email_recipients"`
	EmailAttempts   int        `json:"email_attempts"`
	ChannelsAt      *time.Time `json:"channels_at"`
	ChannelsQueued  int        `json:"channels_queued"`
	// Dismissed: the caller hid the banner for the current verdict
	// (ListThreatNotices only).
	Dismissed bool `json:"dismissed"`
}

const threatNoticeCols = `n.id, n.threat_id, n.verdict, n.notified_verdict, n.findings, n.assets, n.connected, n.outdated, n.signals,
	n.missing, n.told, n.created_at, n.updated_at, n.banner_at, n.email_at, n.email_result, n.email_recipients, n.email_attempts, n.channels_at,
	n.channels_queued`

func scanThreatNotice(row pgx.Row, extra ...any) (*ThreatNotice, error) {
	var n ThreatNotice
	var conn, old, told []byte
	dest := []any{&n.ID, &n.ThreatID, &n.Verdict, &n.NotifiedVerdict, &n.Findings, &n.Assets, &conn, &old, &n.Signals, &n.Missing,
		&told, &n.CreatedAt, &n.UpdatedAt, &n.BannerAt, &n.EmailAt, &n.EmailResult, &n.EmailRecipients, &n.EmailAttempts, &n.ChannelsAt,
		&n.ChannelsQueued}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(conn, &n.Connected); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(old, &n.Outdated); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(told, &n.Told); err != nil {
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

// How SaveThreatNotice treats the verdict people were last told.
type NoticeSave int

const (
	// NoticeQuiet records the verdict; people are not told.
	NoticeQuiet NoticeSave = iota
	// NoticeTell: the verdict is what people are told now. notified_verdict
	// is set, the banner moves (showing again for those who hid it) and
	// every channel's delivery starts over.
	NoticeTell
	// NoticeReset: the verdict improved from what people were told (a found
	// threat was fixed); notified_verdict follows it quietly, so a later
	// "found" is news again. Delivery and the banner are not touched.
	NoticeReset
)

// SaveThreatNotice records the verdict and its evidence (see NoticeSave),
// and returns the notice as stored. With NoticeTell, n.Told is recorded as
// what people are told (assetIDs: the assets with findings); NoticeReset
// gives up an email still being retried, which spoke of the old verdict.
func (s *Store) SaveThreatNotice(ctx context.Context, n ThreatNotice, mode NoticeSave) (*ThreatNotice, error) {
	if n.Connected == nil {
		n.Connected = map[string]int{}
	}
	if n.Outdated == nil {
		n.Outdated = map[string]int{}
	}
	if n.Missing == nil {
		n.Missing = []string{}
	}
	conn, err := json.Marshal(n.Connected)
	if err != nil {
		return nil, err
	}
	old, err := json.Marshal(n.Outdated)
	if err != nil {
		return nil, err
	}
	tell := mode == NoticeTell
	told, err := json.Marshal(ToldFacts{Findings: n.Findings, Assets: n.Assets, Signals: n.Signals, Connected: n.Connected,
		Outdated: n.Outdated, Missing: n.Missing, AssetIDs: n.Told.AssetIDs})
	if err != nil {
		return nil, err
	}
	return scanThreatNotice(s.Pool.QueryRow(ctx, `INSERT INTO threat_notices AS n (threat_id, verdict, notified_verdict, findings, assets,
		  connected, outdated, signals, missing, told)
		VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $11)
		ON CONFLICT (workspace_id, threat_id) DO UPDATE SET verdict = EXCLUDED.verdict, findings = EXCLUDED.findings,
		  assets = EXCLUDED.assets, connected = EXCLUDED.connected, outdated = EXCLUDED.outdated, signals = EXCLUDED.signals,
		  missing = EXCLUDED.missing, updated_at = now(),
		  notified_verdict = CASE WHEN $9 OR $10 THEN EXCLUDED.verdict ELSE n.notified_verdict END,
		  told = CASE WHEN $9 THEN EXCLUDED.told ELSE n.told END,
		  banner_at = CASE WHEN $9 THEN clock_timestamp() ELSE n.banner_at END,
		  email_at = CASE WHEN $9 THEN NULL WHEN $10 THEN COALESCE(n.email_at, now()) ELSE n.email_at END,
		  email_result = CASE WHEN $9 THEN '' ELSE n.email_result END,
		  email_recipients = CASE WHEN $9 THEN 0 ELSE n.email_recipients END,
		  email_attempts = CASE WHEN $9 THEN 0 ELSE n.email_attempts END,
		  channels_at = CASE WHEN $9 THEN NULL ELSE n.channels_at END,
		  channels_queued = CASE WHEN $9 THEN 0 ELSE n.channels_queued END
		RETURNING `+threatNoticeCols, n.ThreatID, n.Verdict, n.Findings, n.Assets, conn, old, n.Signals, n.Missing, tell, mode == NoticeReset,
		told))
}

// ThreatEmailAttempts is how often a failed notice email is tried before
// it is given up (recorded as failed with email_at set).
const ThreatEmailAttempts = 5

// ThreatNoticeEmailed records what happened to the notice's email. A
// failure leaves email_at empty, so the next run tries again, until
// ThreatEmailAttempts.
func (s *Store) ThreatNoticeEmailed(ctx context.Context, id int64, result string, recipients int) error {
	_, err := s.Pool.Exec(ctx, `UPDATE threat_notices SET email_attempts = email_attempts + 1, email_result = $2, email_recipients = $3,
		email_at = CASE WHEN $2 = 'failed' AND email_attempts + 1 < $4 THEN NULL ELSE now() END WHERE id = $1`,
		id, result, recipients, ThreatEmailAttempts)
	return err
}

// ThreatNoticeQueued records that the notice was given to n notification
// routes.
func (s *Store) ThreatNoticeQueued(ctx context.Context, id int64, n int) error {
	_, err := s.Pool.Exec(ctx, `UPDATE threat_notices SET channels_at = now(), channels_queued = $2 WHERE id = $1`, id, n)
	return err
}

// ListThreatNotices lists the workspace's notices, newest first, each with
// whether userID hid it since people were last told (a quiet change of the
// verdict keeps it hidden; a new "found" shows it again).
func (s *Store) ListThreatNotices(ctx context.Context, userID int64) ([]ThreatNotice, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+threatNoticeCols+`,
		EXISTS (SELECT 1 FROM threat_notice_dismissals d WHERE d.notice_id = n.id AND d.user_id = $1 AND d.dismissed_at >= n.banner_at)
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

// DismissThreatNotice hides a notice's banner for userID until people are
// told something new. ErrNotFound when the workspace has no such notice.
func (s *Store) DismissThreatNotice(ctx context.Context, id, userID int64) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO threat_notice_dismissals (notice_id, user_id, verdict, dismissed_at)
		SELECT n.id, $2, n.verdict, clock_timestamp() FROM threat_notices n WHERE n.id = $1
		ON CONFLICT (notice_id, user_id) DO UPDATE SET verdict = EXCLUDED.verdict, dismissed_at = clock_timestamp()`, id, userID)
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
