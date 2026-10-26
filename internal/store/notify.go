package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Channel struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	SecretRef string          `json:"secret_ref"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	LastOKAt  *time.Time      `json:"last_ok_at"`
	LastError string          `json:"last_error"`
}

const channelCols = `id, kind, name, config, secret_ref, enabled, created_at, last_ok_at, last_error`

func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Channel])
}

func (s *Store) GetChannel(ctx context.Context, id int64) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+channelCols+` FROM channels WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Channel])
	return c, notFound(err)
}

func (s *Store) CreateChannel(ctx context.Context, kind, name string, config json.RawMessage, secretRef string) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `INSERT INTO channels (kind, name, config, secret_ref) VALUES ($1,$2,$3,$4) RETURNING `+channelCols,
		kind, name, config, secretRef)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Channel])
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("a channel with that name exists: %w", ErrConflict)
	}
	return c, err
}

func (s *Store) UpdateChannel(ctx context.Context, id int64, name *string, config json.RawMessage, secretRef *string, enabled *bool) error {
	var cfg []byte
	if len(config) > 0 {
		cfg = config
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE channels SET name = COALESCE($2, name), config = COALESCE($3, config),
		secret_ref = COALESCE($4, secret_ref), enabled = COALESCE($5, enabled) WHERE id = $1`, id, name, cfg, secretRef, enabled)
	if isUniqueViolation(err) {
		return fmt.Errorf("a channel with that name exists: %w", ErrConflict)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM channels WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ChannelResult(ctx context.Context, id int64, sendErr error) error {
	if sendErr == nil {
		_, err := s.Pool.Exec(ctx, `UPDATE channels SET last_ok_at = now(), last_error = '' WHERE id = $1`, id)
		return err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE channels SET last_error = $2 WHERE id = $1`, id, truncateText(sendErr.Error(), 1000))
	return err
}

type Route struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	ChannelID    int64     `json:"channel_id"`
	Enabled      bool      `json:"enabled"`
	MinPriority  string    `json:"min_priority"`
	SOSOnly      bool      `json:"sos_only"`
	Kinds        []string  `json:"kinds"`
	Environments []string  `json:"environments"`
	TeamIDs      []int64   `json:"team_ids"`
	Escalation   bool      `json:"escalation"`
	SendResolved bool      `json:"send_resolved"`
	QuietStart   string    `json:"quiet_start"`
	QuietEnd     string    `json:"quiet_end"`
	Timezone     string    `json:"timezone"`
	MaxPerHour   int       `json:"max_per_hour"`
	CreatedAt    time.Time `json:"created_at"`
	// Mode is urgent_summary (urgent alerts right away and a daily
	// summary), daily or weekly (summary only).
	Mode string `json:"mode"`
	// SummaryTime ("HH:MM") and SummaryDay (weekday, for weekly summaries)
	// are in Timezone.
	SummaryTime string `json:"summary_time"`
	SummaryDay  string `json:"summary_day"`
	// LastSummaryAt is the end of the period the last summary covered. It
	// is kept by the dispatcher; SaveRoute ignores it.
	LastSummaryAt time.Time `json:"last_summary_at"`
	// ProjectIDs limits the route to the assets of these projects (empty:
	// every asset). ListRoutes fills ProjectAssets with those assets.
	ProjectIDs    []int64        `json:"project_ids"`
	ProjectAssets map[int64]bool `json:"-" db:"-"`
}

// Route modes.
const (
	ModeUrgentSummary = "urgent_summary"
	ModeDaily         = "daily"
	ModeWeekly        = "weekly"
)

// Weekdays are the values of Route.SummaryDay.
var Weekdays = []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

// A route limited to projects keeps its on/off switch in project_enabled
// and is stored with enabled false (migration 0032): a release before 0.8,
// which ignores project_ids, sees it switched off instead of sending every
// project's alerts to that project's channel.
const routeCols = `id, name, channel_id, CASE WHEN cardinality(project_ids) > 0 THEN project_enabled ELSE enabled END, min_priority, sos_only, kinds, environments, team_ids, escalation, send_resolved,
	quiet_start, quiet_end, timezone, max_per_hour, created_at, mode, summary_time, summary_day, last_summary_at, project_ids`

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+routeCols+` FROM routes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Route])
	if err != nil {
		return nil, err
	}
	return out, s.routeProjectAssets(ctx, out)
}

// routeProjectAssets fills ProjectAssets of the routes limited to projects:
// the assets of those projects that are not archived. A route whose
// projects are all archived matches no asset.
func (s *Store) routeProjectAssets(ctx context.Context, routes []Route) error {
	var ids []int64
	for _, r := range routes {
		ids = append(ids, r.ProjectIDs...)
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT pa.project_id, pa.asset_id FROM project_assets pa JOIN projects p ON p.id = pa.project_id
		WHERE pa.project_id = ANY($1) AND p.archived_at IS NULL`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	byProject := map[int64][]int64{}
	for rows.Next() {
		var p, a int64
		if err := rows.Scan(&p, &a); err != nil {
			return err
		}
		byProject[p] = append(byProject[p], a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range routes {
		if len(routes[i].ProjectIDs) == 0 {
			continue
		}
		routes[i].ProjectAssets = map[int64]bool{}
		for _, p := range routes[i].ProjectIDs {
			for _, a := range byProject[p] {
				routes[i].ProjectAssets[a] = true
			}
		}
	}
	return nil
}

func (s *Store) GetRoute(ctx context.Context, id int64) (*Route, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+routeCols+` FROM routes WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Route])
	return r, notFound(err)
}

// SaveRoute inserts (ID == 0) or replaces a route.
func (s *Store) SaveRoute(ctx context.Context, r Route) (*Route, error) {
	if r.Kinds == nil {
		r.Kinds = []string{}
	}
	if r.Environments == nil {
		r.Environments = []string{}
	}
	if r.TeamIDs == nil {
		r.TeamIDs = []int64{}
	}
	if r.ProjectIDs == nil {
		r.ProjectIDs = []int64{}
	}
	if r.MinPriority == "" {
		r.MinPriority = "P1"
	}
	if r.Mode == "" {
		r.Mode = ModeUrgentSummary
	}
	if r.SummaryTime == "" {
		r.SummaryTime = "09:00"
	}
	if r.SummaryDay == "" {
		r.SummaryDay = "monday"
	}
	var rows pgx.Rows
	var err error
	args := []any{r.Name, r.ChannelID, r.Enabled, r.MinPriority, r.SOSOnly, r.Kinds, r.Environments, r.TeamIDs, r.Escalation,
		r.SendResolved, r.QuietStart, r.QuietEnd, r.Timezone, r.MaxPerHour, r.Mode, r.SummaryTime, r.SummaryDay, r.ProjectIDs}
	if len(r.ProjectIDs) > 0 {
		var known int
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM projects WHERE id = ANY($1)`, r.ProjectIDs).Scan(&known); err != nil {
			return nil, err
		}
		if known != len(uniqueIDs(r.ProjectIDs)) {
			return nil, fmt.Errorf("no such project: %w", ErrInvalid)
		}
	}
	if r.ID == 0 {
		rows, err = s.Pool.Query(ctx, `INSERT INTO routes (name, channel_id, enabled, min_priority, sos_only, kinds, environments,
			team_ids, escalation, send_resolved, quiet_start, quiet_end, timezone, max_per_hour, mode, summary_time, summary_day, project_ids,
			project_enabled)
			VALUES ($1,$2,$3 AND cardinality($18::bigint[]) = 0,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			  $3 AND cardinality($18::bigint[]) > 0) RETURNING `+routeCols, args...)
	} else {
		rows, err = s.Pool.Query(ctx, `UPDATE routes SET name=$1, channel_id=$2, enabled=$3 AND cardinality($18::bigint[]) = 0,
			project_enabled = $3 AND cardinality($18::bigint[]) > 0, min_priority=$4, sos_only=$5, kinds=$6,
			environments=$7, team_ids=$8, escalation=$9, send_resolved=$10, quiet_start=$11, quiet_end=$12, timezone=$13, max_per_hour=$14,
			mode=$15, summary_time=$16, summary_day=$17, project_ids=$18
			WHERE id = $19 RETURNING `+routeCols, append(args, r.ID)...)
	}
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Route])
	switch {
	case isUniqueViolation(err):
		return nil, fmt.Errorf("a route with that name exists: %w", ErrConflict)
	case isForeignKey(err):
		return nil, fmt.Errorf("no such channel: %w", ErrConflict)
	}
	return out, notFound(err)
}

func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM routes WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type Delivery struct {
	ID          int64           `json:"id"`
	ChannelID   int64           `json:"channel_id"`
	ChannelName string          `json:"channel_name"`
	ChannelKind string          `json:"channel_kind"`
	RouteID     *int64          `json:"route_id"`
	IncidentID  *int64          `json:"incident_id"`
	Event       string          `json:"event"`
	DedupeKey   string          `json:"dedupe_key"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Attempts    int             `json:"attempts"`
	NextAttempt time.Time       `json:"next_attempt"`
	LastError   string          `json:"last_error"`
	CreatedAt   time.Time       `json:"created_at"`
	SentAt      *time.Time      `json:"sent_at"`
}

const deliveryCols = `d.id, d.channel_id, c.name, c.kind, d.route_id, d.incident_id, d.event, d.dedupe_key, d.payload, d.status,
	d.attempts, d.next_attempt, d.last_error, d.created_at, d.sent_at`

// EnqueueDelivery queues a message once per (channel, dedupe key).
func (s *Store) EnqueueDelivery(ctx context.Context, channelID int64, routeID, incidentID *int64, event, dedupe string, payload any) (bool, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO deliveries (channel_id, route_id, incident_id, event, dedupe_key, payload)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (channel_id, dedupe_key) DO NOTHING`, channelID, routeID, incidentID, event, dedupe, p)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+deliveryCols+` FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE d.status = 'pending' AND d.next_attempt <= now() AND c.enabled ORDER BY d.next_attempt, d.id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Delivery])
}

type DeliveryFilter struct {
	Status     string
	IncidentID int64
	ChannelID  int64
	Page
}

func (s *Store) ListDeliveries(ctx context.Context, f DeliveryFilter) ([]Delivery, int64, error) {
	w := &where{}
	if f.Status != "" {
		w.add("d.status = ?", f.Status)
	}
	if f.IncidentID > 0 {
		w.add("d.incident_id = ?", f.IncidentID)
	}
	if f.ChannelID > 0 {
		w.add("d.channel_id = ?", f.ChannelID)
	}
	from := ` FROM deliveries d JOIN channels c ON c.id = d.channel_id` + w.sql()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+deliveryCols+from+fmt.Sprintf(` ORDER BY d.created_at DESC, d.id DESC LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Delivery])
	return out, total, err
}

// ClaimDelivery takes a due delivery for one send attempt by moving its next
// attempt past the lease, and counts the attempt. False means another
// replica claimed it, sent it or put it off first. A replica that dies while
// sending leaves the delivery to be retried when the lease ends, so delivery
// is at least once; webhooks carry the delivery id for receivers to dedupe.
func (s *Store) ClaimDelivery(ctx context.Context, id int64, lease time.Duration) (attempts int, ok bool, err error) {
	err = s.Pool.QueryRow(ctx, `UPDATE deliveries SET attempts = attempts + 1, next_attempt = now() + $2::interval
		WHERE id = $1 AND status = 'pending' AND next_attempt <= now() RETURNING attempts`, id, lease).Scan(&attempts)
	if err == pgx.ErrNoRows {
		return 0, false, nil
	}
	return attempts, err == nil, err
}

// DeliverySent records a claimed delivery as sent.
func (s *Store) DeliverySent(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'sent', sent_at = now(), last_error = '' WHERE id = $1`, id)
	return err
}

// DeliveryFailed schedules a retry of a claimed delivery with backoff, or
// marks it failed once attempts (counted by ClaimDelivery) reach maxAttempts.
func (s *Store) DeliveryFailed(ctx context.Context, id int64, attempts, maxAttempts int, sendErr error) error {
	return s.DeliveryFailedWait(ctx, id, attempts, maxAttempts, sendErr, 0)
}

// DeliveryFailedWait is DeliveryFailed with a least wait before the retry,
// such as a receiver's Retry-After.
func (s *Store) DeliveryFailedWait(ctx context.Context, id int64, attempts, maxAttempts int, sendErr error, wait time.Duration) error {
	msg := truncateText(sendErr.Error(), 1000)
	if attempts >= maxAttempts {
		_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'failed', failed_at = now(), last_error = $2 WHERE id = $1`, id, msg)
		return err
	}
	backoff := max(time.Duration(1<<min(max(attempts-1, 0), 8))*30*time.Second, wait)
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET last_error = $2,
		next_attempt = now() + make_interval(secs => $3) WHERE id = $1`, id, msg, backoff.Seconds())
	return err
}

// DeferDelivery puts a due delivery off until a time (quiet hours). It does
// nothing to a delivery another replica has claimed.
func (s *Store) DeferDelivery(ctx context.Context, id int64, until time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = $2 WHERE id = $1 AND status = 'pending' AND next_attempt <= now()`, id, until)
	return err
}

// HoldDelivery keeps a due delivery for the next digest (rate limits). It
// does nothing to a delivery another replica has claimed.
func (s *Store) HoldDelivery(ctx context.Context, id int64, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'held', last_error = $2 WHERE id = $1 AND status = 'pending' AND next_attempt <= now()`, id, reason)
	return err
}

// RetryDelivery puts a failed delivery back in the queue.
func (s *Store) RetryDelivery(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'pending', next_attempt = now(), failed_at = NULL WHERE id = $1 AND status IN ('failed', 'held')`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RouteSentSince counts deliveries sent or queued for a route since t.
func (s *Store) RouteSentSince(ctx context.Context, routeID int64, since time.Time) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM deliveries WHERE route_id = $1 AND status = 'sent' AND sent_at >= $2`, routeID, since).Scan(&n)
	return n, err
}

// HeldByChannel returns held deliveries grouped by channel, for digests.
func (s *Store) HeldByChannel(ctx context.Context) (map[int64][]Delivery, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+deliveryCols+` FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE d.status = 'held' AND c.enabled ORDER BY d.created_at`)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Delivery])
	if err != nil {
		return nil, err
	}
	out := map[int64][]Delivery{}
	for _, d := range list {
		out[d.ChannelID] = append(out[d.ChannelID], d)
	}
	return out, nil
}

func (s *Store) MarkDigested(ctx context.Context, ids []int64, digestKey string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'sent', sent_at = now(), last_error = 'included in ' || $2
		WHERE id = ANY($1) AND status = 'held'`, ids, digestKey)
	return err
}

// IncidentsToAnnounce returns open incidents never announced or whose
// priority rose above what was announced.
func (s *Store) IncidentsToAnnounce(ctx context.Context) ([]Incident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id
		WHERE i.status = 'open' AND (i.notified_priority = '' OR i.priority < i.notified_priority)
		ORDER BY i.sos DESC, i.priority, i.id LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Incident])
}

// ResolvedToAnnounce returns announced incidents resolved since.
func (s *Store) ResolvedToAnnounce(ctx context.Context) ([]Incident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents i LEFT JOIN teams t ON t.id = i.owner_team_id
		WHERE i.status = 'resolved' AND i.notified_at IS NOT NULL AND NOT i.resolved_notified LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Incident])
}

func (s *Store) MarkResolvedNotified(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET resolved_notified = true WHERE id = $1`, id)
	return err
}

func uniqueIDs(ids []int64) map[int64]bool {
	out := map[int64]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}
