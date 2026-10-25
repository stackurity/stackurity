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
}

const routeCols = `id, name, channel_id, enabled, min_priority, sos_only, kinds, environments, team_ids, escalation, send_resolved,
	quiet_start, quiet_end, timezone, max_per_hour, created_at`

func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+routeCols+` FROM routes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Route])
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
	var rows pgx.Rows
	var err error
	args := []any{r.Name, r.ChannelID, r.Enabled, r.MinPriority, r.SOSOnly, r.Kinds, r.Environments, r.TeamIDs, r.Escalation,
		r.SendResolved, r.QuietStart, r.QuietEnd, r.Timezone, r.MaxPerHour}
	if r.ID == 0 {
		rows, err = s.Pool.Query(ctx, `INSERT INTO routes (name, channel_id, enabled, min_priority, sos_only, kinds, environments,
			team_ids, escalation, send_resolved, quiet_start, quiet_end, timezone, max_per_hour)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING `+routeCols, args...)
	} else {
		rows, err = s.Pool.Query(ctx, `UPDATE routes SET name=$1, channel_id=$2, enabled=$3, min_priority=$4, sos_only=$5, kinds=$6,
			environments=$7, team_ids=$8, escalation=$9, send_resolved=$10, quiet_start=$11, quiet_end=$12, timezone=$13, max_per_hour=$14
			WHERE id = $15 RETURNING `+routeCols, append(args, r.ID)...)
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

func (s *Store) DeliverySent(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = '' WHERE id = $1`, id)
	return err
}

// DeliveryFailed schedules a retry with backoff, or marks the delivery
// failed after maxAttempts.
func (s *Store) DeliveryFailed(ctx context.Context, id int64, attempts, maxAttempts int, sendErr error) error {
	msg := truncateText(sendErr.Error(), 1000)
	if attempts+1 >= maxAttempts {
		_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'failed', attempts = attempts + 1, last_error = $2 WHERE id = $1`, id, msg)
		return err
	}
	backoff := time.Duration(1<<min(attempts, 8)) * 30 * time.Second
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET attempts = attempts + 1, last_error = $2,
		next_attempt = now() + make_interval(secs => $3) WHERE id = $1`, id, msg, backoff.Seconds())
	return err
}

func (s *Store) DeferDelivery(ctx context.Context, id int64, until time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = $2 WHERE id = $1`, id, until)
	return err
}

func (s *Store) HoldDelivery(ctx context.Context, id int64, reason string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'held', last_error = $2 WHERE id = $1`, id, reason)
	return err
}

// RetryDelivery puts a failed delivery back in the queue.
func (s *Store) RetryDelivery(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'pending', next_attempt = now() WHERE id = $1 AND status IN ('failed', 'held')`, id)
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
