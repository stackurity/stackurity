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
	// LastOKAt is the last time anything through the channel worked: a
	// test from the integration's page (or a Jira, tracker or PagerDuty
	// connection check) as well as a real message. LastDeliveryAt says
	// whether a real message was ever delivered.
	LastOKAt  *time.Time `json:"last_ok_at"`
	LastError string     `json:"last_error"`
	// OwnerProjectID and OwnerAssetID: the project or asset the channel
	// belongs to; both nil for the organisation's (migration 0096).
	OwnerProjectID *int64 `json:"owner_project_id"`
	OwnerAssetID   *int64 `json:"owner_asset_id"`
	// LastDeliveryAt is when the channel last delivered a real
	// notification (a delivery in the delivery log marked sent); tests
	// are never in the log, so they never set it. Nil: none yet.
	LastDeliveryAt *time.Time `json:"last_delivery_at"`
	// SecretSource says where secret_ref points: "stored" (a secret in
	// this organisation's stored credentials), "missing" (a secret:NAME
	// that is not stored, so sending will fail), "server" (env: or file:,
	// the server's own secrets, which the Secrets page never
	// shows) or "" (no secret).
	SecretSource string `json:"secret_source"`
}

// channelCols ends with two computed columns, LastDeliveryAt and
// SecretSource. Every query selecting them reads FROM channels (no alias),
// or is an INSERT INTO channels ... RETURNING.
const channelCols = `id, kind, name, config, secret_ref, enabled, created_at, last_ok_at, last_error, owner_project_id, owner_asset_id,
	(SELECT max(d.sent_at) FROM deliveries d WHERE d.channel_id = channels.id AND d.status = 'sent'),
	CASE
	  WHEN channels.secret_ref LIKE 'env:%' OR channels.secret_ref LIKE 'file:%' THEN 'server'
	  WHEN channels.secret_ref LIKE 'secret:%' THEN
	    CASE WHEN EXISTS (SELECT 1 FROM workspace_secrets ws WHERE ws.workspace_id = channels.workspace_id
	      AND ws.name = substr(channels.secret_ref, 8)) THEN 'stored' ELSE 'missing' END
	  ELSE '' END`

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
	return s.CreateOwnedChannel(ctx, Owner{}, kind, name, config, secretRef)
}

// Owner is who a channel or route belongs to: a project, an asset, or
// (both nil) the organisation.
type Owner struct {
	ProjectID *int64 `json:"project_id,omitempty"`
	AssetID   *int64 `json:"asset_id,omitempty"`
}

// Org reports whether the owner is the organisation.
func (o Owner) Org() bool { return o.ProjectID == nil && o.AssetID == nil }

// Same reports whether two owners are the same.
func (o Owner) Same(p Owner) bool {
	return eqID(o.ProjectID, p.ProjectID) && eqID(o.AssetID, p.AssetID)
}

// Owner is the channel's owner.
func (c Channel) Owner() Owner { return Owner{ProjectID: c.OwnerProjectID, AssetID: c.OwnerAssetID} }

// CreateOwnedChannel creates a channel of a project, an asset or the
// organisation.
func (s *Store) CreateOwnedChannel(ctx context.Context, owner Owner, kind, name string, config json.RawMessage, secretRef string) (*Channel, error) {
	rows, err := s.Pool.Query(ctx, `INSERT INTO channels (kind, name, config, secret_ref, owner_project_id, owner_asset_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+channelCols,
		kind, name, config, secretRef, owner.ProjectID, owner.AssetID)
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
	_, err := s.DeleteChannelFromRoutes(ctx, id)
	return err
}

// DeleteChannelFromRoutes deletes a channel and, in the same transaction,
// takes it out of every route that sends some events to it
// (event_channels): those events go to the route's own channel again. It
// returns the names of the routes changed.
func (s *Store) DeleteChannelFromRoutes(ctx context.Context, id int64) ([]string, error) {
	var changed []string
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE routes SET event_channels = (SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}')
				FROM jsonb_each(event_channels) e WHERE e.value <> to_jsonb($1::bigint))
			WHERE event_channels @? ('$.* ? (@ == ' || $1::bigint || ')')::jsonpath AND channel_id <> $1
			RETURNING name`, id)
		if err != nil {
			return err
		}
		if changed, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM channels WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
	return changed, err
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
	// summary), urgent_only (urgent alerts, no summary), daily or weekly
	// (summary only).
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
	// AssetProject is, for each of those assets, the first of the route's
	// projects it is in: links in the route's messages open it.
	AssetProject map[int64]int64 `json:"-" db:"-"`
	// Events are what the route sends (Event* constants). Mode is derived
	// from them when the route is saved (ModeCustom when no older mode
	// matches); a request that names only a mode gets its events.
	Events []string `json:"events"`
	// EventChannels sends some events to another channel of the route's
	// kind instead of ChannelID (Slack only).
	EventChannels map[string]int64 `json:"event_channels"`
	// NewMinPriority is the lowest priority the new_issues event sends.
	NewMinPriority string `json:"new_min_priority"`
	// LastWeeklySummaryAt is the end of the period the last weekly summary
	// covered (LastSummaryAt is the daily summary's). Kept by the dispatcher.
	LastWeeklySummaryAt time.Time `json:"last_weekly_summary_at"`
	// SummaryUpdates adds an "Updates available" section (newer releases
	// that fix no known vulnerability) to the route's weekly summary, never
	// the daily one. Off by default.
	SummaryUpdates bool `json:"summary_updates"`
	// OwnerProjectID and OwnerAssetID: the project or asset the route
	// belongs to, both nil for the organisation's (migration 0096). A
	// project's route is limited to it (ProjectIDs is the project); an
	// asset's to that asset. Set when the route is created, never changed.
	OwnerProjectID *int64 `json:"owner_project_id"`
	OwnerAssetID   *int64 `json:"owner_asset_id"`
	// InheritsRouteID: the inherited rule this one replaces for its owner
	// ("Edit for this project"); the inherited rule is turned off there.
	InheritsRouteID *int64 `json:"inherits_route_id"`
	// Excluded is the assets the route is turned off for (route_exclusions):
	// filled by ListRoutes.
	Excluded map[int64]bool `json:"-" db:"-"`
}

// Owner is the route's owner.
func (r Route) Owner() Owner { return Owner{ProjectID: r.OwnerProjectID, AssetID: r.OwnerAssetID} }

// Narrowed reports whether the route hears about some assets only: it is
// limited to projects, belongs to an asset, or is turned off for some.
func (r Route) Narrowed() bool {
	return r.Limited() || len(r.Excluded) > 0
}

// Limited reports whether the route hears about the assets of
// ProjectAssets only (limited to projects, or an asset's route).
func (r Route) Limited() bool { return len(r.ProjectIDs) > 0 || r.OwnerAssetID != nil }

// Covers reports whether the route hears about the asset.
func (r Route) Covers(asset int64) bool {
	if r.Limited() && !r.ProjectAssets[asset] {
		return false
	}
	return !r.Excluded[asset]
}

// Route events.
const (
	EventUrgent        = "urgent"
	EventNewIssues     = "new_issues"
	EventRegressed     = "regressed"
	EventOverdue       = "overdue"
	EventConnected     = "connected"
	EventProblems      = "problems"
	EventDailySummary  = "daily_summary"
	EventWeeklySummary = "weekly_summary"
)

// RouteEvents lists every route event.
var RouteEvents = []string{EventUrgent, EventNewIssues, EventRegressed, EventOverdue, EventConnected, EventProblems, EventDailySummary, EventWeeklySummary}

// rightAway is what the older modes that sent messages as they happened
// sent: everything but summaries.
var rightAway = []string{EventUrgent, EventRegressed, EventOverdue, EventConnected, EventProblems}

// EventsForMode is the events an older mode sent; nil for an unknown mode.
func EventsForMode(mode string) []string {
	switch mode {
	case ModeUrgentSummary:
		return append(append([]string{}, rightAway...), EventDailySummary)
	case ModeUrgentWeekly:
		return append(append([]string{}, rightAway...), EventWeeklySummary)
	case ModeUrgentOnly:
		return append([]string{}, rightAway...)
	case ModeDaily:
		return []string{EventDailySummary}
	case ModeWeekly:
		return []string{EventWeeklySummary}
	}
	return nil
}

// ModeForEvents names the older mode that sends exactly these events, or
// ModeCustom.
func ModeForEvents(events []string) string {
	have := map[string]bool{}
	for _, e := range events {
		have[e] = true
	}
	for _, m := range []string{ModeUrgentSummary, ModeUrgentWeekly, ModeUrgentOnly, ModeDaily, ModeWeekly} {
		want := EventsForMode(m)
		if len(want) != len(have) {
			continue
		}
		same := true
		for _, e := range want {
			same = same && have[e]
		}
		if same {
			return m
		}
	}
	return ModeCustom
}

// ResolveEvents is what a saved route sends, from the mode and events a
// caller gave. Events win, except over an older mode that disagrees with
// them: an older client that read a route and changed only its mode. With
// neither, the default mode's.
func ResolveEvents(mode string, events []string) ([]string, error) {
	if mode != "" && mode != ModeCustom && (events == nil || ModeForEvents(events) != mode) {
		if e := EventsForMode(mode); e != nil {
			return e, nil
		}
		return nil, fmt.Errorf("unknown mode %q: %w", mode, ErrInvalid)
	}
	if events == nil {
		return EventsForMode(ModeUrgentSummary), nil
	}
	return events, nil
}

// HasEvent reports whether the route sends event. A route built without
// events (not read from the database) sends its mode's.
func (r Route) HasEvent(event string) bool {
	events := r.Events
	if events == nil {
		mode := r.Mode
		if mode == "" {
			mode = ModeUrgentSummary
		}
		events = EventsForMode(mode)
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

// ChannelFor is the channel an event of the route goes to.
func (r Route) ChannelFor(event string) int64 {
	if id := r.EventChannels[event]; id > 0 {
		return id
	}
	return r.ChannelID
}

// Route modes.
const (
	ModeUrgentSummary = "urgent_summary"
	ModeUrgentOnly    = "urgent_only"
	ModeDaily         = "daily"
	ModeWeekly        = "weekly"
	// ModeUrgentWeekly: urgent messages right away and a weekly summary.
	ModeUrgentWeekly = "urgent_weekly"
	// ModeCustom: events no older mode matches.
	ModeCustom = "custom"
)

// Weekdays are the values of Route.SummaryDay.
var Weekdays = []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

// A route limited to projects keeps its on/off switch in project_enabled
// and is stored with enabled false (migration 0032): a release before 0.8,
// which ignores project_ids, sees it switched off instead of sending every
// project's alerts to that project's channel.
//
// An asset's route is stored the same way (migration 0096).
const routeCols = `id, name, channel_id, CASE WHEN cardinality(project_ids) > 0 OR owner_asset_id IS NOT NULL THEN project_enabled ELSE enabled END, min_priority, sos_only, kinds, environments, team_ids, escalation, send_resolved,
	quiet_start, quiet_end, timezone, max_per_hour, created_at, mode, summary_time, summary_day, last_summary_at, project_ids,
	events, event_channels, new_min_priority, last_weekly_summary_at, summary_updates, owner_project_id, owner_asset_id, inherits_route_id`

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
// projects are all archived matches no asset. An asset's route covers that
// asset. It also fills Excluded from route_exclusions: an inherited rule
// turned off for an asset leaves it out; turned off for a project, it
// leaves out that project's assets, except those it still hears about
// through another of its projects (or, for a rule of the whole
// organisation, through another project the asset is in).
func (s *Store) routeProjectAssets(ctx context.Context, routes []Route) error {
	type exclusion struct{ route, project, asset int64 }
	rows, err := s.Pool.Query(ctx, `SELECT route_id, COALESCE(project_id, 0), COALESCE(asset_id, 0) FROM route_exclusions`)
	if err != nil {
		return err
	}
	excl, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (exclusion, error) {
		var e exclusion
		return e, row.Scan(&e.route, &e.project, &e.asset)
	})
	if err != nil {
		return err
	}
	offProjects := map[int64]map[int64]bool{} // route -> projects it is off for
	offAssets := map[int64]map[int64]bool{}   // route -> assets it is off for
	var ids []int64
	for _, e := range excl {
		if e.project > 0 {
			if offProjects[e.route] == nil {
				offProjects[e.route] = map[int64]bool{}
			}
			offProjects[e.route][e.project] = true
			ids = append(ids, e.project)
		} else {
			if offAssets[e.route] == nil {
				offAssets[e.route] = map[int64]bool{}
			}
			offAssets[e.route][e.asset] = true
		}
	}
	for _, r := range routes {
		ids = append(ids, r.ProjectIDs...)
	}
	byProject := map[int64][]int64{}
	inProjects := map[int64][]int64{} // asset -> its active projects, for the assets of the projects above
	if len(ids) > 0 {
		rows, err := s.Pool.Query(ctx, `SELECT pa.project_id, pa.asset_id FROM project_assets pa JOIN projects p ON p.id = pa.project_id
			WHERE p.archived_at IS NULL AND pa.asset_id IN (SELECT asset_id FROM project_assets WHERE project_id = ANY($1))`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p, a int64
			if err := rows.Scan(&p, &a); err != nil {
				return err
			}
			byProject[p] = append(byProject[p], a)
			inProjects[a] = append(inProjects[a], p)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	for i := range routes {
		r := &routes[i]
		off := offProjects[r.ID]
		switch {
		case len(r.ProjectIDs) > 0:
			r.ProjectAssets = map[int64]bool{}
			r.AssetProject = map[int64]int64{}
			for _, p := range r.ProjectIDs {
				if off[p] {
					continue
				}
				for _, a := range byProject[p] {
					r.ProjectAssets[a] = true
					if r.AssetProject[a] == 0 {
						r.AssetProject[a] = p
					}
				}
			}
		case r.OwnerAssetID != nil:
			r.ProjectAssets = map[int64]bool{*r.OwnerAssetID: true}
		case len(off) > 0:
			// The whole organisation's rule: an asset is left out when every
			// project it is in turned the rule off.
			for p := range off {
				for _, a := range byProject[p] {
					all := true
					for _, q := range inProjects[a] {
						all = all && off[q]
					}
					if all {
						if r.Excluded == nil {
							r.Excluded = map[int64]bool{}
						}
						r.Excluded[a] = true
					}
				}
			}
		}
		for a := range offAssets[r.ID] {
			if r.Excluded == nil {
				r.Excluded = map[int64]bool{}
			}
			r.Excluded[a] = true
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

// ListOwnedRoutes lists the routes of one owner (the organisation's when
// owner is empty).
func (s *Store) ListOwnedRoutes(ctx context.Context, owner Owner) ([]Route, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+routeCols+` FROM routes
		WHERE owner_project_id IS NOT DISTINCT FROM $1 AND owner_asset_id IS NOT DISTINCT FROM $2 ORDER BY name`, owner.ProjectID, owner.AssetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Route])
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
	events, err := ResolveEvents(r.Mode, r.Events)
	if err != nil {
		return nil, err
	}
	r.Events, r.Mode = events, ModeForEvents(events)
	if r.EventChannels == nil {
		r.EventChannels = map[string]int64{}
	}
	if r.NewMinPriority == "" {
		r.NewMinPriority = "P4"
	}
	if r.SummaryTime == "" {
		r.SummaryTime = "09:00"
	}
	if r.SummaryDay == "" {
		r.SummaryDay = "monday"
	}
	var rows pgx.Rows
	args := []any{r.Name, r.ChannelID, r.Enabled, r.MinPriority, r.SOSOnly, r.Kinds, r.Environments, r.TeamIDs, r.Escalation,
		r.SendResolved, r.QuietStart, r.QuietEnd, r.Timezone, r.MaxPerHour, r.Mode, r.SummaryTime, r.SummaryDay, r.ProjectIDs,
		r.Events, r.EventChannels, r.NewMinPriority, r.SummaryUpdates}
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
		// A project's route is limited to it; an asset's names no project.
		if r.OwnerProjectID != nil {
			r.ProjectIDs = []int64{*r.OwnerProjectID}
			args[17] = r.ProjectIDs
		} else if r.OwnerAssetID != nil {
			r.ProjectIDs = []int64{}
			args[17] = r.ProjectIDs
		}
		rows, err = s.Pool.Query(ctx, `INSERT INTO routes (name, channel_id, enabled, min_priority, sos_only, kinds, environments,
			team_ids, escalation, send_resolved, quiet_start, quiet_end, timezone, max_per_hour, mode, summary_time, summary_day, project_ids,
			project_enabled, events, event_channels, new_min_priority, summary_updates, owner_project_id, owner_asset_id, inherits_route_id)
			VALUES ($1,$2,$3 AND cardinality($18::bigint[]) = 0 AND $24::bigint IS NULL,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			  $3 AND (cardinality($18::bigint[]) > 0 OR $24::bigint IS NOT NULL), $19, $20, $21, $22, $23, $24, $25) RETURNING `+routeCols,
			append(args, r.OwnerProjectID, r.OwnerAssetID, r.InheritsRouteID)...)
	} else {
		rows, err = s.Pool.Query(ctx, `UPDATE routes SET name=$1, channel_id=$2, enabled=$3 AND cardinality($18::bigint[]) = 0 AND owner_asset_id IS NULL,
			project_enabled = $3 AND (cardinality($18::bigint[]) > 0 OR owner_asset_id IS NOT NULL), min_priority=$4, sos_only=$5, kinds=$6,
			environments=$7, team_ids=$8, escalation=$9, send_resolved=$10, quiet_start=$11, quiet_end=$12, timezone=$13, max_per_hour=$14,
			mode=$15, summary_time=$16, summary_day=$17, project_ids=$18, events=$19, event_channels=$20, new_min_priority=$21,
			summary_updates=$22
			WHERE id = $23 RETURNING `+routeCols, append(args, r.ID)...)
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

// DeleteRoute deletes a route. A project's or asset's copy of an inherited
// rule takes its turn-off with it: the inherited rule applies there again.
func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	return pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM route_exclusions e USING routes r
			WHERE r.id = $1 AND e.route_id = r.inherits_route_id
			  AND e.project_id IS NOT DISTINCT FROM r.owner_project_id AND e.asset_id IS NOT DISTINCT FROM r.owner_asset_id`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM routes WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// RouteExclusion is an inherited rule turned off for a project or asset.
type RouteExclusion struct {
	RouteID   int64     `json:"route_id"`
	ProjectID *int64    `json:"project_id"`
	AssetID   *int64    `json:"asset_id"`
	CreatedAt time.Time `json:"created_at"`
}

// RouteExclusions lists the rules turned off for an owner (a project or
// an asset).
func (s *Store) RouteExclusions(ctx context.Context, owner Owner) ([]RouteExclusion, error) {
	rows, err := s.Pool.Query(ctx, `SELECT route_id, project_id, asset_id, created_at FROM route_exclusions
		WHERE project_id IS NOT DISTINCT FROM $1 AND asset_id IS NOT DISTINCT FROM $2 ORDER BY route_id`, owner.ProjectID, owner.AssetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RouteExclusion])
}

// SetRouteExcluded turns a route off (off true) or on again for a project
// or an asset.
func (s *Store) SetRouteExcluded(ctx context.Context, routeID int64, owner Owner, off bool, by int64) error {
	if owner.Org() {
		return fmt.Errorf("a rule is turned off for a project or an asset: %w", ErrInvalid)
	}
	if !off {
		_, err := s.Pool.Exec(ctx, `DELETE FROM route_exclusions WHERE route_id = $1
			AND project_id IS NOT DISTINCT FROM $2 AND asset_id IS NOT DISTINCT FROM $3`, routeID, owner.ProjectID, owner.AssetID)
		return err
	}
	var byp *int64
	if by > 0 {
		byp = &by
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO route_exclusions (route_id, project_id, asset_id, created_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, routeID, owner.ProjectID, owner.AssetID, byp)
	if isForeignKey(err) {
		return fmt.Errorf("no such rule, project or asset: %w", ErrNotFound)
	}
	return err
}

// CustomiseRoute replaces an inherited rule for an owner with a copy of
// it: the copy is saved as the owner's and the inherited rule is turned
// off there (the copy is deleted again if that fails). It returns the copy.
func (s *Store) CustomiseRoute(ctx context.Context, copy Route, by int64) (*Route, error) {
	if copy.InheritsRouteID == nil || copy.Owner().Org() {
		return nil, fmt.Errorf("a copy names the rule it replaces and its project or asset: %w", ErrInvalid)
	}
	out, err := s.SaveRoute(ctx, copy)
	if err != nil {
		return nil, err
	}
	if err := s.SetRouteExcluded(ctx, *copy.InheritsRouteID, copy.Owner(), true, by); err != nil {
		_, _ = s.Pool.Exec(context.WithoutCancel(ctx), `DELETE FROM routes WHERE id = $1`, out.ID)
		return nil, err
	}
	return out, nil
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
	// HeldBy is why it was held: "", hourly_limit or email_quota.
	HeldBy string `json:"held_by"`
}

const deliveryCols = `d.id, d.channel_id, c.name, c.kind, d.route_id, d.incident_id, d.event, d.dedupe_key, d.payload, d.status,
	d.attempts, d.next_attempt, d.last_error, d.created_at, d.sent_at, d.held_by`

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
	return s.HoldDeliveryBy(ctx, id, HeldHourlyLimit, reason)
}

// RetryDelivery puts a failed delivery back in the queue.
func (s *Store) RetryDelivery(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE deliveries SET status = 'pending', next_attempt = now(), failed_at = NULL, held_by = '' WHERE id = $1 AND status IN ('failed', 'held')`, id)
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
