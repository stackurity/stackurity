package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// The plan's history window and inactive pause (docs/asset-limits.md,
// "Plan limits"). Both are unset on a self-hosted install.

// inactivePaused is true for a workspace w paused for inactivity that no
// member has signed in to since: the next sign-in resumes it at once,
// before the sweep notices.
const inactivePaused = `(w.inactive_paused_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM workspace_members m JOIN users u ON u.id = m.user_id
	WHERE m.workspace_id = w.id AND u.last_login_at > w.inactive_paused_at))`

// PausedReason is shown while an organisation is paused for inactivity.
const PausedReason = "Paused because nobody in this organisation has signed in for a while: nothing new is collected and no " +
	"notifications are sent, and everything is kept. Signing in resumes it at once."

type historyKey struct{}

// WithHistoryWindow marks ctx as a request for people (the API), whose
// lists of resolved issues, past inventory and resolved incidents keep to
// the plan's history window. Background work never sets it.
func WithHistoryWindow(ctx context.Context) context.Context {
	return context.WithValue(ctx, historyKey{}, true)
}

// historySince is the start of the plan's history window for a request
// marked WithHistoryWindow; nil shows everything.
func (s *Store) historySince(ctx context.Context) (*time.Time, error) {
	if on, _ := ctx.Value(historyKey{}).(bool); !on {
		return nil, nil
	}
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, nil
	}
	l, err := planLimits(tenant.System(ctx), s.Pool, ws)
	if err != nil || l.HistoryDays == 0 {
		if errors.Is(err, ErrNotFound) {
			err = nil
		}
		return nil, err
	}
	since := time.Now().Add(-time.Duration(l.HistoryDays) * 24 * time.Hour)
	return &since, nil
}

// InactiveNotice is a warning to an organisation's administrators that it
// will be paused for inactivity on PauseOn.
type InactiveNotice struct {
	WorkspaceID int64
	Name        string
	Admins      []string
	PauseOn     time.Time
	// Last: the second (last) warning.
	Last bool
}

// SweepInactive walks the organisations whose plan pauses them after
// inactive_pause_days without a sign-in: it forgets the warnings and pause
// of any that someone signed in to since; warns 15 days before
// (inactive_warned_first_at) and 5 days before (inactive_warned_last_at),
// each at least that long before the pause, also for one already past the
// days when the limit was set; and pauses those warned twice. It returns
// the warnings to email. Run hourly; it changes nothing for organisations
// without the limit.
func (s *Store) SweepInactive(ctx context.Context, now time.Time) ([]InactiveNotice, error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT w.id, w.name, (w.plan_limits->>'inactive_pause_days')::bigint,
		GREATEST(w.created_at, (SELECT max(u.last_login_at) FROM workspace_members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = w.id)),
		w.inactive_warned_first_at, w.inactive_warned_last_at, w.inactive_paused_at
		FROM workspaces w WHERE w.disabled_at IS NULL AND (COALESCE((w.plan_limits->>'inactive_pause_days')::bigint, 0) > 0
		   OR w.inactive_warned_first_at IS NOT NULL OR w.inactive_paused_at IS NOT NULL) ORDER BY w.id`)
	if err != nil {
		return nil, err
	}
	type org struct {
		id                  int64
		name                string
		days                *int64
		active              time.Time
		first, last, paused *time.Time
	}
	orgs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (org, error) {
		var o org
		err := r.Scan(&o.id, &o.name, &o.days, &o.active, &o.first, &o.last, &o.paused)
		return o, err
	})
	if err != nil {
		return nil, err
	}
	day := 24 * time.Hour
	var out []InactiveNotice
	for _, o := range orgs {
		mark := o.first
		if o.paused != nil {
			mark = o.paused
		} else if o.last != nil {
			mark = o.last
		}
		// Someone signed in since the warnings (or the limit is gone):
		// start again.
		if mark != nil && (o.active.After(*mark) || o.days == nil || *o.days == 0) {
			if _, err := s.Pool.Exec(sys, `UPDATE workspaces SET inactive_warned_first_at = NULL, inactive_warned_last_at = NULL,
				inactive_paused_at = NULL WHERE id = $1`, o.id); err != nil {
				return nil, err
			}
			o.first, o.last, o.paused = nil, nil, nil
		}
		if o.days == nil || *o.days == 0 || o.paused != nil {
			continue
		}
		limit := time.Duration(*o.days) * day
		idle := now.Sub(o.active)
		switch {
		case o.first == nil && idle >= limit-15*day:
			n, err := s.inactiveNotice(sys, o.id, o.name, laterOf(o.active.Add(limit), now.Add(15*day)), false)
			if err != nil {
				return nil, err
			}
			if _, err := s.Pool.Exec(sys, `UPDATE workspaces SET inactive_warned_first_at = $2 WHERE id = $1`, o.id, now); err != nil {
				return nil, err
			}
			out = append(out, n)
		case o.first != nil && o.last == nil && idle >= limit-5*day && now.Sub(*o.first) >= 10*day:
			n, err := s.inactiveNotice(sys, o.id, o.name, laterOf(o.active.Add(limit), now.Add(5*day)), true)
			if err != nil {
				return nil, err
			}
			if _, err := s.Pool.Exec(sys, `UPDATE workspaces SET inactive_warned_last_at = $2 WHERE id = $1`, o.id, now); err != nil {
				return nil, err
			}
			out = append(out, n)
		case o.last != nil && idle >= limit && now.Sub(*o.last) >= 5*day:
			if _, err := s.Pool.Exec(sys, `UPDATE workspaces SET inactive_paused_at = $2 WHERE id = $1`, o.id, now); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// laterOf is the later of a and b.
func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (s *Store) inactiveNotice(ctx context.Context, ws int64, name string, pauseOn time.Time, last bool) (InactiveNotice, error) {
	rows, err := s.Pool.Query(ctx, `SELECT u.email FROM workspace_members m JOIN users u ON u.id = m.user_id
		WHERE m.workspace_id = $1 AND m.role = 'admin' AND NOT u.disabled ORDER BY u.email`, ws)
	if err != nil {
		return InactiveNotice{}, err
	}
	admins, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return InactiveNotice{WorkspaceID: ws, Name: name, Admins: admins, PauseOn: pauseOn, Last: last}, err
}
