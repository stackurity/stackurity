package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// FixWork is where the work on one fix group stands, from its open issues:
// who they are assigned to, the earliest fix deadline, and how many are
// overdue, in progress ("applied, waiting for a check") or regressed. The
// Fixes table shows it next to each fix.
type FixWork struct {
	GroupID string `json:"group_id"`
	// Active counts open issues that are not snoozed or accepted.
	Active int64 `json:"active"`
	// Due is the earliest fix deadline of an active issue (null: none).
	Due *time.Time `json:"due"`
	// Overdue counts active issues past their fix deadline.
	Overdue    int64 `json:"overdue"`
	InProgress int64 `json:"in_progress"`
	Regressed  int64 `json:"regressed"`
	// Owners names who open issues are assigned to (a user's email or a
	// team's name), most issues first, at most five.
	Owners     []string `json:"owners"`
	Unassigned int64    `json:"unassigned"`
	// Mine counts open issues assigned to the caller.
	Mine int64 `json:"mine"`
	// AwaitingApproval counts open issues in a pending request to ignore
	// them, which a security or admin user has yet to decide.
	AwaitingApproval int64 `json:"awaiting_approval"`
}

// FixWorkMax is how many groups one FixGroupWork call takes.
const FixWorkMax = 500

// FixGroupWork returns the work state of each of the given fix groups that
// has open issues the caller can see; userID is the caller (0: none).
func (s *Store) FixGroupWork(ctx context.Context, ids []string, userID int64) ([]FixWork, error) {
	if len(ids) == 0 {
		return []FixWork{}, nil
	}
	rows, err := s.Pool.Query(ctx, `WITH o AS (
		SELECT f.fix_group, COALESCE(u.email, t.name) AS owner, count(*) AS n
		FROM findings f LEFT JOIN users u ON u.id = f.assignee_user_id LEFT JOIN teams t ON t.id = f.assignee_team_id
		WHERE f.fix_group = ANY($1) AND f.status = 'open' AND (f.assignee_user_id IS NOT NULL OR f.assignee_team_id IS NOT NULL)
		GROUP BY 1, 2),
	pending AS (SELECT DISTINCT unnest(finding_ids) AS id FROM ignore_requests WHERE status = 'pending')
	SELECT f.fix_group,
		count(*) FILTER (WHERE `+activeFinding+`),
		min(f.fix_due) FILTER (WHERE `+activeFinding+`),
		count(*) FILTER (WHERE `+activeFinding+` AND f.fix_due < now()),
		count(*) FILTER (WHERE f.state = 'in_progress'),
		count(*) FILTER (WHERE f.regressed_at IS NOT NULL AND f.state IN ('new', 'acknowledged')),
		COALESCE((SELECT array_agg(owner ORDER BY n DESC, owner) FROM (SELECT owner, n FROM o WHERE o.fix_group = f.fix_group ORDER BY n DESC, owner LIMIT 5) x), '{}'),
		count(*) FILTER (WHERE f.assignee_user_id IS NULL AND f.assignee_team_id IS NULL),
		count(*) FILTER (WHERE $2 > 0 AND f.assignee_user_id = $2),
		count(*) FILTER (WHERE f.id IN (SELECT id FROM pending))
	FROM findings f WHERE f.fix_group = ANY($1) AND f.status = 'open'
	GROUP BY f.fix_group ORDER BY f.fix_group`, ids, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (FixWork, error) {
		var w FixWork
		err := r.Scan(&w.GroupID, &w.Active, &w.Due, &w.Overdue, &w.InProgress, &w.Regressed, &w.Owners, &w.Unassigned, &w.Mine, &w.AwaitingApproval)
		return w, err
	})
}
