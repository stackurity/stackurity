package store

import (
	"context"
	"time"
)

// The Dashboard's SLA and trend, from what is already stored: open findings
// with their fix-by dates, and the matcher's 'resolved' and 'reopened'
// finding events (migration 0019). No history table: the open count on a
// past day is today's count walked back through what opened and closed since.

// Findings of a deleted asset are deleted with it, events and all, so a
// deleted asset drops out of the past trend too, as if it had never been
// there.

// TrendDays is how far back the open-issue trend goes.
const TrendDays = 30

// TrendWeeks is how many weeks of fixes the trend counts (within TrendDays).
const TrendWeeks = 4

// SLACounts splits active findings (new, to do or in progress) by their
// fix-by date.
type SLACounts struct {
	// OnTime are due later than the end of today, or have no fix-by date.
	OnTime int64 `json:"on_time"`
	// DueToday are due between now and the end of today.
	DueToday int64 `json:"due_today"`
	// Overdue are past their fix-by date.
	Overdue int64 `json:"overdue"`
}

// TrendPoint is the open findings at the end of a day.
type TrendPoint struct {
	Day  time.Time `json:"day"`
	Open int64     `json:"open"`
}

// WeekFixed is the findings fixed (remediated or removed) in a week.
type WeekFixed struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Fixed int64     `json:"fixed"`
}

// DashboardTrend is GET /dashboard/trend.
type DashboardTrend struct {
	CheckedAt time.Time `json:"checked_at"`
	// EndOfToday is the end of the caller's day, which "due today" uses.
	EndOfToday time.Time    `json:"end_of_today"`
	SLA        SLACounts    `json:"sla"`
	Open       []TrendPoint `json:"open"`
	Fixed      []WeekFixed  `json:"fixed"`
}

// SummarizeTrend counts the SLA and the trend for the assets the caller may
// see. endOfToday is the end of the caller's day.
func (s *Store) SummarizeTrend(ctx context.Context, endOfToday time.Time) (*DashboardTrend, error) {
	t := &DashboardTrend{EndOfToday: endOfToday, Open: []TrendPoint{}, Fixed: []WeekFixed{}}
	var openNow int64
	if err := s.Pool.QueryRow(ctx, `SELECT now(),
		  count(*) FILTER (WHERE `+activeFinding+` AND (f.fix_due IS NULL OR f.fix_due >= $1)),
		  count(*) FILTER (WHERE `+activeFinding+` AND f.fix_due >= now() AND f.fix_due < $1),
		  count(*) FILTER (WHERE `+activeFinding+` AND f.fix_due < now()),
		  count(*)
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open'`, endOfToday).
		Scan(&t.CheckedAt, &t.SLA.OnTime, &t.SLA.DueToday, &t.SLA.Overdue, &openNow); err != nil {
		return nil, err
	}
	// What opened and closed each day since TrendDays ago, newest first.
	from := t.CheckedAt.Add(-TrendDays * 24 * time.Hour)
	// Net change per day bucket: bucket k holds events between k and k+1
	// days ago.
	rows, err := s.Pool.Query(ctx, `SELECT floor(extract(epoch FROM $1::timestamptz - ev.at) / 86400)::int, sum(ev.d)::bigint FROM (
		  SELECT e.at, CASE e.action WHEN 'resolved' THEN -1 ELSE 1 END AS d
		  FROM finding_events e JOIN findings f ON f.id = e.finding_id JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE e.action IN ('resolved', 'reopened') AND e.at > $2
		  UNION ALL
		  SELECT f.first_seen, 1 FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE f.first_seen > $2) ev
		GROUP BY 1`, t.CheckedAt, from)
	if err != nil {
		return nil, err
	}
	net := make([]int64, TrendDays+1)
	for rows.Next() {
		var k int
		var d int64
		if err := rows.Scan(&k, &d); err != nil {
			rows.Close()
			return nil, err
		}
		if k >= 0 && k < len(net) {
			net[k] += d
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Open k days ago = open now, less what opened since, plus what closed.
	since := int64(0)
	points := make([]TrendPoint, TrendDays+1)
	for k := 0; k <= TrendDays; k++ {
		if k > 0 {
			since += net[k-1]
		}
		points[TrendDays-k] = TrendPoint{Day: t.CheckedAt.Add(-time.Duration(k) * 24 * time.Hour), Open: max(openNow-since, 0)}
	}
	t.Open = points

	wrows, err := s.Pool.Query(ctx, `SELECT w.start, w.start + interval '7 days',
		  (SELECT count(DISTINCT e.finding_id) FROM finding_events e JOIN findings f ON f.id = e.finding_id
		    JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE e.action = 'resolved' AND e.at > w.start AND e.at <= w.start + interval '7 days'
		      AND COALESCE(e.detail->>'resolution_kind', f.resolution_kind) IN ('remediated', 'removed'))
		FROM (SELECT $1::timestamptz - make_interval(days => 7 * (k + 1)) AS start FROM generate_series(0, $2::int - 1) k) w
		ORDER BY w.start`, t.CheckedAt, TrendWeeks)
	if err != nil {
		return nil, err
	}
	for wrows.Next() {
		var w WeekFixed
		if err := wrows.Scan(&w.Start, &w.End, &w.Fixed); err != nil {
			wrows.Close()
			return nil, err
		}
		t.Fixed = append(t.Fixed, w)
	}
	wrows.Close()
	return t, wrows.Err()
}
