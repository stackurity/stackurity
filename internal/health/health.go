// Package health checks that the platform itself is working: intelligence
// feeds are fresh, periodic tasks succeed and jobs do not fail. Instance
// admins see the report in the dashboard; metrics and platform incidents
// are built from it too.
package health

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
)

// Problem is one thing an operator should look at.
type Problem struct {
	Severity Severity `json:"severity"`
	Kind     string   `json:"kind"` // feed, task, jobs, intelligence
	Key      string   `json:"key"`  // feed name, task name, job kind
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
}

type Report struct {
	// Status is ok, warning or critical: the worst problem's severity.
	Status    string               `json:"status"`
	CheckedAt time.Time            `json:"checked_at"`
	Problems  []Problem            `json:"problems"`
	Tasks     []store.PeriodicTask `json:"tasks"`
	Jobs      []store.JobCount     `json:"jobs"`
	// OldestQueuedSeconds is how long the oldest due job has waited.
	OldestQueuedSeconds float64 `json:"oldest_queued_seconds"`
	// RecentFailures are the latest jobs that gave up in the last 24 hours,
	// in any workspace, with their errors.
	RecentFailures []FailedJob `json:"recent_failures"`
}

// FailedJob is a job that ran out of retries. Its payload is left out.
type FailedJob struct {
	ID          int64     `json:"id"`
	Kind        string    `json:"kind"`
	WorkspaceID *int64    `json:"workspace_id"`
	Attempts    int       `json:"attempts"`
	LastError   string    `json:"last_error"`
	FailedAt    time.Time `json:"failed_at"`
}

const (
	// taskSeen: a task whose row no running server refreshed within this
	// long is no longer registered (renamed, removed, or feeds turned off).
	// Schedulers refresh every five minutes.
	taskSeen = 20 * time.Minute
	// taskGraceMin is the least time a task may go without success, so that
	// one-minute tasks do not flap during a slow cycle or a rolling restart.
	taskGraceMin = 10 * time.Minute
	// queueBacklog is how long a due job may wait before it is a problem.
	queueBacklog = 30 * time.Minute
	// firstSync is how long a new installation has to complete its first
	// intelligence sync before that is critical.
	firstSync = time.Hour
)

type Checker struct {
	Store *store.Store
	// FeedsEnabled is false when STACKURITY_FEEDS=off.
	FeedsEnabled bool
	// PlatformWorkspace is the id or slug of the workspace platform
	// incidents are raised in (STACKURITY_PLATFORM_WORKSPACE); empty means
	// the default workspace.
	PlatformWorkspace string
}

// PlatformTarget returns the workspace platform incidents are raised in. When
// there is none (the configured workspace is missing or disabled), id is 0
// and why says so; err is only for failures to look it up.
func (c *Checker) PlatformTarget(ctx context.Context) (id int64, why string, err error) {
	ref := c.PlatformWorkspace
	if ref == "" {
		ref = strconv.FormatInt(tenant.DefaultWorkspace, 10)
	}
	id, disabled, err := c.Store.WorkspaceByRef(ctx, ref)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 0, fmt.Sprintf("Workspace %q, where platform incidents are raised, does not exist.", ref), nil
	case err != nil:
		return 0, "", err
	case disabled:
		return 0, fmt.Sprintf("Workspace %q, where platform incidents are raised, is disabled.", ref), nil
	}
	return id, "", nil
}

// Check reads platform state in system scope. Only instance admins and the
// server itself may see the result: task errors can name workspaces.
func (c *Checker) Check(ctx context.Context) (*Report, error) {
	ctx = tenant.System(ctx)
	now, err := c.Store.DBNow(ctx)
	if err != nil {
		return nil, err
	}
	r := &Report{CheckedAt: now, Problems: []Problem{}}

	tasks, err := c.Store.ListPeriodicTasks(ctx)
	if err != nil {
		return nil, err
	}
	r.Tasks = []store.PeriodicTask{}
	for _, t := range tasks {
		if now.Sub(t.SeenAt) > taskSeen {
			continue
		}
		r.Tasks = append(r.Tasks, t)
		r.Problems = append(r.Problems, taskProblems(t, now)...)
	}

	feeds, err := c.Store.ListFeeds(ctx)
	if err != nil {
		return nil, err
	}
	r.Problems = append(r.Problems, feedProblems(feeds, now, c.FeedsEnabled)...)

	if r.Jobs, r.OldestQueuedSeconds, err = c.Store.JobStats(ctx); err != nil {
		return nil, err
	}
	if r.Jobs == nil {
		r.Jobs = []store.JobCount{}
	}
	for _, j := range r.Jobs {
		if j.State == "failed" {
			r.Problems = append(r.Problems, Problem{Severity: Warning, Kind: "jobs", Key: j.Kind,
				Title:  fmt.Sprintf("%d %s job(s) failed in the last 24 hours", j.Count, j.Kind),
				Detail: "They ran out of retries; the latest errors are listed with the background tasks."})
		}
	}
	failed, err := c.Store.ListJobs(ctx, "failed", 10)
	if err != nil {
		return nil, err
	}
	r.RecentFailures = []FailedJob{}
	for _, j := range failed {
		if j.FailedAt != nil && now.Sub(*j.FailedAt) <= 24*time.Hour {
			r.RecentFailures = append(r.RecentFailures, FailedJob{ID: j.ID, Kind: j.Kind, WorkspaceID: j.WorkspaceID,
				Attempts: j.Attempts, LastError: j.LastError, FailedAt: *j.FailedAt})
		}
	}
	if _, why, err := c.PlatformTarget(ctx); err != nil {
		return nil, err
	} else if why != "" {
		r.Problems = append(r.Problems, Problem{Severity: Warning, Kind: "platform", Key: "incident-workspace",
			Title: "Platform problems are not raised as incidents",
			Detail: why + " Critical problems are shown here and in the banner, and logged by the server, instead. " +
				"Set STACKURITY_PLATFORM_WORKSPACE to an active workspace."})
	}
	if wait := time.Duration(r.OldestQueuedSeconds * float64(time.Second)); wait > queueBacklog {
		r.Problems = append(r.Problems, Problem{Severity: Warning, Kind: "jobs", Key: "backlog",
			Title:  "Background jobs are backing up",
			Detail: fmt.Sprintf("The oldest due job has waited %s for a worker.", wait.Round(time.Minute))})
	}

	sort.SliceStable(r.Problems, func(i, j int) bool {
		return r.Problems[i].Severity == Critical && r.Problems[j].Severity != Critical
	})
	r.Status = "ok"
	if len(r.Problems) > 0 {
		r.Status = string(r.Problems[0].Severity)
	}
	return r, nil
}

func taskProblems(t store.PeriodicTask, now time.Time) []Problem {
	grace := max(3*t.Every, taskGraceMin)
	since := t.CreatedAt
	if t.LastSuccessAt != nil {
		since = *t.LastSuccessAt
	}
	if now.Sub(since) > grace {
		p := Problem{Severity: Critical, Kind: "task", Key: t.Name,
			Title: fmt.Sprintf("Background task %s has not succeeded for %s", t.Name, ago(now.Sub(since)))}
		switch {
		case t.LastError != "":
			p.Detail = "Last error: " + t.LastError
		case t.LastStartedAt == nil:
			p.Detail = "It has never run. Check that a server is running and its worker is not stuck."
		default:
			p.Detail = "It has not finished a run recently. Check that a server is running and its worker is not stuck."
		}
		return []Problem{p}
	}
	if t.ConsecutiveFailures > 0 {
		return []Problem{{Severity: Warning, Kind: "task", Key: t.Name,
			Title:  fmt.Sprintf("Background task %s failed its last %d run(s)", t.Name, t.ConsecutiveFailures),
			Detail: "Last error: " + t.LastError}}
	}
	return nil
}

func feedProblems(feeds []store.Feed, now time.Time, enabled bool) []Problem {
	var out []Problem
	synced, attempted, failing := false, false, false
	var newest time.Time
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		if f.LastSuccess != nil && f.Kind == "vulnerability" {
			synced = true
		}
		if f.LastAttempt != nil {
			attempted = true
			if f.LastAttempt.After(newest) {
				newest = *f.LastAttempt
			}
		}
		if f.LastError != "" {
			failing = true
		}
		switch {
		case f.Stale && f.LastSuccess != nil:
			sev := Warning
			if f.Kind == "vulnerability" {
				sev = Critical
			}
			out = append(out, Problem{Severity: sev, Kind: "feed", Key: f.Name,
				Title:  fmt.Sprintf("Intelligence feed %s is stale: last synced %s ago", f.Name, ago(now.Sub(*f.LastSuccess))),
				Detail: errDetail(f.LastError)})
		case f.Stale && f.LastAttempt != nil && f.LastError != "":
			sev := Warning
			if f.Kind == "vulnerability" {
				sev = Critical
			}
			out = append(out, Problem{Severity: sev, Kind: "feed", Key: f.Name,
				Title: fmt.Sprintf("Intelligence feed %s has never synced", f.Name), Detail: errDetail(f.LastError)})
		case !f.Stale && f.LastError != "":
			out = append(out, Problem{Severity: Warning, Kind: "feed", Key: f.Name,
				Title:  fmt.Sprintf("Intelligence feed %s is failing; its data is still within its freshness limit", f.Name),
				Detail: errDetail(f.LastError)})
		}
	}
	if synced {
		return out
	}
	p := Problem{Kind: "intelligence", Key: "vulnerability"}
	switch {
	case !enabled:
		p.Severity, p.Title = Warning, "Intelligence feeds are turned off (STACKURITY_FEEDS=off) and no vulnerability data has been synced"
		p.Detail = "Vulnerabilities cannot be matched until feeds are turned on or pointed at a mirror (docs/network.md)."
	case !attempted || !failing && now.Sub(newest) < firstSync:
		// A stuck feed task shows up as an overdue task instead.
		p.Severity, p.Title = Warning, "The first vulnerability intelligence sync has not completed yet"
		p.Detail = "Findings appear once it completes, usually within a few minutes."
	default:
		p.Severity, p.Title = Critical, "No vulnerability intelligence has been synced"
		p.Detail = "Vulnerabilities cannot be matched. Check outbound access to the feeds or their mirrors, and the feed tasks above."
	}
	return append(out, p)
}

func errDetail(e string) string {
	if e == "" {
		return ""
	}
	return "Last error: " + e
}

// ago renders a duration for people: 45m, 7h, 3d.
func ago(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// PlatformIncidents turns critical platform problems into incidents for the
// operator's workspace (PlatformTarget), so the people who run the installation are notified
// through their usual routes. Feed problems are left out: every workspace
// already gets its own feed incidents. Details stay generic because task
// errors can name other workspaces; instance admins see them in the
// dashboard.
func (c *Checker) PlatformIncidents(ctx context.Context) ([]store.SystemIncident, error) {
	r, err := c.Check(ctx)
	if err != nil {
		return nil, err
	}
	var out []store.SystemIncident
	for _, p := range r.Problems {
		if p.Severity != Critical || p.Kind == "feed" {
			continue
		}
		title := p.Title
		if p.Kind == "task" {
			title = "Background task " + p.Key + " is not succeeding"
		}
		out = append(out, store.SystemIncident{Kind: "platform", Key: p.Kind + ":" + p.Key, Title: title, Priority: "P2",
			Detail: map[string]any{"problem": p.Kind}})
	}
	return out, nil
}
