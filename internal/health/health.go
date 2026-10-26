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
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
)

// Problem is one thing an operator should look at: what is wrong, when it
// last worked, the latest error, what it affects and what to do next.
type Problem struct {
	Severity Severity `json:"severity"`
	// Kind is feed, intelligence, task, jobs, platform, integration,
	// notification, collector or coverage.
	Kind   string `json:"kind"`
	Key    string `json:"key"` // feed name, task name, job kind, ...
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	// LastSuccess is when it last worked (the latest sync, run, completed
	// job, delivery or report); nil when it never did or does not apply.
	LastSuccess *time.Time `json:"last_success"`
	// LastError is the latest error, as recorded (credentials are redacted
	// where they are stored). Errors of objects in other workspaces than the
	// viewer's are left out.
	LastError string `json:"last_error,omitempty"`
	Scope     Scope  `json:"scope"`
	// NextStep is what to do about it, and Docs the documentation section
	// that explains it (a path in the repository, such as
	// docs/install.md#health).
	NextStep string `json:"next_step"`
	Docs     string `json:"docs"`
}

// Scope is what a problem affects.
type Scope struct {
	Summary string `json:"summary"`
	// Count is the number of affected objects (jobs, assets,
	// integrations, channels), in every workspace.
	Count int64 `json:"count,omitempty"`
	// Workspaces is the number of workspaces affected.
	Workspaces int64 `json:"workspaces,omitempty"`
	// Items names affected objects, only those in the viewer's active
	// workspace and at most ItemLimit; Hidden counts the rest.
	Items  []ScopeItem `json:"items,omitempty"`
	Hidden int64       `json:"hidden,omitempty"`
}

// ScopeItem is one affected object in the viewer's workspace.
type ScopeItem struct {
	Name        string     `json:"name"`
	Detail      string     `json:"detail,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	// Link is the dashboard page for the object.
	Link string `json:"link,omitempty"`
}

// ItemLimit bounds the objects a problem names.
const ItemLimit = 10

// Documentation sections problems point to.
const (
	docsHealth       = "docs/install.md#health"
	docsIntelligence = "docs/install.md#intelligence"
	docsNetwork      = "docs/network.md"
	docsJobs         = "docs/reliability.md#jobs-feed-syncs-evaluations-integration-runs-image-scans"
	docsTasks        = "docs/reliability.md#periodic-tasks-alert-dispatcher-digests-feed-and-integration-scheduling-housekeeping"
	docsNotify       = "docs/install.md#notifications"
	docsCollect      = "docs/install.md#collecting-inventory"
	docsRepos        = "docs/install.md#repositories"
	docsWorkspaces   = "docs/install.md#workspaces"
	docsVerification = "docs/verification.md"
)

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
// server itself may see the result: task errors can name workspaces. It names
// no workspace's objects; see CheckFor.
func (c *Checker) Check(ctx context.Context) (*Report, error) { return c.CheckFor(ctx, 0) }

// CheckFor is Check for an instance administrator whose active workspace is
// viewerWS: problems that span workspaces count every workspace's objects but
// name (and show the errors of) only those in viewerWS.
func (c *Checker) CheckFor(ctx context.Context, viewerWS int64) (*Report, error) {
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
	kinds, err := c.Store.JobKindHealth(ctx)
	if err != nil {
		return nil, err
	}
	r.Problems = append(r.Problems, jobProblems(kinds)...)
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
				"Set STACKURITY_PLATFORM_WORKSPACE to an active workspace.",
			Scope:    Scope{Summary: "platform incident routing"},
			NextStep: "Set STACKURITY_PLATFORM_WORKSPACE to the id or slug of an active workspace and restart the servers.",
			Docs:     docsHealth})
	}
	if wait := time.Duration(r.OldestQueuedSeconds * float64(time.Second)); wait > queueBacklog {
		var queued int64
		for _, j := range r.Jobs {
			if j.State == "queued" {
				queued += j.Count
			}
		}
		r.Problems = append(r.Problems, Problem{Severity: Warning, Kind: "jobs", Key: "backlog",
			Title:    "Background jobs are backing up",
			Detail:   fmt.Sprintf("The oldest due job has waited %s for a worker.", wait.Round(time.Minute)),
			Scope:    Scope{Summary: fmt.Sprintf("%d job(s) due and waiting for a worker", queued), Count: queued},
			NextStep: "Check that every server replica is running and its worker is not stuck on long jobs; add a replica if the load stays high.",
			Docs:     docsJobs})
	}
	more, err := c.objectProblems(ctx, viewerWS)
	if err != nil {
		return nil, err
	}
	r.Problems = append(r.Problems, more...)

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
	scope := Scope{Summary: fmt.Sprintf("task %s, every %s", t.Name, ago(t.Every))}
	if now.Sub(since) > grace {
		p := Problem{Severity: Critical, Kind: "task", Key: t.Name,
			Title:       fmt.Sprintf("Background task %s has not succeeded for %s", t.Name, ago(now.Sub(since))),
			LastSuccess: t.LastSuccessAt, LastError: t.LastError, Scope: scope, Docs: docsTasks}
		switch {
		case t.LastError != "":
			p.Detail = "Last error: " + t.LastError
			p.NextStep = "Fix the cause in the error (database, network or configuration); the task retries on its own schedule. The server log has the full error."
		case t.LastStartedAt == nil:
			p.Detail = "It has never run. Check that a server is running and its worker is not stuck."
			p.NextStep = "Check that at least one server replica is running with its worker, and look for the task in the server log."
		default:
			p.Detail = "It has not finished a run recently. Check that a server is running and its worker is not stuck."
			p.NextStep = "Check that at least one server replica is running and not stuck (CPU, memory, database locks); restart it if a run never finishes."
		}
		return []Problem{p}
	}
	if t.ConsecutiveFailures > 0 {
		return []Problem{{Severity: Warning, Kind: "task", Key: t.Name,
			Title:       fmt.Sprintf("Background task %s failed its last %d run(s)", t.Name, t.ConsecutiveFailures),
			Detail:      "Last error: " + t.LastError,
			LastSuccess: t.LastSuccessAt, LastError: t.LastError, Scope: scope, Docs: docsTasks,
			NextStep: "Read the error: a temporary failure clears on the next run; one that repeats needs its cause fixed (database, network, configuration)."}}
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
		base := Problem{Kind: "feed", Key: f.Name, Detail: errDetail(f.LastError), LastSuccess: f.LastSuccess, LastError: f.LastError,
			Scope: Scope{Summary: fmt.Sprintf("%s feed %s, used by every workspace; stale after %s", f.Kind, f.Name,
				ago(time.Duration(f.StaleMin)*time.Minute))},
			NextStep: "Check outbound HTTPS access to the feed's source or the mirror configured for it, then use Refresh on the Intelligence page. " +
				"Findings evaluated while it is stale are marked as such.",
			Docs: docsNetwork}
		sev := Warning
		if f.Kind == "vulnerability" {
			sev = Critical
		}
		switch {
		case f.Stale && f.LastSuccess != nil:
			p := base
			p.Severity = sev
			p.Title = fmt.Sprintf("Intelligence feed %s is stale: last synced %s ago", f.Name, ago(now.Sub(*f.LastSuccess)))
			out = append(out, p)
		case f.Stale && f.LastAttempt != nil && f.LastError != "":
			p := base
			p.Severity = sev
			p.Title = fmt.Sprintf("Intelligence feed %s has never synced", f.Name)
			out = append(out, p)
		case !f.Stale && f.LastError != "":
			p := base
			p.Severity = Warning
			p.Title = fmt.Sprintf("Intelligence feed %s is failing; its data is still within its freshness limit", f.Name)
			p.NextStep = "Nothing is stale yet. Check outbound access to the feed's source or mirror before its data passes the freshness limit."
			out = append(out, p)
		}
	}
	if synced {
		return out
	}
	p := Problem{Kind: "intelligence", Key: "vulnerability", Scope: Scope{Summary: "vulnerability matching in every workspace"}, Docs: docsIntelligence}
	switch {
	case !enabled:
		p.Severity, p.Title = Warning, "Intelligence feeds are turned off (STACKURITY_FEEDS=off) and no vulnerability data has been synced"
		p.Detail = "Vulnerabilities cannot be matched until feeds are turned on or pointed at a mirror (docs/network.md)."
		p.NextStep, p.Docs = "Turn feeds on (unset STACKURITY_FEEDS) or point them at a mirror reachable from the server.", docsNetwork
	case !attempted || !failing && now.Sub(newest) < firstSync:
		// A stuck feed task shows up as an overdue task instead.
		p.Severity, p.Title = Warning, "The first vulnerability intelligence sync has not completed yet"
		p.Detail = "Findings appear once it completes, usually within a few minutes."
		p.NextStep = "Wait for the first sync; if it has not finished within an hour, check the feed task and outbound access."
	default:
		p.Severity, p.Title = Critical, "No vulnerability intelligence has been synced"
		p.Detail = "Vulnerabilities cannot be matched. Check outbound access to the feeds or their mirrors, and the feed tasks above."
		p.NextStep, p.Docs = "Check outbound HTTPS access to the feeds (or their mirrors) and the errors of the feeds listed here.", docsNetwork
	}
	return append(out, p)
}

// platformKinds are the problem kinds about the platform itself, which may
// become platform incidents.
var platformKinds = map[string]bool{"task": true, "jobs": true, "intelligence": true, "platform": true}

func jobProblems(kinds []store.JobKindHealth) []Problem {
	var out []Problem
	for _, k := range kinds {
		var parts []string
		if k.Failed > 0 {
			parts = append(parts, fmt.Sprintf("%d failed in the last 24 hours", k.Failed))
		}
		if k.Retrying > 0 {
			parts = append(parts, fmt.Sprintf("%d being retried (%d after three or more attempts)", k.Retrying, k.RetriedOften))
		}
		where := fmt.Sprintf("in %d workspace(s)", k.Workspaces)
		if k.Platform {
			where = "platform jobs"
			if k.Workspaces > 0 {
				where = fmt.Sprintf("platform jobs and %d workspace(s)", k.Workspaces)
			}
		}
		p := Problem{Severity: Warning, Kind: "jobs", Key: k.Kind, LastSuccess: k.LastSuccess, LastError: k.LastError,
			Scope: Scope{Summary: fmt.Sprintf("job kind %s: %s; %s", k.Kind, strings.Join(parts, ", "), where),
				Count: k.Failed + k.Retrying, Workspaces: k.Workspaces},
			Docs: docsJobs}
		switch {
		case k.Failed > 0:
			p.Title = fmt.Sprintf("%d %s job(s) failed in the last 24 hours", k.Failed, k.Kind)
			p.Detail = "They ran out of retries; the latest errors are listed below."
			p.NextStep = "Fix the cause in the latest error, then run the work again (Refresh a feed, Run an integration, Re-evaluate). " +
				"Settings > Background jobs lists each failed job."
		case k.RetriedOften > 0:
			p.Title = fmt.Sprintf("%d %s job(s) are being retried repeatedly", k.RetriedOften, k.Kind)
			p.Detail = "Each failed attempt is retried with a growing delay; after five attempts the job is marked failed."
			p.NextStep = "Read the latest error: a temporary outage clears on its own, a configuration or data problem needs fixing before the retries run out."
		default:
			continue // a first retry is normal
		}
		out = append(out, p)
	}
	return out
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
		// Feeds are left out, and so are problems about one workspace's
		// objects (integrations, channels, assets): their titles may name them.
		if p.Severity != Critical || !platformKinds[p.Kind] {
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
