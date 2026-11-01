package diag

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/words"
)

// Config is the server's configuration as `stackurity server` reads it from
// the same environment (cmd/stackurity resolves it).
type Config struct {
	Version, Edition string
	// FeedsEnabled is false when STACKURITY_FEEDS=off.
	FeedsEnabled bool
	// Intel holds the feed sources, mirrors included.
	Intel intel.Config
	// Offline skips the outbound reachability checks (air-gapped).
	Offline bool
	// Disks are the directories whose free space is checked, by the
	// setting that names them (STACKURITY_DATA_DIR, --backup-dir); an empty
	// path is not configured.
	Disks []Disk
	// LicenceKey is the key from STACKURITY_LICENSE or _FILE (LicenceFrom
	// names which); empty means the one stored in the database, if any.
	LicenceKey, LicenceFrom string
	// PlatformWorkspace and InsecureCookies are as for health.Checker.
	PlatformWorkspace string
	InsecureCookies   string
	// HTTP makes the reachability requests; nil means a client with a
	// 10-second timeout that uses the proxy environment, as feeds do.
	HTTP *http.Client
	// Memory reads the memory limit and GOMEMLIMIT; nil means this
	// process's (see memory.go).
	Memory func() MemoryInfo
}

// Disk is a directory whose free space matters.
type Disk struct {
	Setting string // STACKURITY_DATA_DIR, --backup-dir
	Path    string
	// Explicit: the path was set, so a missing directory is a problem
	// rather than an unused default.
	Explicit bool
}

// Doctor runs every check. st is nil when the database could not be
// opened (dbErr says why); the checks that need it are then skipped.
func Doctor(ctx context.Context, st *store.Store, dbErr error, cfg Config) *Report {
	ctx = tenant.System(ctx)
	r := &Report{Version: cfg.Version, Edition: cfg.Edition, CheckedAt: time.Now().UTC()}
	if st == nil {
		r.add(Result{Check: "database", Status: Fail, Title: "Cannot connect to the database",
			Detail: errText(dbErr),
			Next: "Check STACKURITY_DATABASE_URL (or STACKURITY_DATABASE_URL_FILE) is the one the server uses, that PostgreSQL is running " +
				"and accepts connections from this host (pg_isready), then run doctor again.",
			Docs: "docs/install.md"})
		r.add(Result{Check: "checks", Status: Skip, Title: "Database checks skipped",
			Detail: "Migrations, row-level security, licence, feeds, assets and background work are read from the database."})
	} else {
		r.add(checkDatabase(ctx, st)...)
		r.add(checkMigrations(ctx, st))
		r.add(checkLicence(ctx, st, cfg))
		r.add(checkPlatform(ctx, st, cfg)...)
	}
	for _, d := range cfg.Disks {
		r.add(checkDisk(d))
	}
	mem := cfg.Memory
	if mem == nil {
		mem = readMemory
	}
	r.add(checkMemory(mem()))
	r.finish()
	return r
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// checkDatabase: the database answers, and row-level security applies to
// the application's connections (as `stackurity server` requires).
func checkDatabase(ctx context.Context, st *store.Store) []Result {
	var version, user string
	if err := st.Pool.QueryRow(ctx, `SELECT current_setting('server_version'), current_user`).Scan(&version, &user); err != nil {
		return []Result{{Check: "database", Status: Fail, Title: "The database does not answer queries", Detail: err.Error(),
			Next: "Check PostgreSQL's log and that the server role may log in, then run doctor again.", Docs: "docs/install.md"}}
	}
	out := []Result{{Check: "database", Status: Pass,
		Title: fmt.Sprintf("PostgreSQL %s answers, connected as %s", version, user)}}

	iso := Result{Check: "isolation", Status: Pass, Title: "Row-level security applies to the server's connections (workspaces are isolated)",
		Docs: "docs/install.md#workspaces"}
	err := db.CheckIsolation(ctx, st.Pool)
	switch {
	case errors.Is(err, db.ErrIsolationBypassed):
		ids, lerr := st.ActiveWorkspaceIDs(ctx)
		if lerr != nil {
			err = lerr
			break
		}
		iso.Status, iso.Title, iso.Detail = Warn, "The database role bypasses row-level security", err.Error()
		iso.Next = "Let the migration create the stackurity_app role (the login role needs CREATEROLE once), or connect as a role that is not a superuser and has no BYPASSRLS."
		if len(ids) > 1 {
			iso.Status = Fail
			iso.Detail += fmt.Sprintf(". There are %d active workspaces, so the server refuses to start.", len(ids))
		}
		err = nil
	}
	if err != nil {
		iso.Status, iso.Title, iso.Detail = Fail, "Could not check row-level security", err.Error()
		iso.Next = "Check the database role's privileges (it must read pg_roles), then run doctor again."
	}
	if iso.Status == Pass {
		var on, forced *bool
		if err := st.Pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass('assets')`).
			Scan(&on, &forced); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			iso.Status, iso.Title, iso.Detail = Fail, "Could not check row-level security", err.Error()
		} else if on != nil && (!*on || !*forced) {
			iso.Status, iso.Title = Fail, "Row-level security is switched off on the assets table"
			iso.Detail = "Migration 0010 enables and forces it; it was changed by hand since."
			iso.Next = "Run ALTER TABLE assets ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY as the table owner, and find out who changed it."
		}
	}
	return append(out, iso)
}

// checkMigrations compares the migrations the database has with the ones
// this binary knows. A newer database is refused, as every command that
// opens it refuses it.
func checkMigrations(ctx context.Context, st *store.Store) Result {
	applied, err := db.Applied(ctx, st.Pool)
	if err != nil {
		return Result{Check: "migrations", Status: Fail, Title: "Could not read the applied migrations", Detail: err.Error(),
			Next: "Check that the server role may read schema_migrations, then run doctor again."}
	}
	known := db.Known()
	if err := db.CheckSchema(ctx, st.Pool); errors.Is(err, db.ErrNewerSchema) {
		return Result{Check: "migrations", Status: Fail, Title: "This database was upgraded by a newer Stackurity than this binary",
			Detail: err.Error() + ". This version refuses to run against it.",
			Next:   "Run the version that upgraded the database (check every replica and the image tag), or restore the backup taken before the upgrade.",
			Docs:   "docs/install.md#upgrading"}
	}
	have := map[string]bool{}
	for _, n := range applied {
		have[n] = true
	}
	var pending []string
	for _, n := range known {
		if !have[n] {
			pending = append(pending, n)
		}
	}
	if len(pending) > 0 {
		return Result{Check: "migrations", Status: Warn,
			Title:  fmt.Sprintf("%d of %d migrations are not applied yet (first: %s)", len(pending), len(known), pending[0]),
			Detail: "The server applies them when it starts. Until then a running server is an older version than this binary.",
			Next:   "Take a backup, then start this version's server (or run stackurity migrate) to apply them.",
			Docs:   "docs/install.md#upgrading"}
	}
	return Result{Check: "migrations", Status: Pass, Title: fmt.Sprintf("All %d migrations applied (latest %s)", len(known), known[len(known)-1])}
}

// licenceState is the licence in effect and where it came from.
type licenceState struct {
	Status license.Status
	From   string // STACKURITY_LICENSE, STACKURITY_LICENSE_FILE, database, or "" for none
	Err    error  // a key that does not verify (ignored, as the server ignores it)
	// RequiredFrom is when this server needs a key (a version that asks
	// self-hosted servers for a free Community key); nil when none is
	// needed.
	RequiredFrom *time.Time
}

func readLicence(ctx context.Context, st *store.Store, cfg Config) (licenceState, error) {
	s := licenceState{From: cfg.LicenceFrom}
	key := cfg.LicenceKey
	if strings.TrimSpace(key) == "" {
		k, err := st.LicenseKey(ctx)
		if err != nil {
			return s, err
		}
		key, s.From = k, "database"
	}
	var l *license.License
	if strings.TrimSpace(key) == "" {
		s.From = ""
	} else {
		l, s.Err = license.Parse(key)
	}
	s.Status = license.StatusAt(l, time.Now())
	// Versions that ask self-hosted servers for a key record from when in
	// license_requirement (a newer migration); without the table no key is
	// needed.
	var exists bool
	if err := st.Pool.QueryRow(ctx, `SELECT to_regclass('license_requirement') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return s, err
	}
	var from time.Time
	err := st.Pool.QueryRow(ctx, `SELECT required_from FROM license_requirement WHERE id = 1`).Scan(&from)
	switch {
	case err == nil:
		s.RequiredFrom = &from
	case errors.Is(err, pgx.ErrNoRows):
		// The row is written once by the migration; without it a key is
		// needed now.
		now := time.Now()
		s.RequiredFrom = &now
	default:
		return s, err
	}
	return s, nil
}

// checkLicence reports the edition in effect, a key that does not verify,
// an expiring licence, and, on versions that need one, a missing key.
func checkLicence(ctx context.Context, st *store.Store, cfg Config) Result {
	s, err := readLicence(ctx, st, cfg)
	if err != nil {
		return Result{Check: "licence", Status: Fail, Title: "Could not read the licence", Detail: err.Error(),
			Next: "Check that the server role may read license_key, then run doctor again."}
	}
	res := Result{Check: "licence", Status: Pass, Docs: "docs/editions.md"}
	l := s.Status.License
	switch {
	case s.Err != nil:
		res.Status, res.Title = Warn, fmt.Sprintf("The licence key (from %s) does not verify, so the server runs as Community", s.From)
		res.Detail = s.Err.Error()
		res.Next = "Install the key you were sent again (stackurity admin set-license, or Settings → Licence), or remove the one that does not verify."
	case l == nil:
		res.Title = "Community edition, no licence key"
	case s.Status.State == license.StateActive:
		res.Title = fmt.Sprintf("%s licence, valid until %s (from %s)", title(string(l.Edition)), l.ExpiresAt.Format("2006-01-02"), s.From)
		res.Detail = "Issued to " + l.Customer + "."
		if l.MaxAssets > 0 {
			if n, err := st.CountActiveAssets(ctx); err == nil {
				res.Detail += fmt.Sprintf(" %d of %d assets used.", n, l.MaxAssets)
			}
		}
	case s.Status.State == license.StateGrace:
		res.Status = Warn
		res.Title = fmt.Sprintf("The %s licence expired on %s; paid features stop on %s", l.Edition, l.ExpiresAt.Format("2006-01-02"), s.Status.GraceEnds.Format("2006-01-02"))
		res.Next = "Renew the licence and install the new key (stackurity admin set-license, or Settings → Licence)."
	default:
		res.Status = Warn
		res.Title = fmt.Sprintf("The %s licence expired on %s: running as Community", l.Edition, l.ExpiresAt.Format("2006-01-02"))
		res.Detail = "Detection, alerting and the free features keep working; paid features are off."
		res.Next = "Renew the licence and install the new key, or remove it to run as Community."
	}
	if s.RequiredFrom != nil && (l == nil || s.Err != nil) {
		// A key is needed and none verifies: the dashboard and API wait
		// for one from RequiredFrom (agents and scans keep uploading).
		res.Next = "Enter a free Community key or a licence under Settings → Licence, or with stackurity admin set-license " +
			"(an air-gapped server can get its key on any other computer)."
		if time.Now().Before(*s.RequiredFrom) {
			res.Status = Warn
			res.Title = "No licence key yet: this server needs a free Community key or a licence by " + s.RequiredFrom.Format("2006-01-02")
		} else {
			res.Status = Fail
			res.Title = "No licence key: the dashboard and API wait for a free Community key or a licence"
			res.Detail = "Agents, CLI scans and uploads keep working, and their data is kept."
		}
	}
	return res
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// checkPlatform reads the health report (the dashboard's Platform health)
// once and turns it into results: each feed, the assets' reports, and every
// other problem it finds. Outbound reachability follows the feeds.
func checkPlatform(ctx context.Context, st *store.Store, cfg Config) []Result {
	checker := &health.Checker{Store: st, FeedsEnabled: cfg.FeedsEnabled, PlatformWorkspace: cfg.PlatformWorkspace,
		InsecureCookies: cfg.InsecureCookies}
	rep, err := checker.Check(ctx)
	if err != nil {
		return []Result{{Check: "health", Status: Fail, Title: "Could not read the platform's health", Detail: err.Error(),
			Next: "Check the database (above) and run doctor again."}}
	}
	feeds, err := st.ListFeeds(ctx)
	if err != nil {
		return []Result{{Check: "feeds", Status: Fail, Title: "Could not read the feeds", Detail: err.Error()}}
	}
	feedProblems := map[string]health.Problem{}
	var out, rest []Result
	for _, p := range rep.Problems {
		if p.Kind == "feed" {
			feedProblems[p.Key] = p
			continue
		}
		rest = append(rest, problemResult(p))
	}
	out = append(out, checkFeeds(feeds, feedProblems, cfg, rep.CheckedAt)...)
	out = append(out, checkReach(ctx, feeds, cfg)...)
	out = append(out, checkAssets(ctx, st, rep.CheckedAt))
	return append(out, rest...)
}

func problemResult(p health.Problem) Result {
	r := Result{Check: "health:" + p.Kind + ":" + p.Key, Status: Warn, Title: p.Title, Detail: p.Detail, Next: p.NextStep, Docs: p.Docs}
	if p.Severity == health.Critical {
		r.Status = Fail
	}
	if r.Detail == "" {
		r.Detail = p.Scope.Summary
	}
	return r
}

// behind: a feed that has not synced for this many refresh intervals is
// behind schedule even before it is stale (a sync killed part-way, by the
// OOM killer for one, leaves no error until the next attempt).
const behind = 3

func checkFeeds(feeds []store.Feed, problems map[string]health.Problem, cfg Config, now time.Time) []Result {
	var out []Result
	for _, f := range feeds {
		r := Result{Check: "feed:" + f.Name, Status: Pass, Docs: "docs/network.md"}
		schedule := fmt.Sprintf("refreshed every %s, stale after %s", Ago(time.Duration(f.RefreshMin)*time.Minute), Ago(time.Duration(f.StaleMin)*time.Minute))
		var age time.Duration
		if f.LastSuccess != nil {
			age = now.Sub(*f.LastSuccess)
		}
		p, problem := problems[f.Name]
		switch {
		case problem:
			r = problemResult(p)
			r.Check = "feed:" + f.Name
			r.Detail = strings.TrimSpace(p.Detail + " (" + schedule + ")")
		case !f.Enabled:
			r.Status, r.Title = Warn, "Turned off: its data is not refreshed"
			r.Detail = fmt.Sprintf("A %s feed. Findings that depend on it are evaluated against the data it last had.", f.Kind)
			r.Next = "If that was not intended, an instance admin turns it back on under Intelligence."
			r.Docs = "docs/install.md#intelligence"
		case !cfg.FeedsEnabled:
			r.Status, r.Title = Skip, "Not refreshed: STACKURITY_FEEDS=off"
			if f.LastSuccess != nil {
				r.Detail = "Last synced " + Ago(age) + " ago."
			}
		case f.LastSuccess == nil:
			r.Status, r.Title = Warn, "Has not synced yet"
			r.Detail = "Its first sync is due or running (" + schedule + ")."
			r.Next = "Wait a few minutes; if it does not sync within an hour, check the feed.sync jobs and the server log for this feed."
		case f.RefreshMin > 0 && age > behind*time.Duration(f.RefreshMin)*time.Minute:
			r.Status, r.Title = Warn, fmt.Sprintf("Behind schedule: last synced %s ago", Ago(age))
			r.Detail = "Not stale yet (" + schedule + "), but no sync has succeeded for " + fmt.Sprint(behind) + " intervals and none recorded an error."
			r.Next = "Check that a server is running its worker, and the server log for feed.sync and for restarts (a sync killed part-way, " +
				"for example by the OOM killer, records nothing until its next attempt)."
		default:
			r.Title = fmt.Sprintf("Last synced %s ago (%s)", Ago(age), schedule)
		}
		out = append(out, r)
	}
	if len(feeds) == 0 && cfg.FeedsEnabled {
		out = append(out, Result{Check: "feeds", Status: Warn, Title: "No intelligence feeds exist yet",
			Detail: "The server creates them a minute after it starts, for the ecosystems in the inventory.",
			Next:   "Check that a server is running; feeds appear once it has run for a minute.", Docs: "docs/install.md#intelligence"})
	}
	return out
}

// checkReach makes one request to each host the enabled feeds read from,
// through the proxy settings feeds use. Any HTTP answer means the network
// path works.
func checkReach(ctx context.Context, feeds []store.Feed, cfg Config) []Result {
	if !cfg.FeedsEnabled {
		return []Result{{Check: "reach", Status: Skip, Title: "Outbound access not checked: feeds are off (STACKURITY_FEEDS=off)"}}
	}
	if cfg.Offline {
		return []Result{{Check: "reach", Status: Skip, Title: "Outbound access not checked (--offline)",
			Detail: "An air-gapped server reads feeds from mirrors; their freshness is checked above."}}
	}
	type target struct {
		url   string
		feeds []string
		vuln  bool
	}
	byHost := map[string]*target{}
	var hosts []string
	for _, f := range feeds {
		if !f.Enabled {
			continue
		}
		for _, src := range cfg.Intel.Sources(f.Name) {
			u, err := url.Parse(src)
			if err != nil || u.Host == "" {
				continue
			}
			h := u.Scheme + "://" + u.Host
			t := byHost[h]
			if t == nil {
				t = &target{url: src}
				byHost[h] = t
				hosts = append(hosts, h)
			}
			if !contains(t.feeds, f.Name) {
				t.feeds = append(t.feeds, f.Name)
			}
			t.vuln = t.vuln || f.Kind == "vulnerability"
		}
	}
	sort.Strings(hosts)
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	out := make([]Result, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, h := range hosts {
		t := byHost[h]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u, _ := url.Parse(h)
			r := Result{Check: "reach:" + u.Host, Status: Pass, Docs: "docs/network.md"}
			used := strings.Join(t.feeds, ", ")
			code, err := probe(ctx, client, t.url)
			switch {
			case err != nil:
				r.Status, r.Title = Warn, "Cannot reach "+u.Host+" (used by "+used+")"
				if t.vuln {
					r.Status = Fail
				}
				r.Detail = err.Error()
				r.Next = "Allow outbound HTTPS from this server to " + u.Host + " (through HTTPS_PROXY if you use one), or point these feeds at a mirror. " +
					"On an air-gapped server, run doctor with --offline."
			case code == http.StatusProxyAuthRequired:
				r.Status, r.Title = Fail, "The proxy refuses requests to "+u.Host+" (407 Proxy Authentication Required)"
				r.Next = "Put the proxy's credentials in HTTPS_PROXY, or allow the server through the proxy without them."
			default:
				r.Title = fmt.Sprintf("%s answers (HTTP %d), used by %s", u.Host, code, used)
			}
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func probe(ctx context.Context, c *http.Client, u string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "stackurity-doctor")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// checkAssets summarises how assets report. Those that stopped are health
// problems (silent agents, overdue scans), reported after this line.
func checkAssets(ctx context.Context, st *store.Store, now time.Time) Result {
	counts, err := st.ReportingCounts(ctx)
	if err != nil {
		return Result{Check: "assets", Status: Fail, Title: "Could not read the assets' reports", Detail: err.Error()}
	}
	var total, stale int64
	var parts []string
	for _, c := range counts {
		total += c.Assets
		stale += c.Stale
		src := c.Source
		if src == "" {
			src = "unknown source"
		}
		p := fmt.Sprintf("%s %d", src, c.Assets)
		if c.Newest != nil {
			p += fmt.Sprintf(" (latest report %s ago)", Ago(now.Sub(*c.Newest)))
		}
		parts = append(parts, p)
	}
	if total == 0 {
		return Result{Check: "assets", Status: Warn, Title: "No assets have reported yet",
			Next: "Install the agent on a server, or run stackurity scan in a repository or CI job.", Docs: "docs/install.md#collecting-inventory"}
	}
	r := Result{Check: "assets", Status: Pass, Title: words.Count(int(total), "asset", "assets") + ": " + strings.Join(parts, ", "),
		Docs: "docs/operations.md#assets-that-stop-reporting"}
	if stale > 0 {
		r.Detail = fmt.Sprintf("%d of them stopped reporting: see the problems below (silent agents, overdue scans).", stale)
	}
	return r
}

// checkDisk reports a directory's free space.
func checkDisk(d Disk) Result {
	r := Result{Check: "disk", Status: Pass, Docs: "docs/operations.md#disk-exhaustion"}
	if _, err := os.Stat(d.Path); err != nil {
		if !d.Explicit && errors.Is(err, os.ErrNotExist) {
			r.Status, r.Title = Skip, d.Setting+" is not set and its default does not exist on this host"
			return r
		}
		r.Status, r.Title, r.Detail = Warn, "Cannot read "+d.Path+" ("+d.Setting+")", err.Error()
		r.Next = "Run doctor where the server runs (in its container), or create the directory and give the server's user write access."
		return r
	}
	free, total, err := diskSpace(d.Path)
	if err != nil {
		r.Status, r.Title, r.Detail = Skip, "Free space not checked on this system", err.Error()
		return r
	}
	pct := 100 * float64(free) / float64(max(total, 1))
	r.Title = fmt.Sprintf("%s free of %s (%.0f%%) at %s (%s)", bytesIEC(free), bytesIEC(total), pct, d.Path, d.Setting)
	const gib = 1 << 30
	switch {
	case free < gib:
		r.Status = Fail
		r.Next = "Free space now: feed downloads and repository and image scans fail without it (a full Ubuntu archive is about 750 MB). " +
			"Files under the work directory are temporary and can be deleted while the server is stopped."
	case free < 5*gib:
		r.Status = Warn
		r.Next = "Give the volume more room before it fills: feed downloads and scans need a few GiB at a time."
	}
	return r
}
