package diag

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Bundle is what `stackurity support-bundle` writes: the installation's
// state, for support, without its contents. It holds counts, states and
// errors, never inventory, package lists, asset or host names, findings,
// email addresses, tokens or URLs. Configuration is redacted by default:
// only the settings in safeEnv and safeSettings keep their values (a
// deny-list would leak every new secret). Free text (titles, errors) goes
// through Redactor first.
type Bundle struct {
	Format    int       `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Build     struct {
		Version string `json:"version"`
		Edition string `json:"edition"`
		Go      string `json:"go"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
	} `json:"build"`
	Database struct {
		Reachable bool   `json:"reachable"`
		Version   string `json:"version,omitempty"`
		Error     string `json:"error,omitempty"`
	} `json:"database"`
	Licence    *BundleLicence        `json:"licence,omitempty"`
	Doctor     []Result              `json:"doctor"`
	Migrations *BundleMigrations     `json:"migrations,omitempty"`
	Feeds      []BundleFeed          `json:"feeds,omitempty"`
	Tasks      []BundleTask          `json:"periodic_tasks,omitempty"`
	Jobs       *BundleJobs           `json:"jobs,omitempty"`
	Deliveries []store.DeliveryCount `json:"notification_deliveries,omitempty"`
	Counts     *BundleCounts         `json:"counts,omitempty"`
	// Environment lists the STACKURITY_* variables (and the Go runtime's)
	// set for this process; values not on the allow-list read "<redacted>".
	Environment []Setting `json:"environment"`
	// Settings are the workspaces' stored settings, by workspace id, with
	// the same rule.
	Settings []WorkspaceSetting `json:"settings,omitempty"`
	Logs     string             `json:"logs"`
	Notes    []string           `json:"notes"`
}

type BundleLicence struct {
	State     license.State   `json:"state"`
	Edition   license.Edition `json:"edition"`
	From      string          `json:"from,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
	GraceEnds *time.Time      `json:"grace_ends,omitempty"`
	MaxAssets int             `json:"max_assets,omitempty"`
	Invalid   string          `json:"invalid,omitempty"`
	// RequiredFrom: this version needs a key from then.
	RequiredFrom *time.Time `json:"key_required_from,omitempty"`
}

type BundleMigrations struct {
	Known   int      `json:"known"`
	Applied []string `json:"applied"`
	Pending []string `json:"pending,omitempty"`
	Unknown []string `json:"unknown_to_this_binary,omitempty"`
}

type BundleFeed struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Enabled     bool       `json:"enabled"`
	RefreshMin  int64      `json:"refresh_minutes"`
	StaleMin    int64      `json:"stale_after_minutes"`
	Records     int64      `json:"records"`
	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	LastError   string     `json:"last_error,omitempty"`
	Stale       bool       `json:"stale"`
	// Source is "default" or "mirror": whether the configuration points it
	// somewhere else (the mirror's address is not included).
	Source string `json:"source"`
}

type BundleTask struct {
	Name                string     `json:"name"`
	EverySeconds        float64    `json:"every_seconds"`
	LastStartedAt       *time.Time `json:"last_started_at"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	LastDurationSeconds *float64   `json:"last_duration_seconds,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	Running             bool       `json:"running"`
}

type BundleJobs struct {
	Counts              []store.JobCount   `json:"counts"`
	OldestQueuedSeconds float64            `json:"oldest_queued_seconds"`
	RecentFailures      []health.FailedJob `json:"recent_failures"`
}

type BundleCounts struct {
	Instance         store.InstanceCounts   `json:"instance"`
	AssetsByKind     []store.Count          `json:"assets_by_kind"`
	AssetsByReport   []store.ReportingCount `json:"assets_by_reporting"`
	FindingsByStatus []store.Count          `json:"findings_by_status"`
}

// Setting is one configuration value as the bundle shows it.
type Setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type WorkspaceSetting struct {
	WorkspaceID int64  `json:"workspace_id"`
	Key         string `json:"key"`
	Value       string `json:"value"`
}

// Redacted replaces a value that is not on the allow-list.
const Redacted = "<redacted>"

// safeEnv are the environment variables whose values are kept: switches,
// numbers and durations that cannot hold a secret, an address or a name.
// Anything else, including variables this version does not know, is
// redacted.
var safeEnv = map[string]bool{
	"STACKURITY_FEEDS": true, "STACKURITY_LOG_LEVEL": true, "STACKURITY_LOG_FORMAT": true, "STACKURITY_STALE_AFTER": true,
	"STACKURITY_COOKIE_SECURE": true, "STACKURITY_TRUST_PROXY": true, "STACKURITY_ALLOW_HTTP_WEBHOOKS": true,
	"STACKURITY_HEAP_WARN_MIB": true, "STACKURITY_MSRC_MONTHS": true, "STACKURITY_SESSION_IDLE_TIMEOUT": true,
	"STACKURITY_UPDATE_CHECK": true, "STACKURITY_BREACHED_PASSWORD_CHECK": true, "STACKURITY_PACK_ALLOW_UNSIGNED": true,
	"STACKURITY_SMTP_TLS": true, "STACKURITY_SMTP_PORT": true, "STACKURITY_TEST_TIMINGS": true,
	"GOMEMLIMIT": true, "GOGC": true, "GOMAXPROCS": true,
}

// safeSettings are the stored settings whose values are kept.
var safeSettings = map[string]bool{"fix_grouping": true}

// safeValue is the shape an allow-listed value must still have: a value
// that does not look like a switch, number or duration is redacted anyway.
var safeValue = regexp.MustCompile(`^[A-Za-z0-9_.,:=+-]{0,64}$`)

// environment returns the variables set for this process that concern
// Stackurity, redacted. Secrets referenced as env:STACKURITY_SECRET_* are
// counted, not named: their names are the operator's own.
func environment(environ []string) []Setting {
	var out []Setting
	secrets := 0
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, "STACKURITY_") && !safeEnv[k] {
			continue
		}
		if strings.HasPrefix(k, "STACKURITY_SECRET_") && k != "STACKURITY_SECRET_KEY" && k != "STACKURITY_SECRET_KEY_FILE" {
			secrets++
			continue
		}
		val := Redacted
		switch {
		case v == "":
			val = ""
		case safeEnv[k] && safeValue.MatchString(v):
			val = v
		}
		out = append(out, Setting{Name: k, Value: val})
	}
	if secrets > 0 {
		out = append(out, Setting{Name: "STACKURITY_SECRET_* (secrets for env: references)", Value: strconv.Itoa(secrets) + " set, " + Redacted})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// BundleInput is what the bundle is built from.
type BundleInput struct {
	Config  Config
	Store   *store.Store // nil when the database could not be opened
	DBErr   error
	Report  *Report  // the doctor's report
	Environ []string // os.Environ()
}

// BuildBundle collects the bundle. Sections it cannot read are left out
// with a note; the bundle is then still useful.
func BuildBundle(ctx context.Context, in BundleInput) *Bundle {
	ctx = tenant.System(ctx)
	red := NewRedactor(in.Environ, in.Config.Intel)
	b := &Bundle{Format: 1, CreatedAt: time.Now().UTC(), Notes: []string{}}
	b.Build.Version, b.Build.Edition = in.Config.Version, in.Config.Edition
	b.Build.Go, b.Build.OS, b.Build.Arch = runtime.Version(), runtime.GOOS, runtime.GOARCH
	b.Environment = environment(in.Environ)
	b.Logs = "Not included: Stackurity writes its log to standard error and keeps no copy it could read back. " +
		"If support asks for it, attach `docker compose logs stackurity` or `journalctl -u stackurity` after reading it."
	b.Notes = append(b.Notes, "Configuration values are redacted unless allow-listed; errors and titles have URLs, addresses, "+
		"host names, email addresses, paths and token-like strings replaced. No inventory, package, asset, host or finding detail is included.")
	note := func(section string, err error) {
		b.Notes = append(b.Notes, section+" could not be read: "+red.Text(err.Error()))
	}

	if in.Report != nil {
		for _, r := range in.Report.Results {
			r.Check, r.Title, r.Detail, r.Next = red.Text(r.Check), red.Text(r.Title), red.Text(r.Detail), red.Text(r.Next)
			if r.Check == "licence" {
				r.Detail = "" // names the licence holder; the licence section has the state
			}
			b.Doctor = append(b.Doctor, r)
		}
	}
	st := in.Store
	if st == nil {
		b.Database.Error = red.Text(errText(in.DBErr))
		return b
	}
	b.Database.Reachable = true
	if err := st.Pool.QueryRow(ctx, `SELECT current_setting('server_version')`).Scan(&b.Database.Version); err != nil {
		note("database version", err)
	}

	if s, err := readLicence(ctx, st, in.Config); err != nil {
		note("licence", err)
	} else {
		l := &BundleLicence{State: s.Status.State, Edition: s.Status.Edition, From: s.From, GraceEnds: s.Status.GraceEnds, RequiredFrom: s.RequiredFrom}
		if s.Status.License != nil {
			exp := s.Status.License.ExpiresAt
			l.ExpiresAt, l.MaxAssets = &exp, s.Status.License.MaxAssets
		}
		if s.Err != nil {
			l.Invalid = red.Text(s.Err.Error())
		}
		b.Licence = l
	}

	if applied, err := db.Applied(ctx, st.Pool); err != nil {
		note("migrations", err)
	} else {
		m := &BundleMigrations{Applied: applied}
		known := db.Known()
		m.Known = len(known)
		have, knows := map[string]bool{}, map[string]bool{}
		for _, n := range applied {
			have[n] = true
		}
		for _, n := range known {
			knows[n] = true
			if !have[n] {
				m.Pending = append(m.Pending, n)
			}
		}
		for _, n := range applied {
			if !knows[n] {
				m.Unknown = append(m.Unknown, n)
			}
		}
		b.Migrations = m
	}

	if feeds, err := st.ListFeeds(ctx); err != nil {
		note("feeds", err)
	} else {
		def := intel.DefaultConfig()
		for _, f := range feeds {
			src := "default"
			if strings.Join(in.Config.Intel.Sources(f.Name), " ") != strings.Join(def.Sources(f.Name), " ") {
				src = "mirror"
			}
			b.Feeds = append(b.Feeds, BundleFeed{Name: f.Name, Kind: f.Kind, Enabled: f.Enabled, RefreshMin: f.RefreshMin, StaleMin: f.StaleMin,
				Records: f.Records, LastAttempt: f.LastAttempt, LastSuccess: f.LastSuccess, LastError: red.Text(f.LastError), Stale: f.Stale, Source: src})
		}
	}

	checker := &health.Checker{Store: st, FeedsEnabled: in.Config.FeedsEnabled}
	if rep, err := checker.Check(ctx); err != nil {
		note("background work", err)
	} else {
		for _, t := range rep.Tasks {
			bt := BundleTask{Name: red.Text(t.Name), EverySeconds: t.EverySeconds, LastStartedAt: t.LastStartedAt, LastSuccessAt: t.LastSuccessAt,
				LastError: red.Text(t.LastError), ConsecutiveFailures: t.ConsecutiveFailures, Running: t.Running}
			if t.LastDuration != nil {
				s := t.LastDuration.Seconds()
				bt.LastDurationSeconds = &s
			}
			b.Tasks = append(b.Tasks, bt)
		}
		j := &BundleJobs{Counts: rep.Jobs, OldestQueuedSeconds: rep.OldestQueuedSeconds, RecentFailures: []health.FailedJob{}}
		for _, f := range rep.RecentFailures {
			f.LastError = red.Text(f.LastError)
			j.RecentFailures = append(j.RecentFailures, f)
		}
		b.Jobs = j
		b.Deliveries = rep.Deliveries
	}

	c := &BundleCounts{}
	var err error
	if c.Instance, err = st.InstanceCounts(ctx); err != nil {
		note("counts", err)
	}
	if c.AssetsByKind, err = st.AssetKindCounts(ctx); err != nil {
		note("asset counts", err)
	}
	if c.AssetsByReport, err = st.ReportingCounts(ctx); err != nil {
		note("asset reporting", err)
	}
	if c.FindingsByStatus, err = st.FindingStatusCounts(ctx); err != nil {
		note("finding counts", err)
	}
	b.Counts = c

	if settings, err := st.AllSettings(ctx); err != nil {
		note("settings", err)
	} else {
		for _, s := range settings {
			v := Redacted
			if safeSettings[s.Key] {
				var raw any
				if json.Unmarshal(s.Value, &raw) == nil {
					if str, ok := raw.(string); ok && safeValue.MatchString(str) {
						v = str
					}
				}
			}
			b.Settings = append(b.Settings, WorkspaceSetting{WorkspaceID: s.WorkspaceID, Key: red.Text(s.Key), Value: v})
		}
	}
	return b
}

// JSON renders the bundle as the file support receives, after a last pass
// that replaces any configured secret still in it (Redactor.Final).
func (b *Bundle) JSON(environ []string, cfg intel.Config) ([]byte, error) {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(NewRedactor(environ, cfg).Final(raw), '\n'), nil
}

// Redactor scrubs free text for the bundle: errors and titles can name
// hosts, URLs (with credentials), addresses, paths and tokens, and can
// quote any configured secret.
type Redactor struct {
	// secrets are the values of every variable not on the allow-list,
	// replaced wherever they appear.
	secrets []string
	// public are the hosts of the default feed sources, kept so errors
	// about them stay readable.
	public map[string]bool
}

func NewRedactor(environ []string, cfg intel.Config) *Redactor {
	r := &Redactor{public: map[string]bool{"github.com": true, "stackurity.dev": true, "wordpress.org": true}}
	def := intel.DefaultConfig()
	for _, name := range publicFeeds {
		for _, u := range def.Sources(name) {
			if p, err := url.Parse(u); err == nil && p.Hostname() != "" {
				r.public[strings.ToLower(p.Hostname())] = true
			}
		}
	}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if (strings.HasPrefix(k, "STACKURITY_") || safeEnv[k]) && !safeEnv[k] && len(v) >= 6 {
			r.secrets = append(r.secrets, v)
			// A database URL's password, on its own.
			if u, err := url.Parse(v); err == nil && u.User != nil {
				if pw, ok := u.User.Password(); ok && len(pw) >= 4 {
					r.secrets = append(r.secrets, pw)
				}
				if n := u.User.Username(); len(n) >= 4 {
					r.secrets = append(r.secrets, n)
				}
			}
		}
	}
	// Longest first, so a value containing another is replaced whole.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	return r
}

// jobKinds are job names that look like host names.
var jobKinds = map[string]bool{"feed.sync": true, "image.scan": true, "integration.run": true, "second.check": true}

// publicFeeds name every feed source, for the public hosts.
var publicFeeds = []string{"osv:npm", intel.FeedKEV, intel.FeedEPSS, intel.FeedEndOfLife, intel.FeedNpm, intel.FeedPackagist,
	intel.FeedPyPI, intel.FeedGo, intel.FeedCrates, intel.FeedRubyGems, intel.FeedNuGet, intel.FeedMaven, intel.FeedPub, intel.FeedHex,
	intel.FeedAmazonLinux, intel.FeedOracleLinux, intel.FeedMSRC, intel.FeedWindowsPrograms, intel.FeedVendorBuilds, intel.FeedWordPressOrg}

var (
	reURL      = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>()\[\]{},]+`)
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reIPv4     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	reIPv6     = regexp.MustCompile(`\[?\b(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}\b\]?|\[?(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\]?`)
	reHost     = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b`)
	rePath     = regexp.MustCompile(`(?:^|[\s"'=(:])(/[^\s/"'<>(),;][^\s"'<>(),;]*)`)
	reAssign   = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie)\b(\s*[=:]\s*)((?:bearer|basic)\s+\S+|"[^"]*"|'[^']*'|\S+)`)
	reBearer   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+\S+`)
	reTokenish = regexp.MustCompile(`\b[A-Za-z0-9_\-+/]{24,}={0,2}`)
)

// Final replaces any configured secret left in the finished bundle (as it
// appears in JSON), a last guard in case a section quoted one.
func (r *Redactor) Final(raw []byte) []byte {
	s := string(raw)
	for _, v := range r.secrets {
		q, _ := json.Marshal(v)
		s = strings.ReplaceAll(s, strings.Trim(string(q), `"`), Redacted)
	}
	return []byte(s)
}

// Text returns s with secrets, URLs, email addresses, IP addresses, host
// names (other than the default feed sources'), absolute paths and
// token-like strings replaced.
func (r *Redactor) Text(s string) string {
	if s == "" {
		return s
	}
	for _, v := range r.secrets {
		s = strings.ReplaceAll(s, v, Redacted)
	}
	s = reURL.ReplaceAllStringFunc(s, func(m string) string {
		trimmed := strings.TrimRight(m, ".:;")
		rest := m[len(trimmed):]
		u, err := url.Parse(trimmed)
		if err == nil && u.User == nil && r.public[strings.ToLower(u.Hostname())] {
			return u.Scheme + "://" + u.Host + rest
		}
		return "<url>" + rest
	})
	s = reEmail.ReplaceAllString(s, "<email>")
	s = reAssign.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = reBearer.ReplaceAllString(s, "${1} "+Redacted)
	s = reIPv4.ReplaceAllString(s, "<ip>")
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Trim(m, "[]:") == "" {
			return m // "::" alone, as in Go's scope operator in a message
		}
		return "<ip>"
	})
	s = reHost.ReplaceAllStringFunc(s, func(m string) string {
		if r.public[strings.ToLower(m)] || jobKinds[m] {
			return m
		}
		return "<host>"
	})
	s = rePath.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexByte(m, '/')
		return m[:i] + "<path>"
	})
	s = reTokenish.ReplaceAllStringFunc(s, func(m string) string {
		// Long words of letters only are words, not tokens.
		if strings.IndexFunc(m, func(c rune) bool { return c >= '0' && c <= '9' }) < 0 {
			return m
		}
		return "<token>"
	})
	return s
}
