// Package threats is the threat catalogue: named attacks, attacker tools,
// actively exploited vulnerabilities and campaigns Stackurity has checks
// for, what each check reads and the first release that has it.
//
// The catalogue ships in the binary (catalogue.json), so an offline server
// knows the threats of its release. Servers also fetch a signed copy from
// stackurity.ai (internal/threatnotice) and merge it with the embedded one
// (Merge): per threat, the higher revision wins. The feed is verified with
// the public keys embedded here (keys/*.pub) before anything in it is used.
//
// This package is pure: it reads no database and makes no request, so the
// MCP server, the API and the notifier share it.
package threats

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

// Schema is the catalogue format this build reads. A feed with a higher
// schema is ignored (the server keeps the catalogue it has) and reported as
// needing an upgrade.
const Schema = 1

// Kinds of threat.
const (
	KindAttackTool    = "attack_tool"    // an attacker or penetration-testing tool used against systems
	KindExploitedVuln = "exploited_vuln" // a vulnerability exploited in the wild (KEV-style)
	KindDisclosedVuln = "disclosed_vuln" // a critical vulnerability with a fix out, not known to be exploited yet
	KindCampaign      = "campaign"       // a named campaign
	KindPractice      = "practice"       // an unsafe practice attackers rely on
)

// Connections a threat's checks may rely on.
const (
	ConnHostAgent    = "host_agent"    // the Stackurity agent on servers
	ConnDocker       = "docker"        // container images (the agent's --docker, or a registry)
	ConnRepository   = "repository"    // connected repositories
	ConnCloudAccount = "cloud_account" // a connected cloud account
	ConnKubernetes   = "kubernetes"    // a reporting Kubernetes cluster
)

// Connections lists every connection, in the order they are shown.
var Connections = []string{ConnHostAgent, ConnDocker, ConnRepository, ConnCloudAccount, ConnKubernetes}

// ConnectionLabel names a connection for people ("a Stackurity agent on
// your servers").
func ConnectionLabel(c string) string {
	switch c {
	case ConnHostAgent:
		return "the Stackurity agent on your servers"
	case ConnDocker:
		return "container images (the agent's Docker access or a connected registry)"
	case ConnRepository:
		return "your repositories"
	case ConnCloudAccount:
		return "a connected cloud account"
	case ConnKubernetes:
		return "a Kubernetes cluster reporting to Stackurity"
	}
	return c
}

// Catalogue is the whole list, as embedded and as served at
// https://stackurity.ai/threats/feed.signed.json (inside a signed Envelope).
type Catalogue struct {
	Schema int `json:"schema"`
	// Serial grows with every published catalogue. A server refuses a feed
	// with a lower serial than one it already accepted (a replay).
	Serial      int64     `json:"serial"`
	GeneratedAt time.Time `json:"generated_at"`
	// ExpiresAt, in a published feed, is when servers stop accepting it
	// (tools/threatfeed sign --valid-for sets both times). A feed that is
	// never re-signed is refused after it, so an attacker who blocks or
	// replays the feed cannot hide new threats for longer. The embedded
	// catalogue has none.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Threats   []Threat   `json:"threats"`
}

// Threat is one named threat.
type Threat struct {
	ID string `json:"id"`
	// Revision grows when the entry changes; when the embedded catalogue
	// and the feed both have a threat, the higher revision is used.
	Revision int    `json:"revision"`
	Name     string `json:"name"`
	// ShortName is what a threat notice's title and banner call it when
	// Name carries an explanation ("nginx2root" for "nginx2root (nginx
	// memory-corruption bugs ...)"). Empty means Name.
	ShortName   string   `json:"short_name,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"` // critical, high, medium or low
	Summary     string   `json:"summary"`
	FirstSeen   string   `json:"first_seen"`   // YYYY-MM-DD: first reported in the wild
	PublishedAt string   `json:"published_at"` // YYYY-MM-DD: when Stackurity added it
	Sources     []string `json:"sources"`
	Detects     Detects  `json:"detects"`
	Needs       []Need   `json:"needs"`
	// MinVersion is the first Stackurity release with the check. An older
	// self-hosted server tells its organisations to upgrade.
	MinVersion string `json:"min_version"`
	// Source is where this entry came from: embedded or feed. Set when
	// loaded, never read from JSON.
	Source string `json:"source,omitempty"`
}

// Detects is what finds the threat: config-finding rules (risky settings)
// and vulnerability ids (CVE, GHSA). Vulnerabilities reuse the normal
// findings, so a known-exploited CVE needs no new check.
type Detects struct {
	ConfigRules []string `json:"config_rules,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	// SignalRules are weaker config rules (something only named like the
	// tool): counted and shown as signals to look at, never "found" on
	// their own.
	SignalRules []string `json:"signal_rules,omitempty"`
}

// Need is a connection the threat's checks read.
type Need struct {
	Connection string `json:"connection"`
	// Required: without it the threat is not checked at all. The others
	// widen the check.
	Required bool `json:"required,omitempty"`
	// Checks says what the check looks for there.
	Checks string `json:"checks"`
	// Help is the Help page that sets the connection up: a dashboard path
	// (/help/...) or an https://stackurity.ai page.
	Help string `json:"help"`
}

// Limits on what a catalogue may hold. The feed is signed, but its content
// is still checked: it is shown in the dashboard and in emails.
const (
	maxThreats = 500
	maxText    = 4000
	maxShort   = 200
	maxList    = 50
)

var (
	idRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	ruleRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	vulnRE    = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._:-]{1,64}$`)
	dateRE    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	helpRE    = regexp.MustCompile(`^/help/[a-z0-9-]+(#[a-z0-9-]+)?$`)
	versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// ErrNewerSchema means the catalogue is in a format this build does not
// read yet: the server must be upgraded to use it.
var ErrNewerSchema = errors.New("the threat catalogue uses a newer format than this server reads")

// Parse reads and checks a catalogue. Unknown fields are refused, so a
// typo in the published feed fails here rather than being ignored.
func Parse(b []byte) (*Catalogue, error) {
	var head struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("threat catalogue: %w", err)
	}
	if head.Schema > Schema {
		return nil, fmt.Errorf("%w (schema %d, this server reads %d)", ErrNewerSchema, head.Schema, Schema)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Catalogue
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("threat catalogue: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks every entry.
func (c *Catalogue) Validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("threat catalogue: schema must be %d", Schema)
	}
	if c.Serial < 1 {
		return errors.New("threat catalogue: serial must be 1 or more")
	}
	if c.ExpiresAt != nil && !c.ExpiresAt.After(c.GeneratedAt) {
		return errors.New("threat catalogue: expires_at must be after generated_at")
	}
	if len(c.Threats) > maxThreats {
		return fmt.Errorf("threat catalogue: more than %d threats", maxThreats)
	}
	seen := map[string]bool{}
	for i := range c.Threats {
		t := &c.Threats[i]
		if err := t.validate(); err != nil {
			return fmt.Errorf("threat catalogue: %q: %w", t.ID, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("threat catalogue: %q is listed twice", t.ID)
		}
		seen[t.ID] = true
	}
	return nil
}

// Short is the name a notice's title uses: ShortName, else Name.
func (t Threat) Short() string {
	if t.ShortName != "" {
		return t.ShortName
	}
	return t.Name
}

func (t *Threat) validate() error {
	switch {
	case !idRE.MatchString(t.ID):
		return errors.New("id must be lower-case letters, digits and dashes")
	case t.Revision < 1:
		return errors.New("revision must be 1 or more")
	case t.Name == "" || len(t.Name) > maxShort:
		return errors.New("name is empty or too long")
	case len(t.ShortName) > maxShort || t.ShortName != strings.TrimSpace(t.ShortName):
		return errors.New("short_name is too long or has spaces around it")
	case !slices.Contains([]string{KindAttackTool, KindExploitedVuln, KindDisclosedVuln, KindCampaign, KindPractice}, t.Kind):
		return fmt.Errorf("unknown kind %q", t.Kind)
	case !slices.Contains([]string{"critical", "high", "medium", "low"}, t.Severity):
		return fmt.Errorf("unknown severity %q", t.Severity)
	case t.Summary == "" || len(t.Summary) > maxText:
		return errors.New("summary is empty or too long")
	case !dateRE.MatchString(t.FirstSeen) || !dateRE.MatchString(t.PublishedAt):
		return errors.New("first_seen and published_at must be YYYY-MM-DD")
	case !versionRE.MatchString(t.MinVersion):
		return errors.New("min_version must be X.Y.Z")
	case len(t.Aliases) > maxList || len(t.Sources) > maxList || len(t.Needs) > len(Connections):
		return errors.New("too many aliases, sources or needs")
	case len(t.Detects.ConfigRules)+len(t.Detects.CVEs) == 0:
		return errors.New("detects names no rule and no vulnerability")
	case len(t.Detects.ConfigRules) > maxList || len(t.Detects.CVEs) > maxList || len(t.Detects.SignalRules) > maxList:
		return errors.New("detects lists too many rules or vulnerabilities")
	case len(t.Needs) == 0:
		return errors.New("needs is empty: every check reads some connection")
	}
	for _, d := range []string{t.FirstSeen, t.PublishedAt} {
		if _, err := time.Parse(time.DateOnly, d); err != nil {
			return fmt.Errorf("date %q: %w", d, err)
		}
	}
	for i, a := range t.Aliases {
		a = normalName(a)
		if a == "" || len(a) > maxShort {
			return errors.New("an alias is empty or too long")
		}
		t.Aliases[i] = a
	}
	for _, s := range t.Sources {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(s) > 2048 {
			return fmt.Errorf("source %q must be an https URL", s)
		}
	}
	for _, r := range append(append([]string(nil), t.Detects.ConfigRules...), t.Detects.SignalRules...) {
		if !ruleRE.MatchString(r) {
			return fmt.Errorf("config rule %q is not a rule id", r)
		}
	}
	for _, v := range t.Detects.CVEs {
		if !vulnRE.MatchString(v) {
			return fmt.Errorf("%q is not a vulnerability id (CVE-..., GHSA-...)", v)
		}
	}
	seen := map[string]bool{}
	for _, n := range t.Needs {
		if !slices.Contains(Connections, n.Connection) {
			return fmt.Errorf("unknown connection %q", n.Connection)
		}
		if seen[n.Connection] {
			return fmt.Errorf("connection %q is listed twice", n.Connection)
		}
		seen[n.Connection] = true
		if n.Checks == "" || len(n.Checks) > maxText {
			return fmt.Errorf("need %q: checks is empty or too long", n.Connection)
		}
		if !validHelp(n.Help) {
			return fmt.Errorf("need %q: help must be a /help/ page or an https://stackurity.ai page", n.Connection)
		}
	}
	return nil
}

// validHelp: a dashboard Help path, or a page on stackurity.ai. Nothing
// else is linked from a notice, whoever signed the feed.
func validHelp(h string) bool {
	if helpRE.MatchString(h) {
		return true
	}
	u, err := url.Parse(h)
	return err == nil && u.Scheme == "https" && u.Host == "stackurity.ai" && u.User == nil && len(h) <= 512
}

func normalName(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

//go:embed catalogue.json
var embeddedJSON []byte

var embedded = func() *Catalogue {
	c, err := Parse(embeddedJSON)
	if err != nil {
		panic(err) // TestEmbedded catches it first
	}
	for i := range c.Threats {
		c.Threats[i].Source = "embedded"
	}
	return c
}()

// Embedded is the catalogue this build shipped with. Callers must not
// change it.
func Embedded() *Catalogue { return embedded }

// Merge combines the embedded catalogue with a verified feed: every threat
// of either, and for a threat in both, the entry with the higher revision
// (the embedded one on a tie). feed may be nil.
func Merge(base, feed *Catalogue) *Catalogue {
	out := &Catalogue{Schema: Schema, Serial: base.Serial, GeneratedAt: base.GeneratedAt}
	byID := map[string]Threat{}
	for _, t := range base.Threats {
		byID[t.ID] = t
	}
	if feed != nil {
		out.Serial = max(out.Serial, feed.Serial)
		if feed.GeneratedAt.After(out.GeneratedAt) {
			out.GeneratedAt = feed.GeneratedAt
		}
		for _, t := range feed.Threats {
			if cur, ok := byID[t.ID]; ok && cur.Revision >= t.Revision {
				continue
			}
			t.Source = "feed"
			byID[t.ID] = t
		}
	}
	for _, t := range byID {
		out.Threats = append(out.Threats, t)
	}
	// Newest first, then by id: the order lists and notices are shown in.
	sort.Slice(out.Threats, func(i, j int) bool {
		a, b := out.Threats[i], out.Threats[j]
		if a.PublishedAt != b.PublishedAt {
			return a.PublishedAt > b.PublishedAt
		}
		return a.ID < b.ID
	})
	return out
}

// Find matches a name, id or alias, ignoring case and spacing.
func (c *Catalogue) Find(name string) (Threat, bool) {
	n := normalName(name)
	for _, t := range c.Threats {
		if n == t.ID || n == normalName(t.Name) || slices.Contains(t.Aliases, n) {
			return t, true
		}
	}
	return Threat{}, false
}

// Get returns the threat with this id.
func (c *Catalogue) Get(id string) (Threat, bool) {
	for _, t := range c.Threats {
		if t.ID == id {
			return t, true
		}
	}
	return Threat{}, false
}

// Published is the day the threat was added, as a time (UTC midnight).
func (t Threat) Published() time.Time {
	d, _ := time.Parse(time.DateOnly, t.PublishedAt)
	return d
}

// HasCheck reports whether a server running version running has the
// threat's check. running is a comparable release ("0.20.17"); "" (a
// development build) counts as having every check.
func (t Threat) HasCheck(running string) bool {
	if running == "" {
		return true
	}
	c, err := version.CompareSemver(running, t.MinVersion)
	return err != nil || c >= 0
}
