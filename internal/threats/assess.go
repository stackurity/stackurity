package threats

import (
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

// FeedStatusKey is the instance value (store.InstanceValue) that holds
// the last feed fetch's FeedStatus, written by internal/threatnotice and
// read by Platform health.
const FeedStatusKey = "threat_feed_status"

// FeedStatus is the outcome of the last fetch of the threat feed.
type FeedStatus struct {
	CheckedAt time.Time `json:"checked_at"`
	// Since is the first fetch; LastSuccess the last feed that was used;
	// ExpiresAt that feed's expiry.
	Since       *time.Time `json:"since,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// Problem is "" after a good fetch or a network failure (kept quiet,
	// like the release check; a long outage shows as stale), else
	// bad_signature, invalid, newer_schema, replay or expired: the feed was
	// refused and the last good one is kept.
	Problem string `json:"problem,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Serial  int64  `json:"serial,omitempty"`
}

// Verdicts of a threat for one organisation.
const (
	// Found: the threat's checks found it on the organisation's assets.
	Found = "found"
	// Covered: the connected assets are checked and nothing was found.
	Covered = "covered"
	// NeedsConnection: Stackurity can check for it, but a connection the
	// check needs is missing.
	NeedsConnection = "needs_connection"
	// Upgrade: this self-hosted server is older than the release with the
	// check. Stackurity Cloud always runs the latest release, so it never
	// gives this verdict.
	Upgrade = "upgrade"
)

// Verdicts lists them, worst first.
var Verdicts = []string{Found, Upgrade, NeedsConnection, Covered}

// Evidence is what an organisation's open findings say about a threat.
type Evidence struct {
	// Findings are open findings of the threat's rules and vulnerabilities,
	// on Assets distinct assets.
	Findings int `json:"findings"`
	Assets   int `json:"assets"`
	// Signals are open findings of the threat's signal rules (something
	// only named like it): shown, never a verdict of their own.
	Signals int `json:"signals"`
}

// Assessment is the verdict and what it rests on.
type Assessment struct {
	Verdict  string   `json:"verdict"`
	Evidence Evidence `json:"evidence"`
	// Connected counts, per connection the threat needs, the assets
	// connected that way (0 for a missing one).
	Connected map[string]int `json:"connected"`
	// Outdated counts, per connection, assets connected that way whose
	// collector is older than the check (min_version): they are not
	// checked yet, so they do not count as connected.
	Outdated map[string]int `json:"outdated,omitempty"`
	// Missing are the needs with nothing connected: for needs_connection
	// at least one is required; for covered they would widen the check.
	Missing []Need `json:"missing"`
}

// Assess gives the verdict for one organisation. conns counts the
// organisation's assets per connection whose latest complete collection
// came from a collector with the check (CollectorChecked); outdated counts
// those whose collector is older, which were not checked; running is the
// server's comparable release ("" for a development build); cloud is true
// on Stackurity Cloud. ok is false when nothing should be said yet:
// Stackurity Cloud has not deployed the release with the check.
//
// A required connection with any outdated asset is missing: one updated
// agent among ten old ones must not say "nothing to do". The notice then
// says how many to update; once all are, the verdict becomes covered.
func Assess(t Threat, ev Evidence, conns, outdated map[string]int, running string, cloud bool) (a Assessment, ok bool) {
	a = Assessment{Evidence: ev, Connected: map[string]int{}, Outdated: map[string]int{}, Missing: []Need{}}
	anyConnected, requiredMissing := false, false
	for _, n := range t.Needs {
		c, o := conns[n.Connection], outdated[n.Connection]
		a.Connected[n.Connection] = c
		if o > 0 {
			a.Outdated[n.Connection] = o
		}
		anyConnected = anyConnected || c > 0
		if c > 0 && (o == 0 || !n.Required) {
			continue
		}
		a.Missing = append(a.Missing, n)
		requiredMissing = requiredMissing || n.Required
	}
	switch {
	case ev.Findings > 0:
		// Found wins, also on an older server: a vulnerability found by the
		// normal checks needs no new release.
		a.Verdict = Found
	case !t.HasCheck(running):
		if cloud {
			return a, false
		}
		a.Verdict = Upgrade
	case requiredMissing || !anyConnected:
		a.Verdict = NeedsConnection
	default:
		a.Verdict = Covered
	}
	return a, true
}

// Worsened reports whether moving from verdict old to now is news an
// organisation is told again: only a threat that is now found where it was
// not before. Every other change updates the notice quietly.
func Worsened(old, now string) bool {
	return now == Found && old != Found
}

// coreCollectors are the collectors released with Stackurity itself (the
// agents and the server's own scanners): their version is Stackurity's, so
// it can be compared with min_version. The scan CLI, plugins and uploads
// carry versions of their own.
var coreCollectors = map[string]bool{
	"linux-agent": true, "linux-software": true, "linux-apps": true, "linux-docker": true,
	"macos-agent": true, "macos-software": true, "macos-apps": true, "windows-agent": true,
	"lockfile-scanner": true, "image-scanner": true, "container-registry": true,
}

// CollectorChecked reports whether a collection by collector id, of
// recorded version v, ran t's check: a core collector whose version is a
// release ("0.20.17", "v0.20.17-ee", a describe suffix) of min_version or
// later. Any other collector, and a version that is not a release (dev,
// demo, a commit), counts as not checked, unless serverDev: a development
// server compares nothing.
func (t Threat) CollectorChecked(id, v string, serverDev bool) bool {
	if serverDev {
		return true
	}
	r := ReleaseVersion(v)
	if !coreCollectors[id] || r == "" {
		return false
	}
	c, err := version.CompareSemver(r, t.MinVersion)
	return err == nil && c >= 0
}

var (
	releaseRE  = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	describeRE = regexp.MustCompile(`-\d+-g[0-9a-f]+$`)
)

// ReleaseVersion turns a build version into a comparable release, or ""
// when it is not one (dev, a commit). It drops "-ee", "-dirty" and git
// describe's "-<n>-g<hash>", like internal/updates.Running.
func ReleaseVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "-ee")
	v = strings.TrimSuffix(v, "-dirty")
	v = describeRE.ReplaceAllString(v, "")
	if !releaseRE.MatchString(v) {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}
