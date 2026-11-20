package threats

import "time"

// FeedStatusKey is the instance value (store.InstanceValue) that holds
// the last feed fetch's FeedStatus, written by internal/threatnotice and
// read by Platform health.
const FeedStatusKey = "threat_feed_status"

// FeedStatus is the outcome of the last fetch of the threat feed.
type FeedStatus struct {
	CheckedAt   time.Time  `json:"checked_at"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	// Problem is "" after a good fetch or a network failure (kept quiet,
	// like the release check), else bad_signature, invalid, newer_schema
	// or replay: the feed was refused and the last good one is kept.
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
}

// Assessment is the verdict and what it rests on.
type Assessment struct {
	Verdict  string   `json:"verdict"`
	Evidence Evidence `json:"evidence"`
	// Connected counts, per connection the threat needs, the assets
	// connected that way (0 for a missing one).
	Connected map[string]int `json:"connected"`
	// Missing are the needs with nothing connected: for needs_connection
	// at least one is required; for covered they would widen the check.
	Missing []Need `json:"missing"`
}

// Assess gives the verdict for one organisation. conns counts the
// organisation's assets per connection; running is the server's comparable
// release ("" for a development build); cloud is true on Stackurity Cloud.
// ok is false when nothing should be said yet: Stackurity Cloud has not
// deployed the release with the check.
func Assess(t Threat, ev Evidence, conns map[string]int, running string, cloud bool) (a Assessment, ok bool) {
	a = Assessment{Evidence: ev, Connected: map[string]int{}, Missing: []Need{}}
	anyConnected, requiredMissing := false, false
	for _, n := range t.Needs {
		c := conns[n.Connection]
		a.Connected[n.Connection] = c
		if c > 0 {
			anyConnected = true
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
