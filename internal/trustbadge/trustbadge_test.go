package trustbadge

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time { t := now.Add(-d); return &t }

// healthy is a badge that meets every condition: one host that reported an
// hour ago and was processed, npm components evaluated against the npm
// feed's latest refresh, and Homebrew runtimes nothing covers.
func healthy() Inputs {
	return Inputs{
		BadgeID: 1, Enabled: true, ScopeKind: "assets", ScopeIDs: []int64{10},
		Assets: []Asset{{ID: 10, Kind: "host", LastReport: at(time.Hour), LatestComplete: true, ProcessedAt: at(50 * time.Minute)}},
		Sources: map[string]Source{
			"osv:npm":    {Exists: true, Enabled: true, Cursor: "c2", LastSuccess: at(2 * time.Hour), StaleAfter: 6 * time.Hour},
			"osv:Debian": {Exists: true, Enabled: true, Cursor: "d9", LastSuccess: at(30 * time.Minute), StaleAfter: 6 * time.Hour},
		},
		Pairs: []Pair{
			{Class: ClassEvaluated, Source: "osv:npm", SourceLastSuccess: at(2 * time.Hour), SourceCursor: "c2", OldestEvaluated: at(90 * time.Minute), Count: 40},
			{Class: ClassUnsupported, Kind: "runtimes installed outside a package manager", OldestEvaluated: at(90 * time.Minute), Count: 2},
		},
	}
}

func TestActiveWhenEveryConditionHolds(t *testing.T) {
	d := Evaluate(healthy(), now)
	if d.Result != Active || d.Reason != ReasonActive || len(d.Failed) != 0 {
		t.Fatalf("decision = %+v, want active", d)
	}
	if d.RuleVersion != RuleVersion {
		t.Errorf("rule version = %q, want %q", d.RuleVersion, RuleVersion)
	}
	if !d.OldestEvaluated.Equal(*at(90 * time.Minute)) {
		t.Errorf("oldest evaluated = %v", d.OldestEvaluated)
	}
	if d.States[StateEvaluated] != 40 || d.States[StateUnsupported] != 2 {
		t.Errorf("states = %v", d.States)
	}
}

func TestNotActiveReasons(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Inputs)
		want   string
		state  string // a state that must be counted, if any
	}{
		{"badge turned off", func(in *Inputs) { in.Enabled = false }, ReasonDisabled, ""},
		{"empty scope", func(in *Inputs) { in.Assets = nil; in.Pairs = nil }, ReasonEmptyScope, ""},
		{"never reported", func(in *Inputs) { in.Assets[0].LastReport = nil }, ReasonNotReporting, ""},
		{"silent for over 7 days", func(in *Inputs) { in.Assets[0].LastReport = at(7*24*time.Hour + time.Minute) }, ReasonNotReporting, ""},
		{"incomplete collection", func(in *Inputs) { in.Assets[0].LatestComplete = false }, ReasonCollectionErrors, ""},
		{"failed collector scope", func(in *Inputs) { in.Assets[0].FailedScopes = 1 }, ReasonCollectionErrors, ""},
		{"inventory not processed in time", func(in *Inputs) {
			in.Assets[0].LastReport = at(2 * time.Hour)
			in.Assets[0].ProcessedAt = at(3 * time.Hour)
		}, ReasonNotProcessed, ""},
		{"inventory never processed", func(in *Inputs) {
			in.Assets[0].LastReport = at(2 * time.Hour)
			in.Assets[0].ProcessedAt = nil
		}, ReasonNotProcessed, ""},
		{"source past its freshness window", func(in *Inputs) {
			in.Sources["osv:npm"] = Source{Exists: true, Enabled: true, LastSuccess: at(7 * time.Hour), StaleAfter: 6 * time.Hour}
			in.Pairs[0].SourceLastSuccess = at(7 * time.Hour)
		}, ReasonSourceStale, StateStale},
		{"source switched off", func(in *Inputs) {
			s := in.Sources["osv:npm"]
			s.Enabled = false
			in.Sources["osv:npm"] = s
		}, ReasonSourceStale, StateStale},
		{"source missing", func(in *Inputs) { delete(in.Sources, "osv:npm") }, ReasonSourceStale, StateStale},
		{"source never synced", func(in *Inputs) {
			in.Sources["osv:npm"] = Source{Exists: true, Enabled: true, StaleAfter: 6 * time.Hour}
		}, ReasonSourceStale, StateStale},
		{"evaluation failed", func(in *Inputs) {
			in.Pairs = append(in.Pairs, Pair{Class: ClassFailed, Count: 1})
		}, ReasonEvaluationFailed, StateFailed},
		{"never evaluated past the grace", func(in *Inputs) {
			in.Pairs = append(in.Pairs, Pair{Class: ClassAwaiting, Since: at(ProcessingGrace + time.Minute), Count: 3})
		}, ReasonEvaluationFailed, StateFailed},
		{"waiting for a source past the grace", func(in *Inputs) {
			in.Pairs = append(in.Pairs, Pair{Class: ClassWaiting, Since: at(SourceGrace + time.Minute), Count: 3})
		}, ReasonSourceStale, StateStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := healthy()
			c.change(&in)
			d := Evaluate(in, now)
			if d.Result != NotActive || d.Reason != c.want {
				t.Fatalf("decision = %s/%s (failed %v), want not_active/%s", d.Result, d.Reason, d.Failed, c.want)
			}
			if c.state != "" && d.States[c.state] == 0 {
				t.Errorf("states = %v, want some %s", d.States, c.state)
			}
		})
	}
}

// Pending: the source refreshed and the re-check has not run yet. The badge
// stays active while the refresh the components were evaluated against is
// within the source's freshness window, then the overdue re-check makes it
// not active, even though the source itself keeps refreshing. Without the
// grace, an hourly refresh would make every badge flicker; with a grace
// that restarted at each refresh, a badge whose re-checks never run would
// stay active for ever.
func TestPendingWithinTheSourceWindowThenOverdue(t *testing.T) {
	in := healthy()
	in.Sources["osv:npm"] = Source{Exists: true, Enabled: true, LastSuccess: at(20 * time.Minute), StaleAfter: 6 * time.Hour}
	in.Pairs[0].SourceLastSuccess = at(80 * time.Minute) // the refresh before
	d := Evaluate(in, now)
	if d.Result != Active || d.States[StatePending] != 40 {
		t.Fatalf("just after a refresh: %+v, want active with 40 pending", d)
	}
	// Hours later the source has refreshed every hour, and the components
	// were still last evaluated against the refresh 80 minutes before now.
	later := now.Add(5 * time.Hour)
	in.Sources["osv:npm"] = Source{Exists: true, Enabled: true, LastSuccess: &later, StaleAfter: 6 * time.Hour}
	d = Evaluate(in, later.Add(10*time.Minute))
	if d.Result != NotActive || d.Reason != ReasonRecheckOverdue || d.States[StateFailed] != 40 {
		t.Fatalf("re-check overdue: %+v", d)
	}
	if slices.Contains(d.Failed, ReasonSourceStale) {
		t.Fatalf("the source is fresh; only the re-check is overdue: %v", d.Failed)
	}
}

// A refresh of one source never counts for another: Debian refreshing
// does not make npm components current, and npm refreshing makes only npm
// components pending.
func TestOneSourceRefreshNeverCountsForAnother(t *testing.T) {
	in := healthy()
	in.Pairs = append(in.Pairs, Pair{Class: ClassEvaluated, Source: "osv:Debian", SourceLastSuccess: at(5 * time.Hour),
		OldestEvaluated: at(5 * time.Hour), Count: 7})
	d := Evaluate(in, now)
	if d.States[StatePending] != 7 || d.States[StateEvaluated] != 40 {
		t.Fatalf("states = %v, want the 7 Debian rows pending and the npm rows evaluated", d.States)
	}
}

// A component checked against several sources is evaluated only if it was
// evaluated after every one of them last refreshed: one pair per source.
func TestMultiSourceComponentNeedsEverySource(t *testing.T) {
	in := healthy()
	in.Sources["osv:Debian"] = Source{Exists: true, Enabled: true, LastSuccess: at(time.Hour), StaleAfter: 6 * time.Hour}
	in.Sources["ghsa"] = Source{Exists: true, Enabled: true, LastSuccess: at(time.Hour), StaleAfter: 6 * time.Hour}
	in.Pairs = []Pair{
		{Class: ClassEvaluated, Source: "osv:Debian", SourceLastSuccess: at(time.Hour), OldestEvaluated: at(50 * time.Minute), Count: 1},
		// Evaluated against ghsa's refresh from 8 hours ago only.
		{Class: ClassEvaluated, Source: "ghsa", SourceLastSuccess: at(8 * time.Hour), OldestEvaluated: at(50 * time.Minute), Count: 1},
	}
	d := Evaluate(in, now)
	if d.Result != NotActive || d.Reason != ReasonRecheckOverdue {
		t.Fatalf("decision = %+v: the ghsa pair was not re-checked", d)
	}
	in.Pairs[1].SourceLastSuccess = at(time.Hour)
	if d := Evaluate(in, now); d.Result != Active {
		t.Fatalf("decision = %+v: both sources current", d)
	}
}

// Unsupported is never failed, and failed is never unsupported.
func TestUnsupportedAndFailedStayApart(t *testing.T) {
	in := healthy()
	in.Pairs = append(in.Pairs,
		Pair{Class: ClassNoAdvisories, Kind: "deb packages for releases with no published advisories", Count: 4},
		Pair{Class: ClassUnsupported, Kind: "WordPress plugins and themes", Count: 9})
	d := Evaluate(in, now)
	if d.Result != Active || d.States[StateFailed] != 0 || d.States[StateUnsupported] != 15 {
		t.Fatalf("decision = %+v: coverage limits keep the badge active", d)
	}
	want := []string{"WordPress plugins and themes", "deb packages for releases with no published advisories", "runtimes installed outside a package manager"}
	if !reflect.DeepEqual(d.UnsupportedKinds, want) {
		t.Errorf("kinds = %q, want %q", d.UnsupportedKinds, want)
	}
	in.Pairs = append(in.Pairs, Pair{Class: ClassFailed, Count: 1})
	d = Evaluate(in, now)
	if d.States[StateUnsupported] != 15 || d.States[StateFailed] != 1 || d.Reason != ReasonEvaluationFailed {
		t.Fatalf("decision = %+v", d)
	}
}

func TestPendingWithinGraces(t *testing.T) {
	in := healthy()
	in.Assets[0].LastReport = at(10 * time.Minute)
	in.Assets[0].ProcessedAt = at(time.Hour)
	in.Pairs = append(in.Pairs,
		Pair{Class: ClassAwaiting, Since: at(10 * time.Minute), Count: 5},
		Pair{Class: ClassWaiting, Since: at(time.Hour), Count: 2})
	d := Evaluate(in, now)
	if d.Result != Active || d.PendingAssets != 1 || d.States[StatePending] != 7 {
		t.Fatalf("decision = %+v", d)
	}
}

// Rows evaluated before the source refresh was recorded compare their
// evaluation time with the source's last refresh.
func TestRowsFromBeforeTheRefreshWasRecorded(t *testing.T) {
	in := healthy()
	in.Pairs[0].SourceLastSuccess = nil
	in.Pairs[0].OldestEvaluated = at(time.Hour) // after the 2h-old refresh
	if d := Evaluate(in, now); d.States[StateEvaluated] != 40 {
		t.Fatalf("states = %v", d.States)
	}
	in.Pairs[0].OldestEvaluated = at(3 * time.Hour)
	if d := Evaluate(in, now); d.States[StatePending] != 40 {
		t.Fatalf("states = %v", d.States)
	}
}

func TestUnknownClassIsNeverFine(t *testing.T) {
	in := healthy()
	in.Pairs = append(in.Pairs, Pair{Class: "something new", Count: 1})
	if d := Evaluate(in, now); d.Result != NotActive {
		t.Fatalf("decision = %+v", d)
	}
}

// A decision is rebuilt from its stored evidence: the same inputs at the
// same time give the same decision after a JSON round trip.
func TestDecisionRebuildsFromEvidence(t *testing.T) {
	limited := healthy()
	limited.Assets[0].LatestComplete, limited.Assets[0].IncompleteExplained = false, true
	limited.Assets[0].LimitKinds = []string{"Flutter web engines"}
	for _, in := range []Inputs{healthy(), func() Inputs { i := healthy(); i.Assets[0].FailedScopes = 2; return i }(), limited} {
		d := Evaluate(in, now)
		body, err := json.Marshal(Evidence{Inputs: in, Decision: d})
		if err != nil {
			t.Fatal(err)
		}
		var ev Evidence
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Fatal(err)
		}
		if again := Evaluate(ev.Inputs, now); !reflect.DeepEqual(again, ev.Decision) {
			t.Fatalf("rebuilt %+v, stored %+v", again, ev.Decision)
		}
	}
}

func TestEveryReasonHasText(t *testing.T) {
	for _, r := range append(slices.Clone(reasonOrder), ReasonActive) {
		if ReasonText[r] == "" {
			t.Errorf("no text for %s", r)
		}
	}
}

// The scopes production reported for three Commmerce applications.
func TestScopeClass(t *testing.T) {
	cases := []struct{ scope, status, class, kind string }{
		{"bundles:/var/www/ghost/versions/6.52.0", "partial", ScopeLimit, "compiled front-end bundles"},
		{"bundle-limits:/srv/app", "partial", ScopeLimit, "compiled front-end bundles"},
		{"source-maps:/srv/app", "partial", ScopeLimit, "compiled front-end bundles"},
		{"flutter:/var/www/chat", "partial", ScopeLimit, "Flutter web engines"},
		{"app-permissions:/var/www/chat", "partial", ScopeFailed, ""},
		{"app-permissions:/var/www/help-centre", "unsupported", ScopeFailed, ""},
		{"hex:mix.lock:/srv/app/mix.lock", "unsupported", ScopeLimit, "files in formats Stackurity does not read yet"},
		{"os-packages", "unsupported", ScopeLimit, "systems without a package database"},
		{"app:/srv/app", "partial", ScopeFailed, ""}, // stopped after the package cap: incomplete, not a limit
		{"lockfile:/srv/app/yarn.lock", "failed", ScopeFailed, ""},
		{"bundles:/srv/app", "failed", ScopeFailed, ""},
		{"lockfiles", "skipped", ScopeOK, ""},
		{"web-assets:/var/www/chat", "checked", ScopeOK, ""},
		{"something-new:/x", "partial", ScopeFailed, ""},
	}
	for _, c := range cases {
		class, kind := ScopeClass(c.scope, c.status)
		if class != c.class || kind != c.kind {
			t.Errorf("ScopeClass(%q, %q) = %q, %q; want %q, %q", c.scope, c.status, class, kind, c.class, c.kind)
		}
	}
}

// An incomplete inventory explained only by coverage limits keeps the badge
// active and discloses them; unreadable files or a failed scope do not.
func TestCoverageLimitsAreNotCollectionErrors(t *testing.T) {
	limited := func(kinds ...string) Inputs {
		in := healthy()
		in.Assets[0].LatestComplete = false
		in.Assets[0].IncompleteExplained = true
		in.Assets[0].LimitKinds = kinds
		return in
	}
	// Ghost: compiled bundles only partly identifiable.
	if d := Evaluate(limited("compiled front-end bundles"), now); d.Result != Active ||
		!slices.Contains(d.UnsupportedKinds, "compiled front-end bundles") {
		t.Fatalf("ghost: %+v", d)
	}
	// Chat with only the Flutter limit.
	d := Evaluate(limited("Flutter web engines"), now)
	if d.Result != Active || !slices.Contains(d.UnsupportedKinds, "Flutter web engines") {
		t.Fatalf("chat: %+v", d)
	}
	// Chat and the help centre as they are: files the agent may not read.
	in := limited("Flutter web engines")
	in.Assets[0].FailedScopes = 1
	in.Assets[0].IncompleteExplained = false
	if d := Evaluate(in, now); d.Result != NotActive || d.Reason != ReasonCollectionErrors {
		t.Fatalf("unreadable files: %+v", d)
	}
	// Incomplete with nothing to explain it stays an error.
	in = healthy()
	in.Assets[0].LatestComplete = false
	if d := Evaluate(in, now); d.Reason != ReasonCollectionErrors {
		t.Fatalf("unexplained: %+v", d)
	}
}

// Evidence stored under the previous rule version carries no limit fields:
// rebuilt, an incomplete inventory there is still a collection error.
func TestEvidenceFromThePreviousRuleRebuilds(t *testing.T) {
	in := healthy()
	in.Assets[0].LatestComplete = false
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var old Inputs
	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}
	if d := Evaluate(old, now); d.Result != NotActive || d.Reason != ReasonCollectionErrors {
		t.Fatalf("decision = %+v", d)
	}
}
