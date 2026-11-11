// Package trustbadge decides whether a trust badge is active: the
// "evaluation contract" of the trust badge spec (docs/trust-badge.md).
//
// Evaluate is a pure function of its Inputs and the time, so a decision can
// be rebuilt from the evidence stored with it (trust_badge_status). The
// store gathers the inputs (store.TrustBadgeInputs); this package never
// reads the database.
//
// A badge is active only when every covered system meets all four
// conditions:
//
//	(a) it reported its software inventory in the last 7 days;
//	(b) its latest inventory was processed, without collection errors. A
//	    scope the collector could not fully read for an inherent reason (a
//	    compiled bundle whose contents are not identifiable, a Flutter
//	    engine no source covers, a format not read yet) is a coverage
//	    limit, disclosed like unsupported software, not an error. A scope
//	    that failed, files the agent may not read, or any other partial
//	    result is an error (ScopeClass);
//	(c) every vulnerability source its components were matched against is
//	    within that source's own freshness window (stale_after);
//	(d) every component was evaluated against the latest refresh of each of
//	    its sources. A refresh of one source never counts for another.
//
// Each component and source pair is in exactly one state: Evaluated,
// Unsupported (no source covers it: stays active, disclosed by broad kind of
// software), Pending (its source refreshed, or it arrived, and the check has
// not run yet: stays active while the refresh it was last evaluated against
// is within the source's freshness window), Failed (a check that should
// have completed did not) or Stale (its source is past its freshness
// window). Unsupported is never counted as failed, nor failed as
// unsupported.
package trustbadge

import (
	"sort"
	"strings"
	"time"
)

// RuleVersion names this rule. It is stored with every decision; change it
// whenever the rule's meaning changes.
//
// 2026-11-11.1: coverage limits in a system's latest inventory (ScopeClass)
// no longer count as collection errors; they are disclosed by broad kind.
// Evidence from 2026-11-10.1 rebuilds to the same decision: it carries no
// limit fields, so an incomplete inventory there still counts as an error.
const RuleVersion = "2026-11-11.1"

// ReportWindow is condition (a): how recently each covered system must have
// reported its inventory.
const ReportWindow = 7 * 24 * time.Hour

// ProcessingGrace is how long a newly received inventory, or a newly
// inventoried component, may wait for processing before the badge stops
// being active. Evaluations normally run within seconds of a report.
const ProcessingGrace = time.Hour

// SourceGrace is how long a component may wait for a vulnerability source
// that has not been set up or has not completed its first sync (the
// "waiting for data" reasons), the same as store.FeedGrace.
const SourceGrace = 6 * time.Hour

// Results.
const (
	Active    = "active"
	NotActive = "not_active"
)

// States of a component and source pair.
const (
	StateEvaluated   = "evaluated"
	StateUnsupported = "unsupported"
	StatePending     = "pending"
	StateFailed      = "failed"
	StateStale       = "stale"
)

// Reasons a badge is not active, in the order they are reported. Reason is
// the first that applies; Failed lists every one.
const (
	ReasonDisabled         = "badge_disabled"
	ReasonEmptyScope       = "no_systems_in_scope"
	ReasonNotReporting     = "system_not_reporting"
	ReasonCollectionErrors = "collection_errors"
	ReasonNotProcessed     = "inventory_not_processed"
	ReasonSourceStale      = "source_stale"
	ReasonEvaluationFailed = "evaluation_failed"
	ReasonRecheckOverdue   = "recheck_overdue"
	ReasonActive           = "all_conditions_met"
)

var reasonOrder = []string{ReasonDisabled, ReasonEmptyScope, ReasonNotReporting, ReasonCollectionErrors,
	ReasonNotProcessed, ReasonSourceStale, ReasonEvaluationFailed, ReasonRecheckOverdue}

// ReasonText says a reason in words, for the customer's own status timeline.
// It is never shown in public: the public page says only "Monitoring status
// could not be confirmed".
var ReasonText = map[string]string{
	ReasonDisabled:         "The badge is turned off.",
	ReasonEmptyScope:       "No systems are in the badge's scope.",
	ReasonNotReporting:     "A covered system has not reported its software inventory in the last 7 days.",
	ReasonCollectionErrors: "A covered system's latest inventory was incomplete or had collection errors.",
	ReasonNotProcessed:     "A covered system's latest inventory was not processed in time.",
	ReasonSourceStale:      "A vulnerability data source used for covered software is past its freshness window.",
	ReasonEvaluationFailed: "Some covered software could not be evaluated although a data source exists for it.",
	ReasonRecheckOverdue:   "Some covered software was not evaluated against the latest refresh of its data source within that source's freshness window.",
	ReasonActive:           "Every covered system meets all four conditions.",
}

// Classes of a component and source pair, as the store reads them from
// inventory coverage (store.uncheckedReasonSQL).
const (
	ClassEvaluated    = "evaluated"     // matched against Feed
	ClassUnsupported  = "unsupported"   // no source covers it
	ClassNoAdvisories = "no_advisories" // the source publishes nothing for this release
	ClassWaiting      = "waiting"       // its source is not set up or not synced yet
	ClassFailed       = "failed"        // a source exists but could not be used (unreadable version, other)
	ClassAwaiting     = "awaiting"      // inventoried, not evaluated yet
)

// Inputs is everything the rule reads for one badge. It is stored, whole,
// as the evidence of each decision.
type Inputs struct {
	BadgeID int64 `json:"badge_id"`
	Enabled bool  `json:"enabled"`
	// ScopeKind is "projects" or "assets"; ScopeIDs are the ids it names.
	ScopeKind string  `json:"scope_kind"`
	ScopeIDs  []int64 `json:"scope_ids"`
	Assets    []Asset `json:"assets"`
	// Sources are the vulnerability sources the pairs name, by name.
	Sources map[string]Source `json:"sources"`
	// Pairs are the covered components, grouped: rows with the same class,
	// kind, source and source refresh are one Pair with a count.
	Pairs []Pair `json:"pairs"`
}

// Asset is one covered system.
type Asset struct {
	ID   int64  `json:"id"`
	Kind string `json:"kind"`
	// LastReport is when its latest inventory arrived (nil: never).
	LastReport *time.Time `json:"last_report"`
	// LatestComplete: the latest inventory was a complete collection.
	LatestComplete bool `json:"latest_complete"`
	// FailedScopes counts collector scopes whose last attempt failed, or
	// that ScopeClass counts as failed (unreadable files, other partial
	// results).
	FailedScopes int64 `json:"failed_scopes"`
	// LimitKinds are the broad kinds of software of its coverage-limit
	// scopes (ScopeClass), disclosed like unsupported software.
	LimitKinds []string `json:"limit_kinds,omitempty"`
	// IncompleteExplained: the collector reported every scope that kept the
	// latest inventory from being complete, and each is a coverage limit or
	// had nothing to read. Then LatestComplete false is not an error.
	IncompleteExplained bool `json:"incomplete_explained,omitempty"`
	// ProcessedAt is when an evaluation of the asset last finished.
	ProcessedAt *time.Time `json:"processed_at"`
}

// Source is a vulnerability source as it stands now.
type Source struct {
	Exists      bool          `json:"exists"`
	Enabled     bool          `json:"enabled"`
	Cursor      string        `json:"cursor"`
	LastSuccess *time.Time    `json:"last_success"`
	StaleAfter  time.Duration `json:"stale_after"`
}

// Pair is a group of component and source pairs that the rule treats alike.
type Pair struct {
	Class string `json:"class"`
	// Kind is a broad kind of software ("npm packages", "WordPress plugins
	// and themes"), never a package name; set for unsupported classes.
	Kind string `json:"kind,omitempty"`
	// Source is the vulnerability source (evaluated pairs).
	Source string `json:"source,omitempty"`
	// SourceLastSuccess and SourceCursor are the refresh of the source the
	// evaluation read. Nil for rows evaluated before this was recorded:
	// their evaluation time is compared with the source's last refresh.
	SourceLastSuccess *time.Time `json:"source_last_success,omitempty"`
	SourceCursor      string     `json:"source_cursor,omitempty"`
	// OldestEvaluated is the earliest evaluation time in the group; Since
	// is the earliest time its rows started waiting (first inventoried, or
	// last evaluated, for awaiting and waiting rows).
	OldestEvaluated *time.Time `json:"oldest_evaluated,omitempty"`
	Since           *time.Time `json:"since,omitempty"`
	Count           int64      `json:"count"`
}

// Decision is the outcome of the rule.
type Decision struct {
	Result      string `json:"result"`
	Reason      string `json:"reason"`
	RuleVersion string `json:"rule_version"`
	// Failed lists every condition that failed, in reasonOrder.
	Failed []string `json:"failed"`
	// States counts component and source pairs by state.
	States map[string]int64 `json:"states"`
	// UnsupportedKinds are the broad kinds of software no source covers,
	// sorted: the trust page may disclose these, never package names.
	UnsupportedKinds []string `json:"unsupported_kinds"`
	// OldestEvaluated is the oldest evaluation time across the scope (nil:
	// nothing evaluated): the "last evaluated" time, never the time the
	// badge was drawn.
	OldestEvaluated *time.Time `json:"oldest_evaluated"`
	// PendingAssets counts systems whose latest inventory is waiting for
	// processing within ProcessingGrace.
	PendingAssets int `json:"pending_assets"`
}

// Evidence is what trust_badge_status.evidence holds.
type Evidence struct {
	Inputs   Inputs   `json:"inputs"`
	Decision Decision `json:"decision"`
}

// Evaluate applies the rule to in at now.
func Evaluate(in Inputs, now time.Time) Decision {
	d := Decision{RuleVersion: RuleVersion, States: map[string]int64{}, Failed: []string{}, UnsupportedKinds: []string{}}
	failed := map[string]bool{}
	if !in.Enabled {
		failed[ReasonDisabled] = true
	}
	if len(in.Assets) == 0 {
		failed[ReasonEmptyScope] = true
	}
	kinds := map[string]bool{}
	for _, a := range in.Assets {
		if a.LastReport == nil || now.Sub(*a.LastReport) > ReportWindow {
			failed[ReasonNotReporting] = true
			continue
		}
		if a.FailedScopes > 0 || (!a.LatestComplete && !a.IncompleteExplained) {
			failed[ReasonCollectionErrors] = true
		}
		for _, k := range a.LimitKinds {
			if k != "" {
				kinds[k] = true
			}
		}
		if a.ProcessedAt == nil || a.ProcessedAt.Before(*a.LastReport) {
			if now.Sub(*a.LastReport) <= ProcessingGrace {
				d.PendingAssets++
			} else {
				failed[ReasonNotProcessed] = true
			}
		}
	}
	for _, p := range in.Pairs {
		state, reason := pairState(p, in.Sources, now)
		d.States[state] += p.Count
		if reason != "" {
			failed[reason] = true
		}
		if state == StateUnsupported && p.Kind != "" {
			kinds[p.Kind] = true
		}
		if (state == StateEvaluated || state == StatePending || state == StateUnsupported) && p.OldestEvaluated != nil {
			if d.OldestEvaluated == nil || p.OldestEvaluated.Before(*d.OldestEvaluated) {
				t := *p.OldestEvaluated
				d.OldestEvaluated = &t
			}
		}
	}
	for k := range kinds {
		d.UnsupportedKinds = append(d.UnsupportedKinds, k)
	}
	sort.Strings(d.UnsupportedKinds)
	for _, r := range reasonOrder {
		if failed[r] {
			d.Failed = append(d.Failed, r)
		}
	}
	if len(d.Failed) == 0 {
		d.Result, d.Reason = Active, ReasonActive
	} else {
		d.Result, d.Reason = NotActive, d.Failed[0]
	}
	return d
}

// pairState is the state of a group of pairs, and the badge condition it
// fails ("" when it fails none).
func pairState(p Pair, sources map[string]Source, now time.Time) (string, string) {
	switch p.Class {
	case ClassUnsupported, ClassNoAdvisories:
		return StateUnsupported, ""
	case ClassFailed:
		return StateFailed, ReasonEvaluationFailed
	case ClassAwaiting:
		if p.Since != nil && now.Sub(*p.Since) <= ProcessingGrace {
			return StatePending, ""
		}
		return StateFailed, ReasonEvaluationFailed
	case ClassWaiting:
		if p.Since != nil && now.Sub(*p.Since) <= SourceGrace {
			return StatePending, ""
		}
		return StateStale, ReasonSourceStale
	case ClassEvaluated:
		if p.Source == "" {
			// Evaluated without a vulnerability feed (Windows updates read
			// from the lifecycle data, notes the matcher writes): there is
			// no source refresh to compare with. The same as the coverage
			// page, which never shows these rows as stale.
			return StateEvaluated, ""
		}
		src, ok := sources[p.Source]
		if !ok || !src.Exists || !src.Enabled || src.LastSuccess == nil ||
			now.Sub(*src.LastSuccess) > src.StaleAfter {
			return StateStale, ReasonSourceStale
		}
		// Evaluated against the source's latest refresh: the refresh the
		// evaluation read is the current one (or, for rows from before that
		// was recorded, the evaluation finished after it).
		current := false
		switch {
		case p.SourceLastSuccess != nil:
			current = !p.SourceLastSuccess.Before(*src.LastSuccess)
		case p.OldestEvaluated != nil:
			current = !p.OldestEvaluated.Before(*src.LastSuccess)
		}
		if current {
			return StateEvaluated, ""
		}
		// The source refreshed after the evaluation: pending while the data
		// the evaluation read is within the source's freshness window. The
		// grace runs from the refresh the component was evaluated against,
		// not from the latest one: a source that refreshes hourly would
		// otherwise keep restarting it, and a badge whose re-checks never
		// run would stay active.
		read := p.SourceLastSuccess
		if read == nil {
			read = p.OldestEvaluated
		}
		if read != nil && now.Sub(*read) <= src.StaleAfter {
			return StatePending, ""
		}
		return StateFailed, ReasonRecheckOverdue
	}
	// A class this rule does not know is never treated as fine.
	return StateFailed, ReasonEvaluationFailed
}

// Classes of a collector coverage scope (ScopeClass).
const (
	ScopeOK     = "ok"     // checked, or nothing to read (skipped)
	ScopeLimit  = "limit"  // an inherent coverage limit: disclosed, not an error
	ScopeFailed = "failed" // a check that should have completed did not
)

// limitScopes are the scope kinds (the scope up to its first ':') whose
// partial result is inherent to what the files are, not a failed read:
// compiled bundles are identified only by licence banners, version
// constants and source maps, and no vulnerability source covers a Flutter
// engine. Each maps to the broad kind of software the trust page names
// ("including some …").
var limitScopes = map[string]string{
	"bundles":       "compiled front-end bundles",
	"bundle-limits": "compiled front-end bundles",
	"source-maps":   "compiled front-end bundles",
	"flutter":       "Flutter web engines",
}

// permissionScope is apps.PermissionScope without its ':': files the
// agent's user may not read. The workspace can fix it (grant read access),
// so it is never a coverage limit. The coverage page counts the same
// scopes as unreadable files (store/unchecked.go).
const permissionScope = "app-permissions"

// ScopeClass classifies one collector coverage scope by its status, and
// for a coverage limit names its broad kind of software. Unknown partial
// results are failures: a limit must be listed here to keep a badge active.
func ScopeClass(scope, status string) (class, kind string) {
	k, _, _ := strings.Cut(scope, ":")
	switch status {
	case "checked", "skipped":
		return ScopeOK, ""
	case "failed":
		return ScopeFailed, ""
	}
	if k == permissionScope {
		return ScopeFailed, ""
	}
	switch status {
	case "partial":
		if kind, ok := limitScopes[k]; ok {
			return ScopeLimit, kind
		}
	case "unsupported":
		// A format or kind of system Stackurity does not read yet (an
		// unparsed lockfile, a host without a package database).
		if k == "os-packages" {
			return ScopeLimit, "systems without a package database"
		}
		return ScopeLimit, "files in formats Stackurity does not read yet"
	}
	return ScopeFailed, ""
}
