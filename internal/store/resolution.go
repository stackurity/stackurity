package store

// Why a finding closed. The matcher records a machine-readable kind
// (findings.resolution_kind) next to the sentence it writes
// (findings.resolution), and the facts behind it (findings.resolution_detail:
// the advisories and their source, the date an advisory was withdrawn, the
// version upgraded to, the remediation plan, the finding that took over).
// Reports count only remediated and removed findings as remediation: the
// other kinds close a finding without anything changing on the asset.
// Migration 0045 classified the findings resolved before kinds existed.
//
// Nothing closes a finding by policy or by hand today: ignore rules and
// people snooze or accept a finding, which stays open. Such a kind would be
// added with the code that writes it.
const (
	// The installed version changed to one the advisories do not list: an
	// upgrade seen in a newer inventory, or a verified remediation plan.
	ResolutionRemediated = "remediated"
	// A complete inventory no longer lists the component.
	ResolutionRemoved = "removed"
	// The component was upgraded, but the new version is still affected:
	// the issue continues as another finding on the new version.
	ResolutionSuperseded = "superseded"
	// Every advisory behind the finding was withdrawn by its source.
	ResolutionAdvisoryWithdrawn = "advisory_withdrawn"
	// The advisory (or lifecycle) data changed so the installed version,
	// which did not change, is no longer listed.
	ResolutionAdvisoryChanged = "advisory_changed"
	// The row could no longer be evaluated (its feed was disabled, or the
	// version could not be compared), so the matcher could not confirm it.
	ResolutionNotEvaluated = "not_evaluated"
	// A resolution written before kinds existed that could not be classified.
	ResolutionOther = "other"
)

// ResolutionKinds lists every kind, remediation first.
var ResolutionKinds = []string{ResolutionRemediated, ResolutionRemoved, ResolutionSuperseded, ResolutionAdvisoryWithdrawn,
	ResolutionAdvisoryChanged, ResolutionNotEvaluated, ResolutionOther}

// CountsAsRemediation reports whether a resolution kind is remediation:
// something changed on the asset that took the issue away.
func CountsAsRemediation(kind string) bool {
	return kind == ResolutionRemediated || kind == ResolutionRemoved
}

// remedied is true for a resolved finding (alias a) that counts as
// remediation in reports (outcomes, and the paid edition's evidence
// report): time to remedy, SLA and resolved totals.
func remedied(a string) string {
	return a + `.resolution_kind IN ('remediated', 'removed')`
}

// advisorySource names who publishes an advisory, from its id, or else the
// ecosystem of the feed it came from ("osv:Ubuntu" is Ubuntu).
func advisorySource(a string) string {
	return `CASE WHEN ` + a + `.id LIKE 'UBUNTU-%' OR ` + a + `.id LIKE 'USN-%' THEN 'Ubuntu'
		WHEN ` + a + `.id LIKE 'GHSA-%' THEN 'GitHub'
		WHEN ` + a + `.id LIKE 'DEBIAN-%' OR ` + a + `.id LIKE 'DSA-%' OR ` + a + `.id LIKE 'DLA-%' OR ` + a + `.id LIKE 'DTSA-%' THEN 'Debian'
		WHEN ` + a + `.id LIKE 'RHSA-%' OR ` + a + `.id LIKE 'RHBA-%' OR ` + a + `.id LIKE 'RHEA-%' THEN 'Red Hat'
		WHEN ` + a + `.id LIKE 'SUSE-%' OR ` + a + `.id LIKE 'openSUSE-%' THEN 'SUSE'
		WHEN ` + a + `.id LIKE 'ALSA-%' THEN 'AlmaLinux'
		WHEN ` + a + `.id LIKE 'RLSA-%' THEN 'Rocky Linux'
		WHEN ` + a + `.id LIKE 'ALAS%' THEN 'Amazon Linux'
		ELSE regexp_replace(` + a + `.feed, '^[^:]*:', '') END`
}

// closedByIntel classifies the open findings (alias f, with inventory row i
// and component c) that an evaluation no longer produced while their
// inventory row is still installed: nothing on the asset changed. It yields
// kind, resolution and detail for each.
func closedByIntel() string {
	return `CROSS JOIN LATERAL (SELECT count(*) AS total, count(a.withdrawn) AS withdrawn, max(a.withdrawn) AS withdrawn_at,
		  string_agg(DISTINCT ` + advisorySource("a") + `, ' and ') FILTER (WHERE a.withdrawn IS NOT NULL) AS source,
		  min(a.feed) AS feed
		  FROM advisories a WHERE a.id = ANY(f.sources)) adv
		CROSS JOIN LATERAL (SELECT CASE WHEN f.kind = 'vulnerability' AND i.coverage IN ('not_evaluated', 'unsupported') THEN 'not_evaluated'
		    WHEN f.kind = 'vulnerability' AND adv.total > 0 AND adv.withdrawn = adv.total THEN 'advisory_withdrawn'
		    ELSE 'advisory_changed' END AS kind,
		  COALESCE(NULLIF(f.evidence->>'osv_package', ''), c.name) AS package,
		  CASE WHEN cardinality(f.sources) > 0 THEN array_to_string(f.sources, ', ') ELSE f.key END AS ids) k
		CROSS JOIN LATERAL (SELECT k.kind,
		  CASE k.kind
		    WHEN 'not_evaluated' THEN 'no longer evaluated: ' || COALESCE(NULLIF(i.coverage_reason, ''), 'the vulnerability feed could not be used')
		    WHEN 'advisory_withdrawn' THEN 'advisory withdrawn by ' || adv.source || ' on ' || to_char(adv.withdrawn_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
		    ELSE CASE WHEN f.kind = 'end_of_life' THEN 'lifecycle data updated: ' || k.package || ' ' || i.version || ' is no longer listed as end of life'
		      ELSE 'advisory updated: ' || k.ids || ' no longer lists ' || k.package || ' ' || i.version END
		  END AS resolution,
		  jsonb_strip_nulls(jsonb_build_object('advisories', CASE WHEN f.kind = 'vulnerability' THEN to_jsonb(f.sources) END,
		    'source', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.source END,
		    'feed', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.feed END,
		    'withdrawn_at', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.withdrawn_at END,
		    'package', k.package, 'version', i.version,
		    'reason', CASE WHEN k.kind = 'not_evaluated' THEN i.coverage_reason END)) AS detail) x`
}
