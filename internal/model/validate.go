package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
)

// Limits applied to every batch; batches are untrusted input.
const (
	MaxObservations   = 200_000
	MaxCoverageItems  = 1_000
	MaxIdentifiers    = 32
	MaxRelations      = 16
	MaxFieldLen       = 2048
	MaxEvidenceFields = 32
)

type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid batch: " + strings.Join(e.Problems, "; ")
}

// Validate checks a batch and normalises observation purls in place. It
// returns a *ValidationError listing every problem found, up to a cap.
func (b *ObservationBatch) Validate() error {
	var p []string
	add := func(format string, args ...any) {
		if len(p) < 50 {
			p = append(p, fmt.Sprintf(format, args...))
		}
	}
	long := func(s string) bool { return len(s) > MaxFieldLen }
	b.sanitise()

	if b.SchemaVersion != BatchSchemaVersion {
		add("unsupported schema_version %q", b.SchemaVersion)
	}
	if b.Collector.ID == "" || long(b.Collector.ID) || long(b.Collector.Version) || long(b.Collector.Method) {
		add("collector.id is required and fields must be under %d bytes", MaxFieldLen)
	}
	if !b.Asset.Kind.Valid() {
		add("asset.kind %q is not valid", b.Asset.Kind)
	}
	if b.Asset.Name == "" || long(b.Asset.Name) {
		add("asset.name is required")
	}
	if len(b.Asset.Environment) > MaxShortField || len(b.Asset.Provider) > MaxShortField || len(b.Asset.Region) > MaxShortField {
		add("asset.environment, provider and region must be under %d bytes", MaxShortField)
	}
	if len(b.Asset.Identifiers) == 0 || len(b.Asset.Identifiers) > MaxIdentifiers {
		add("asset.identifiers must have 1-%d entries", MaxIdentifiers)
	}
	for i, id := range b.Asset.Identifiers {
		if id.Scheme == "" || id.Value == "" || long(id.Scheme) || long(id.Value) {
			add("asset.identifiers[%d] needs scheme and value", i)
		}
	}
	for k, v := range b.Asset.Attributes {
		if long(k) || long(v) {
			add("asset.attributes[%q] too long", k)
		}
	}
	if b.ObservedAt.IsZero() || b.ObservedAt.After(time.Now().Add(10*time.Minute)) {
		add("observed_at is missing or in the future")
	}
	if len(b.Observations) > MaxObservations {
		add("too many observations (%d > %d)", len(b.Observations), MaxObservations)
	}
	if len(b.Coverage) > MaxCoverageItems {
		add("too many coverage items")
	}
	for i := range b.Observations {
		o := &b.Observations[i]
		if len(p) >= 50 {
			break
		}
		pu, err := packageurl.FromString(o.Purl)
		if err != nil || long(o.Purl) || hasControl(o.Purl) {
			add("observations[%d].purl %q is not a valid purl", i, truncate(o.Purl))
			continue
		}
		if o.Version == "" {
			o.Version = pu.Version
		}
		if long(o.Version) || long(o.Location) || long(o.Scope) {
			add("observations[%d] has an over-long field", i)
		}
		if hasControl(o.Version) {
			add("observations[%d].version has control characters", i)
		}
		if o.Confidence == "" {
			if o.Version == "" {
				o.Confidence = ConfidenceUnknown
			} else {
				o.Confidence = ConfidenceInferred
			}
		}
		if !o.Confidence.Valid() {
			add("observations[%d].confidence %q is not valid", i, o.Confidence)
		}
		if len(o.Evidence) > MaxEvidenceFields {
			add("observations[%d] has too many evidence fields", i)
		}
		for k, v := range o.Evidence {
			if long(k) || long(v) {
				add("observations[%d].evidence[%q] too long", i, truncate(k))
			}
		}
	}
	if len(b.Relations) > MaxRelations {
		add("too many relations")
	}
	runsOn := false
	for i, r := range b.Relations {
		if r.Kind != "runs_on" && r.Kind != "built_from" && r.Kind != "deployed_as" {
			add("relations[%d].kind must be runs_on, built_from or deployed_as", i)
		}
		runsOn = runsOn || r.Kind == "runs_on"
		if len(r.To) == 0 || len(r.To) > MaxIdentifiers {
			add("relations[%d].to must have 1-%d identifiers", i, MaxIdentifiers)
		}
		for _, id := range r.To {
			if id.Scheme == "" || id.Value == "" || long(id.Scheme) || long(id.Value) || id.Scheme == AppPathScheme {
				add("relations[%d] has an invalid identifier", i)
			}
		}
	}
	for _, id := range b.Asset.Identifiers {
		if id.Scheme != AppPathScheme {
			continue
		}
		// An application path means nothing without its host, and must not
		// be mixed with identities that could match another asset.
		if b.Asset.Kind != AssetApplication || !runsOn || len(b.Asset.Identifiers) != 1 || !strings.HasPrefix(id.Value, "/") {
			add("an %s identifier needs an application asset, an absolute path, no other identifiers and a runs_on relation", AppPathScheme)
		}
	}
	if b.Apps != nil {
		if b.Asset.Kind != AssetHost {
			add("apps is only allowed on a host's batch")
		}
		if len(b.Apps.Dirs) > MaxAppDirs {
			add("apps.dirs has more than %d directories", MaxAppDirs)
		}
		for i, d := range b.Apps.Dirs {
			if !strings.HasPrefix(d, "/") || long(d) || hasControl(d) {
				add("apps.dirs[%d] must be an absolute path", i)
				break
			}
		}
	}
	for i, c := range b.Coverage {
		switch c.Status {
		case "checked", "skipped", "failed", "unsupported", "partial":
		default:
			add("coverage[%d].status %q is not valid", i, c.Status)
		}
		if c.Scope == "" || long(c.Scope) || long(c.Reason) {
			add("coverage[%d] needs a scope", i)
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Usable reports whether an observation would pass Validate, so a
// collector can leave out one bad entry (a hostile lockfile line, say)
// instead of producing a batch the server refuses as a whole.
func Usable(o Observation) bool {
	long := func(s string) bool { return len(s) > MaxFieldLen }
	if long(o.Purl) || long(o.Version) || long(o.Location) || long(o.Scope) || len(o.Evidence) > MaxEvidenceFields {
		return false
	}
	if hasControl(o.Purl) || hasControl(o.Version) {
		return false
	}
	if o.Confidence != "" && !o.Confidence.Valid() {
		return false
	}
	for k, v := range o.Evidence {
		if long(k) || long(v) {
			return false
		}
	}
	pu, err := packageurl.FromString(o.Purl)
	return err == nil && !(o.Version == "" && long(pu.Version))
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// ComponentKey returns the versionless purl used as component identity,
// plus the parsed type, namespace and name.
func ComponentKey(purl string) (key, typ, namespace, name string, err error) {
	pu, err := packageurl.FromString(purl)
	if err != nil {
		return "", "", "", "", err
	}
	pu.Version = ""
	pu.Subpath = ""
	// Qualifiers such as distro or arch stay on the full purl stored with
	// each inventory row; the component itself is distro-independent.
	pu.Qualifiers = nil
	return pu.ToString(), pu.Type, pu.Namespace, pu.Name, nil
}
