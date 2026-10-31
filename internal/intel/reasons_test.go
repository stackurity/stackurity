package intel

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/winprograms"
	"github.com/stackurity/stackurity/internal/winrelease"
)

// TestUncheckedReasonsFromProducers produces every reason a component can
// be left unchecked for, from the code that writes it, and checks who the
// breakdown says acts on it (store/unchecked.go). The breakdown reads the
// reason's wording: if a producer's text changes, this test names the case
// and the pattern to update, instead of the reason silently landing in the
// wrong bucket.
func TestUncheckedReasonsFromProducers(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := context.Background()

	type tc struct {
		name, coverage, reason string
		class, cause, actor    string
	}
	var cases []tc
	add := func(name, coverage, reason, class, cause string) {
		cases = append(cases, tc{name: name, coverage: coverage, reason: reason, class: class, cause: cause, actor: store.UncheckedActors[class]})
	}
	const user, unsupported, waiting, none, other = store.UncheckedUnreadableVersion, store.UncheckedUnsupported,
		store.UncheckedWaitingForData, store.UncheckedNoAdvisories, store.UncheckedOther

	// osv.WhyNoTarget: no vulnerability target for a package URL.
	for _, c := range []struct{ purl, class, cause string }{
		{"pkg:npm/left-pad", user, "no_version"},
		{"pkg:npm/%zz", user, "unreadable_package"},
		{"pkg:swift/acme/Alamofire@5.0.0", unsupported, ""},
		{"pkg:hex/acme/billing@1.0.0", unsupported, ""},
		{"pkg:cocoapods/Alamofire@5.0.0", unsupported, ""},
		{"pkg:conan/zlib@1.3", unsupported, ""},
		{"pkg:generic/vcpkg/zlib@1.3", unsupported, ""},
		{"pkg:deb/mint/bash@5.0", unsupported, ""},
		{"pkg:deb/debian/bash@5.2", user, "unknown_release"},
		{"pkg:deb/debian/bash?distro=debian-12", user, "no_version"},
		{"pkg:deb/debian/bash@5.2?distro=plan9", unsupported, ""},
		{"pkg:rpm/centos/bash@5.0?distro=centos-7", unsupported, ""},
		{"pkg:rpm/amzn/bash@4.2?distro=amzn-1", unsupported, ""},
		{"pkg:rpm/oracle/bash@3.2?distro=ol-5", unsupported, ""},
		{"pkg:rpm/redhat/bash@5.1", user, "unknown_release"},
		{"pkg:rpm/redhat/bash?distro=rhel-9", user, "no_version"},
		{"pkg:bitbucket/acme/lib@1.0", unsupported, ""},
	} {
		reason, unsup := osv.WhyNoTarget(c.purl, "")
		cov := store.CoverageNotEvaluated
		if unsup {
			cov = store.CoverageUnsupported
		}
		add("WhyNoTarget "+c.purl, cov, reason, c.class, c.cause)
	}

	// The matcher's own reasons.
	add("feed not set up", store.CoverageNotEvaluated, feedGapReason("osv:npm", store.Feed{}, false), waiting, "")
	add("feed disabled", store.CoverageNotEvaluated, feedGapReason("osv:npm", store.Feed{Enabled: false}, true), waiting, "")
	add("feed never synced", store.CoverageNotEvaluated, feedGapReason("osv:npm", store.Feed{Enabled: true}, true), waiting, "")
	add("no advisories for the release", store.CoverageNotEvaluated, noAdvisoriesReason("osv:Debian", "Debian:14"), none, "")
	add("uncomparable version", store.CoverageNotEvaluated, uncomparableReason("banana", "npm"), user, "unparseable_version")
	add("program advisories not read", store.CoverageNotEvaluated, programNotReadReason("Google Chrome", "NVD", "programs:Windows"), waiting, "")

	// Windows updates: winrelease.UpdateLine's gaps as the matcher records them.
	for _, c := range []struct {
		name  string
		info  winrelease.Info
		class string
		cause string
	}{
		{"no build", winrelease.Info{Version: "banana", ProductName: "Windows Server 2022 Standard"}, user, "windows_no_build"},
		{"no UBR", winrelease.Info{Version: "10.0.20348", ProductName: "Windows Server 2022 Standard"}, user, "windows_no_ubr"},
		{"no product name", winrelease.Info{Version: "10.0.20348.2227"}, user, "windows_no_product"},
		{"version and build disagree", winrelease.Info{Version: "10.0.19045.3803", ProductName: "Windows 10 Pro", DisplayVersion: "21H2"}, user, "windows_mismatch"},
		{"unknown client build", winrelease.Info{Version: "10.0.99999.1", ProductName: "Windows 11 Pro"}, unsupported, ""},
		{"semi-annual server out of support", winrelease.Info{Version: "10.0.18363.1", ProductName: "Windows Server Datacenter"}, none, ""},
		{"ESU server", winrelease.Info{Version: "6.3.9600.1", ProductName: "Windows Server 2012 R2 Standard"}, unsupported, ""},
	} {
		_, gap := winrelease.UpdateLine(c.info)
		if gap == nil {
			t.Errorf("UpdateLine %s: no gap", c.name)
			continue
		}
		state, reason := windowsGapCoverage(gap)
		add("UpdateLine "+c.name, state, reason, c.class, c.cause)
	}

	// Windows end of life: winrelease.Map's reasons and the lifecycle data
	// gaps, merged with evaluated updates as the matcher merges them.
	evaluated := store.RowCoverage{State: store.CoverageEvaluated, Reason: windowsCumulativeOnly}
	for _, c := range []struct {
		name  string
		info  winrelease.Info
		class string
		cause string
	}{
		{"no product name", winrelease.Info{Version: "10.0.26100.1"}, user, "windows_no_product"},
		{"2019 or 1809", winrelease.Info{Version: "10.0.17763.1", EditionID: "ServerStandard"}, user, "windows_no_product"},
		{"name and build disagree", winrelease.Info{Version: "10.0.17763.1", ProductName: "Windows Server 2022 Standard"}, user, "windows_mismatch"},
		{"not a tracked release", winrelease.Info{Version: "10.0.20348.1", ProductName: "Windows Embedded Thing"}, unsupported, ""},
	} {
		_, why := winrelease.Map(c.info)
		if why == "" {
			t.Errorf("Map %s: no reason", c.name)
			continue
		}
		rc := mergeWindowsCoverage(evaluated, "end of life not evaluated: "+why)
		add("Map "+c.name, rc.State, rc.Reason, c.class, c.cause)
	}
	for _, c := range []struct{ name, gap, class string }{
		{"lifecycle not synced", "end of life not evaluated: no endoflife.date data for windows-server yet (the endoflife.date feed has not synced)", waiting},
		{"lifecycle has no release", "end of life not evaluated: endoflife.date windows-server has no release 2028", unsupported},
	} {
		rc := mergeWindowsCoverage(evaluated, c.gap)
		add(c.name, rc.State, rc.Reason, c.class, "")
	}

	// Windows programs: winprograms NormaliseVersion's errors.
	var withRule, withoutRule *winprograms.Program
	for _, p := range winprograms.Default().Programs() {
		if _, err := p.NormaliseVersion(p.Label, "1.0"); err != nil && strings.Contains(err.Error(), "reads no version") {
			withoutRule = p
		} else if withRule == nil {
			withRule = p
		}
	}
	if withRule == nil {
		t.Fatal("no catalogue program with a version rule")
	}
	if _, err := withRule.NormaliseVersion(withRule.Label, ""); err != nil {
		add("program without a version", store.CoverageNotEvaluated, err.Error()+", so it is not matched", user, "program_no_version")
	}
	if _, err := withRule.NormaliseVersion(withRule.Label, "!!garbage!!"); err != nil {
		add("program version in another form", store.CoverageNotEvaluated, err.Error()+", so it is not matched", user, "program_version_form")
	} else {
		t.Logf("%s reads %q; the version-form case is not produced", withRule.ID, "!!garbage!!")
	}
	if withoutRule != nil {
		_, err := withoutRule.NormaliseVersion(withoutRule.Label, "1.0")
		add("catalogue reads no version", store.CoverageNotEvaluated, err.Error()+", so it is not matched", unsupported, "")
	}

	// A reason with no rule never lands with Stackurity: the user looks.
	add("unknown reason", store.CoverageNotEvaluated, "something new went wrong", other, "")

	if len(cases) < 25 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		class, cause, actor, err := st.ClassifyUnchecked(ctx, c.coverage, c.reason)
		if err != nil {
			t.Fatal(err)
		}
		if class != c.class || cause != c.cause || actor != c.actor {
			t.Errorf("%s: %q (%s)\n  got %s/%s (%s), want %s/%s (%s)", c.name, c.reason, c.coverage, class, cause, actor, c.class, c.cause, c.actor)
		}
		// Every user case comes with a fix.
		if actor == store.ActorUser && class == store.UncheckedUnreadableVersion {
			if fix, _ := store.UnreadableVersionFix(cause, ""); fix == "" {
				t.Errorf("%s: no fix for %s", c.name, cause)
			}
		}
	}
}
