package osv

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/version"
)

var ecosystems = []version.Ecosystem{version.SemVer, version.Composer, version.Debian, version.RPM, version.APK,
	version.PEP440, version.RubyGems, version.Maven, version.NuGet, version.Generic}

// FuzzRecord decodes an OSV record from a feed (untrusted: a mirror or a
// compromised upstream) and checks every affected entry against an
// installed version with every comparator. Nothing may panic.
func FuzzRecord(f *testing.F) {
	f.Add([]byte(`{"id":"GHSA-1","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`), "1.0.0", uint8(0))
	f.Add([]byte(`{"id":"DSA-1","affected":[{"package":{"ecosystem":"Debian:12","name":"a"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:2.3-4~deb12u1"},{"last_affected":"9"},{"limit":"*"}]}],"versions":["1","2"]}]}`), "1:2.3-3", uint8(2))
	f.Add([]byte(`{"id":"x","affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":""},{"introduced":"\u0000"},{"fixed":"999999999999999999999999999999999"}]}]}]}`), "0.0.0-a.b.c+d", uint8(5))
	f.Add([]byte(`{"id":"x","affected":[{"ranges":[{"type":"SEMVER","events":[]}]}]}`), "", uint8(7))
	f.Fuzz(func(t *testing.T, rec []byte, installed string, eco uint8) {
		var v Vulnerability
		if json.Unmarshal(rec, &v) != nil {
			return
		}
		e := ecosystems[int(eco)%len(ecosystems)]
		target := Target{Ecosystem: "npm", Name: "a", Version: installed, Compare: e}
		for _, a := range v.Affected {
			_, _ = Check(a, target)
		}
		_ = GroupKey(v.ID, v.Aliases)
	})
}

// FuzzComparators: every version comparator accepts any pair of strings
// without panicking, and agrees with itself when the arguments swap.
func FuzzComparators(f *testing.F) {
	for _, s := range [][2]string{{"1.0.0", "1.0.1"}, {"1:2.3-4", "2.3-4"}, {"1.0a1", "1.0.post2"}, {"1.0-r0", "1.0_p1-r1"},
		{"v1.2.3-beta+meta", "1.2.3"}, {"", "~"}, {"9999999999999999999999", "1"}, {"1.0.0.0.0.0.0", "1..0"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, e := range ecosystems {
			cmp := version.For(e)
			x, errX := cmp(a, b)
			y, errY := cmp(b, a)
			if errX == nil && errY == nil && x != -y {
				t.Fatalf("%s: cmp(%q,%q)=%d but cmp(%q,%q)=%d", e, a, b, x, b, a, y)
			}
		}
	})
}

// TestHostileRecords: huge range lists and versions as long as a batch
// allows are evaluated in bounded time; over-long versions fail to parse
// instead of being compared.
func TestHostileRecords(t *testing.T) {
	var events []Event
	for i := 0; i < 5000; i++ {
		events = append(events, Event{Introduced: "0"}, Event{Fixed: strings.Repeat("9.", 100) + "9"})
	}
	a := Affected{Ranges: []Range{{Type: "ECOSYSTEM", Events: events}, {Type: "SEMVER", Events: events}}, Versions: make([]string, 50000)}
	for _, e := range ecosystems {
		start := time.Now()
		if _, err := Check(a, Target{Version: strings.Repeat("1.", 1000) + "0", Compare: e}); err == nil {
			t.Errorf("%s: a 2001-character version was compared", e)
		}
		_, _ = Check(a, Target{Version: strings.Repeat("1.", 120) + "0", Compare: e})
		if d := time.Since(start); d > timeBudgetFactor*5*time.Second {
			t.Errorf("%s: %s", e, d)
		}
	}
}
