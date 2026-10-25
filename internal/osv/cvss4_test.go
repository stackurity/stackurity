package osv

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Expected scores in this file and in testdata/cvss4_vectors.txt come from
// the official FIRST CVSS v4.0 calculator
// (https://github.com/FIRSTdotorg/cvss-v4-calculator, commit c5b0d409, its
// cvss_score.js run under Node). 9.3 for the network/no-interaction/high
// impact vector also matches the specification's examples and NVD.
func TestCVSS4Score(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// all-high, all-none, all-low; then each exploitability metric, each
		// impact metric on its own, threat (E), environmental and supplemental.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L", 1.0},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N", 1.0},
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5},
		{"CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.6},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 7.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N", 7.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H", 7.7},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L", 6.9},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.9},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L", 8.9},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:M/IR:M/AR:M", 9.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:P", 7.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAC:H/MAT:P/MPR:H/MUI:A", 7.1},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N", 0.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSI:S/MSA:S", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MSC:H/MSI:H/MSA:H", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MVC:H", 8.7},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MSC:L", 6.5},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Red", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear", 9.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X", 9.3},
		{"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P", 8.5},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/MSI:S", 9.4},
		{"CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:L/SA:N/E:P/IR:H", 1.6},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.3},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.3},
	}
	for _, c := range cases {
		if got, ok := CVSS4Score(c.vector); !ok || got != c.want {
			t.Errorf("%s = %v %v, want %v", c.vector, got, ok, c.want)
		}
	}
}

// TestCVSS4Fixture compares against a few hundred vectors scored by the
// official calculator; see testdata/README.md.
func TestCVSS4Fixture(t *testing.T) {
	f, err := os.Open("testdata/cvss4_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		vec, want, ok := strings.Cut(sc.Text(), " ")
		w, err := strconv.ParseFloat(want, 64)
		if !ok || err != nil {
			t.Fatalf("bad fixture line %q", sc.Text())
		}
		n++
		if got, ok := CVSS4Score(vec); !ok || got != w {
			t.Errorf("%s = %v %v, want %v", vec, got, ok, w)
		}
	}
	if n < 300 {
		t.Fatalf("only %d fixture vectors", n)
	}
}

func TestCVSS4Invalid(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, vec := range []string{
		"",
		"CVSS:4.0",
		"CVSS:4.0/AV:N",                       // Base metrics missing
		strings.Replace(base, "/AT:N", "", 1), // one Base metric missing
		strings.Replace(base, "CVSS:4.0", "CVSS:3.1", 1),
		strings.Replace(base, "AV:N", "AV:X", 1),           // Base metrics cannot be Not Defined
		strings.Replace(base, "AV:N", "AV:n", 1),           // values are case-sensitive
		strings.Replace(base, "AV:N/AC:L", "AC:L/AV:N", 1), // out of order
		base + "/",
		base + "/E:A/E:A",     // duplicate
		base + "/AV:N",        // duplicate Base metric
		base + "/CR:H/E:A",    // Threat after Environmental
		base + "/XX:Y",        // unknown metric
		base + "/E:Q",         // unknown value
		base + "/MSC:S",       // S only exists for MSI and MSA
		base + "/U:red",       // case-sensitive
		base + "/E",           // no value
		base + "/E:A:P",       // extra colon
		"cvss:4.0" + base[8:], // prefix is case-sensitive
		" " + base,            // no trimming
	} {
		if s, ok := CVSS4Score(vec); ok {
			t.Errorf("%q accepted with score %v", vec, s)
		}
	}
}

func FuzzCVSS4Score(f *testing.F) {
	f.Add("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	f.Add("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/E:U/CR:L/MSI:S/U:Red")
	f.Add("CVSS:4.0/AV:N/E:A")
	f.Fuzz(func(t *testing.T, vec string) {
		s, ok := CVSS4Score(vec)
		if !ok {
			return
		}
		if s < 0 || s > 10 || s*10 != float64(int(s*10+0.5)) {
			t.Fatalf("%q scored %v", vec, s)
		}
	})
}
