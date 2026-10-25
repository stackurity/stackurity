package version

import "testing"

type tc struct {
	a, b string
	want int
}

func run(t *testing.T, name string, cmp Comparator, cases []tc) {
	t.Helper()
	for _, c := range cases {
		got, err := cmp(c.a, c.b)
		if err != nil {
			t.Errorf("%s(%q, %q): %v", name, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s(%q, %q) = %d, want %d", name, c.a, c.b, got, c.want)
		}
		// antisymmetry
		if back, _ := cmp(c.b, c.a); back != -c.want {
			t.Errorf("%s(%q, %q) = %d, not antisymmetric", name, c.b, c.a, back)
		}
	}
}

func TestSemver(t *testing.T) {
	run(t, "semver", CompareSemver, []tc{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.10.0", "1.9.0", 1},
		{"v2.0.0", "2.0.0", 0},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0+build.5", "1.0.0", 0},
		{"1.2", "1.2.0", 0},
		{"10000000000000000000.0.0", "9.0.0", 1},
	})
	if _, err := CompareSemver("latest", "1.0.0"); err == nil {
		t.Error("expected parse error")
	}
	if UpdateType("4.17.15", "4.17.21") != "patch" || UpdateType("4.17.15", "5.0.0") != "major" ||
		UpdateType("1.2.3", "1.3.0") != "minor" || UpdateType("2.0.0", "1.0.0") != "" {
		t.Error("UpdateType")
	}
}

func TestDebian(t *testing.T) {
	run(t, "debian", CompareDebian, []tc{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1}, // epoch wins
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0~~", "1.0~", -1},
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"3.0.11-1~deb12u2", "3.0.11-1", -1}, // backport is older than the unstable revision
		{"2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"1.2.3a", "1.2.3", 1},
		{"1.0+b1", "1.0", 1},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u5", 0},
		{"0", "0~", 1},
	})
}

func TestRPM(t *testing.T) {
	run(t, "rpm", CompareRPM, []tc{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:3.0.7-24.el9", "3.0.7-25.el9", 1},
		{"3.0.7-24.el9", "3.0.7-24.el9_3", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0^git1-1", "1.0.1-1", -1},
		{"1.0a-1", "1.0-1", 1},
		{"1.0.1", "1.0a", 1}, // numeric segment newer than alpha
		{"2.0", "2.0-5", 0},  // bare version matches any release
	})
}

func TestAPK(t *testing.T) {
	run(t, "apk", CompareAPK, []tc{
		{"1.2.13-r0", "1.2.13-r1", -1},
		{"3.1.4-r5", "3.1.4-r5", 0},
		{"1.2.4_git20230717-r4", "1.2.4-r4", 1},
		{"1.0_rc1-r0", "1.0-r0", -1},
		{"1.0_alpha1", "1.0_beta1", -1},
		{"1.0a-r0", "1.0-r0", 1},
		{"1.10-r0", "1.9-r0", 1},
		{"1.0_p1-r0", "1.0-r0", 1},
	})
}

func TestComposer(t *testing.T) {
	run(t, "composer", CompareComposer, []tc{
		{"10.48.4", "10.48.10", -1},
		{"v6.4.4", "6.4.4", 0},
		{"1.0.0-beta2", "1.0.0", -1},
		{"1.0.0-RC1", "1.0.0-beta9", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"2.0", "2.0.0.0", 0},
		{"1.0.0-patch1", "1.0.0", 1},
		{"5.4.0-dev", "5.4.0-alpha1", -1},
	})
	if _, err := CompareComposer("dev-main", "1.0"); err == nil {
		t.Error("branch versions are not comparable")
	}
}

func TestGeneric(t *testing.T) {
	run(t, "generic", CompareGeneric, []tc{
		{"12", "11", 1},
		{"24.04", "22.04", 1},
		{"1.0", "1.0.0", 0},
		{"1.0a", "1.0", 1},
	})
}

func TestPEP440(t *testing.T) {
	run(t, "pep440", ComparePEP440, []tc{
		{"2.0.0rc1", "2.0.0", -1},
		{"2.0.0a1", "2.0.0b1", -1},
		{"2.0.0b2", "2.0.0rc1", -1},
		{"2.0.0.dev1", "2.0.0a1", -1},
		{"2.0.0", "2.0.0.post1", -1},
		{"2.0.0.post1", "2.0.1", -1},
		{"1.0", "1.0.0", 0},
		{"1!1.0", "2.0", 1},
		{"4.2.7", "4.2.10", -1},
		{"1.26.18", "1.26.18+local.1", 0},
		{"2.0.0-1", "2.0.0.post1", 0},
	})
}

func TestRubyGems(t *testing.T) {
	run(t, "rubygems", CompareRubyGems, []tc{
		{"1.0.0.pre", "1.0.0", -1},
		{"1.0.0.rc1", "1.0.0.rc2", -1},
		{"1.0.0.beta", "1.0.0.rc", -1},
		{"1.15.5", "1.15.10", -1},
		{"1.0", "1", 0},
		{"7.1.2", "7.1.2.1", -1},
	})
}
