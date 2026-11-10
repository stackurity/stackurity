package lifecycle

import "testing"

func TestCycleIndex(t *testing.T) {
	cycles := []string{"3", "3.19", "20"}
	for v, want := range map[string]int{"3.19.1": 1, "v3.2": 0, "1:20.1-1": 2, "4.0": -1} {
		if got := CycleIndex(cycles, v); got != want {
			t.Errorf("CycleIndex(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestResolve(t *testing.T) {
	r := &Resolver{ByPurl: map[string]string{"pkg:npm/express": "express"}, Names: map[string]bool{"express": true, "php": true, "ubuntu": true}}
	if m, ok := r.Resolve("npm", "pkg:npm/express", "4.17.1", ""); !ok || m.Product != "express" || m.CycleVersion != "4.17.1" {
		t.Errorf("express: %+v %v", m, ok)
	}
	if m, ok := r.Resolve("deb", "pkg:deb/debian/php7.4-common", "7.4.33-1", ""); !ok || m.Product != "php" || m.CycleVersion != "7.4" {
		t.Errorf("php: %+v %v", m, ok)
	}
	if m, ok := r.Resolve("generic", "pkg:generic/ubuntu", "22.04", "operating-system"); !ok || m.Product != "ubuntu" {
		t.Errorf("ubuntu: %+v %v", m, ok)
	}
	if _, ok := r.Resolve("npm", "pkg:npm/left-pad", "1.0.0", ""); ok {
		t.Error("left-pad has no lifecycle")
	}
}
