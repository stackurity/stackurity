package store

import "testing"

// The Latest column's badge: an update, nothing when current, and "ahead"
// when the installed version is newer than the latest stable release (a
// beta), never the "latest stable" tick.
func TestUpdateType(t *testing.T) {
	for _, c := range []struct{ typ, ns, installed, latest, want string }{
		{"npm", "", "4.3.1", "5.3.8", "major"},
		{"npm", "", "5.3.8", "5.3.8", ""},
		{"npm", "", "6.0.0-beta.1", "5.3.8", "ahead"},
		{"golang", "", "v1.6.0", "v1.5.0", ""}, // yanked: not "newer"
		{"generic", "wordpress-plugin", "9.9.5", "10.3.0", "major"},
		{"generic", "wordpress-plugin", "2.0", "2.0.0", ""},
		{"generic", "wordpress-plugin", "1.9", "1.9.2", "patch"},
		{"generic", "wordpress-plugin", "2.0-beta1", "1.9.2", "ahead"},
		{"generic", "wordpress-plugin", "1.9.2-rc1", "1.9.2", "patch"},
		{"generic", "wordpress-plugin", "1.8-beta", "1.9.2", "minor"},
		{"generic", "wordpress-theme", "4.6.0", "4.14.2", "minor"},
		{"generic", "wordpress-theme", "5.0.0", "4.14.2", "ahead"},
		{"generic", "", "1.0", "2.0", ""}, // other generic components have no release feed
	} {
		if got := updateType(c.typ, c.ns, c.installed, c.latest); got != c.want {
			t.Errorf("%s/%s %s -> %s = %q, want %q", c.typ, c.ns, c.installed, c.latest, got, c.want)
		}
	}
}
