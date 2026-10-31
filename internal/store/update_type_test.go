package store

import "testing"

// The Latest column's badge: an update, nothing when current, and "ahead"
// when the installed version is newer than the latest stable release (a
// beta), never the "latest stable" tick. A pre-release of the latest
// release itself takes that release's type (2.0.0 major, 2.1.0 minor,
// 2.1.3 patch); a pre-release is never the latest stable release.
func TestUpdateType(t *testing.T) {
	for _, c := range []struct{ typ, ns, installed, latest, want string }{
		{"npm", "", "4.3.1", "5.3.8", "major"},
		{"npm", "", "5.3.8", "5.3.8", ""},
		{"npm", "", "6.0.0-beta.1", "5.3.8", "ahead"},
		{"golang", "", "v1.6.0", "v1.5.0", ""}, // yanked: not "newer"
		{"npm", "", "2.0.0-rc.1", "2.0.0", "major"},
		{"npm", "", "2.1.0-beta.3", "2.1.0", "minor"},
		{"npm", "", "2.1.3-rc.1", "2.1.3", "patch"},
		{"npm", "", "2.0.0-rc.1", "2.0.1", "patch"}, // past its release: the usual comparison
		{"npm", "", "1.9.0", "2.0.0-rc.1", ""},      // a pre-release is never latest stable
		{"pypi", "", "2.0.0rc1", "2.0.0", "major"},
		{"maven", "", "3.1.0-RC1", "3.1.0", "minor"},
		{"golang", "", "v2.0.0-beta.1", "v2.0.0", "major"},
		{"generic", "wordpress-plugin", "9.9.5", "10.3.0", "major"},
		{"generic", "wordpress-plugin", "2.0", "2.0.0", ""},
		{"generic", "wordpress-plugin", "1.9", "1.9.2", "patch"},
		{"generic", "wordpress-plugin", "2.0-beta1", "1.9.2", "ahead"},
		{"generic", "wordpress-plugin", "1.9.2-rc1", "1.9.2", "patch"},
		{"generic", "wordpress-plugin", "2.0-rc1", "2.0", "major"},
		{"generic", "wordpress-plugin", "2.1-beta2", "2.1.0", "minor"},
		{"generic", "wordpress-plugin", "1.9.2", "2.0-beta1", ""},
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
