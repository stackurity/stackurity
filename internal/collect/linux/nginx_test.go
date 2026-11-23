package linux

import (
	"context"
	"testing"
)

func TestNginxEdition(t *testing.T) {
	for out, want := range map[string]string{
		"nginx version: nginx/1.31.9\n":                                 "open-source",
		"nginx version: nginx/1.27.4 (nginx-plus-r34)\n":                "nginx-plus",
		"nginx version: nginx/1.29.0 (nginx-plus-r35-p1)\n":             "nginx-plus",
		"Tengine version: Tengine/3.1.0\nnginx version: nginx/1.24.0\n": "tengine",
		"nginx version: openresty/1.25.3.1\n":                           "openresty",
	} {
		if got := nginxEdition([]byte(out)); got != want {
			t.Errorf("%q: edition %q, want %q", out, got, want)
		}
	}
}

// nginxBinary is the part of an nginx binary that matters: the -v line is
// compiled in as one string, among others that mention nginx/ paths.
func nginxBinary(versionLine string, more ...string) string {
	s := "\x7fELF\x00/etc/nginx/nginx.conf\x00nginx/\x00"
	for _, m := range more {
		s += m + "\x00"
	}
	return s + versionLine + "\n\x00built by gcc 12.2.0\x00"
}

// The nginx an ingress controller's image compiles from source into
// /usr/local/nginx: in an image nothing is run, so the version and the
// edition come from the binary's strings.
func TestImageNginxFromBinary(t *testing.T) {
	for name, tc := range map[string]struct {
		line, more, version, edition string
	}{
		"open source": {"nginx version: nginx/1.31.8", "", "1.31.8", "open-source"},
		"nginx plus":  {"nginx version: nginx/1.29.0 (nginx-plus-r35)", "", "1.29.0", "nginx-plus"},
		"tengine":     {"nginx version: nginx/1.24.0", "Tengine version: Tengine/3.1.0", "1.24.0", "tengine"},
	} {
		t.Run(name, func(t *testing.T) {
			r := officialRuntimeRoot(t, "usr/local/nginx/sbin/nginx", "", "")
			r.file("usr/local/nginx/sbin/nginx", nginxBinary(tc.line, tc.more), 0o755)
			r.link("usr/sbin/nginx", "/usr/local/nginx/sbin/nginx")
			got, _ := runtimes(t, imageCollector(r.root, nil))
			o := onlyRuntime(t, got, "nginx")
			if o.Purl != "pkg:generic/nginx@"+tc.version || o.Evidence["detected_by"] != "binary-strings" ||
				o.Evidence["edition"] != tc.edition || o.Evidence["version_file"] != "/usr/local/nginx/sbin/nginx" {
				t.Errorf("nginx = %+v", o)
			}
		})
	}
}

// OpenResty's binary says "nginx version: openresty/...": no nginx version
// is read from it.
func TestImageOpenRestyNotNginx(t *testing.T) {
	r := officialRuntimeRoot(t, "usr/local/nginx/sbin/nginx", "", "")
	r.file("usr/local/nginx/sbin/nginx", nginxBinary("nginx version: openresty/1.25.3.1"), 0o755)
	got, _ := runtimes(t, imageCollector(r.root, nil))
	if o := onlyRuntime(t, got, "nginx"); o.Version != "" {
		t.Errorf("OpenResty read as nginx %s: %+v", o.Version, o)
	}
}

// On a host the binary is run, and the edition comes from what it prints.
func TestHostNginxEdition(t *testing.T) {
	r := officialRuntimeRoot(t, "usr/local/nginx/sbin/nginx", "", "")
	c := fixture(r.root)
	c.RunVersion = func(context.Context, string, []string) ([]byte, error) {
		return []byte("nginx version: nginx/1.27.4 (nginx-plus-r34)\n"), nil
	}
	got, _ := runtimes(t, c)
	o := onlyRuntime(t, got, "nginx")
	if o.Purl != "pkg:generic/nginx@1.27.4" || o.Evidence["detected_by"] != "version-output" || o.Evidence["edition"] != "nginx-plus" {
		t.Errorf("nginx = %+v", o)
	}
}
