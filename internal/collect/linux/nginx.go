package linux

import (
	"bytes"
	"io"
	"os"
	"regexp"

	"github.com/stackurity/stackurity/internal/model"
)

// nginx found outside a package manager is matched against nginx's
// vulnerabilities by the release it reports (internal/intel), but only when
// it is nginx Open Source: NGINX Plus prints "nginx/1.27.4 (nginx-plus-r34)"
// and has releases and advisories of its own, and OpenResty, Tengine and
// Angie are builds of nginx with their own version lines. The agent says
// which one it saw in the evidence "edition".
//
// In a container image the binary is never run, so its version is read from
// the binary itself: nginx compiles the line "nginx version: nginx/1.27.3"
// that -v prints into it as one string. That is how the nginx an ingress
// controller's image compiles from source gets a version.

// nginxVersionLine is the -v line compiled into the binary.
var nginxVersionLine = regexp.MustCompile(`nginx version: nginx/(\d+\.\d+\.\d+)[^\x00\n]*`)

// maxNginxBinary bounds how much of a binary is read (nginx with every
// module is a few MB; ingress controllers' builds stay well under this).
const maxNginxBinary = 64 << 20

// nginxEdition reads the edition from nginx -v output or the binary's
// strings.
func nginxEdition(out []byte) string {
	l := bytes.ToLower(out)
	switch {
	case bytes.Contains(l, []byte("nginx-plus")):
		return "nginx-plus"
	case bytes.Contains(l, []byte("openresty")):
		return "openresty"
	case bytes.Contains(l, []byte("tengine")):
		return "tengine"
	case bytes.Contains(l, []byte("angie")):
		return "angie"
	}
	return "open-source"
}

// nginxVersionFromBinary reads nginx's version from the binary at bin (a
// host path with symlinks resolved).
func (c *Collector) nginxVersionFromBinary(bin string) (pythonFileVersion, bool) {
	f, err := os.Open(c.path(bin))
	if err != nil {
		return pythonFileVersion{}, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return pythonFileVersion{}, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxNginxBinary))
	if err != nil {
		return pythonFileVersion{}, false
	}
	m := nginxVersionLine.FindSubmatch(data)
	if m == nil {
		return pythonFileVersion{}, false
	}
	// The edition is in the version line (NGINX Plus) or another banner
	// of the same binary ("Tengine version: ...", "openresty/...").
	edition := nginxEdition(m[0])
	if edition == "open-source" {
		for _, other := range [][]byte{[]byte("Tengine version:"), []byte("openresty/"), []byte("Angie version:")} {
			if bytes.Contains(data, other) {
				edition = nginxEdition(other)
				break
			}
		}
	}
	return pythonFileVersion{string(m[1]), model.ConfidenceConfirmed, "binary-strings",
		map[string]string{"version_file": bin, "edition": edition}}, true
}
