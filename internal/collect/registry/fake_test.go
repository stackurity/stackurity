package registry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

func TestMain(m *testing.M) {
	// The fakes are httptest TLS servers with their own certificate.
	testTLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // tests only
	// Names under .test resolve to the loopback address the fakes listen
	// on, so a "foreign host" is a different name on the same machine.
	restore := netguard.SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if strings.HasSuffix(host, ".test") || host == "localhost" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, fmt.Errorf("no such host %s (tests never resolve real names)", host)
	})
	code := m.Run()
	restore()
	os.Exit(code)
}

// ws1 is the default workspace, which may reach the loopback fakes.
func ws1() context.Context {
	return tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
}

// recorder keeps every request a fake server received.
type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

type recorded struct {
	Method, Host, Path, Auth string
	Body                     string
}

func (r *recorder) add(req *http.Request, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, recorded{req.Method, req.Host, req.URL.Path, req.Header.Get("Authorization"), body})
}

func (r *recorder) all() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

func (r *recorder) count(prefix string) int {
	n := 0
	for _, q := range r.all() {
		if strings.HasPrefix(q.Path, prefix) {
			n++
		}
	}
	return n
}

// image is one image in the fake registry.
type fakeImage struct {
	manifest []byte
	digest   string
	config   []byte
	cfgDig   string
}

func newFakeImage(created time.Time, salt string) fakeImage {
	cfg, _ := json.Marshal(map[string]any{"created": created.UTC().Format(time.RFC3339Nano), "architecture": "amd64", "os": "linux", "salt": salt})
	cs := sha256.Sum256(cfg)
	cfgDig := "sha256:" + hex.EncodeToString(cs[:])
	man, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfgDig, "size": len(cfg)},
		"layers": []any{},
	})
	ms := sha256.Sum256(man)
	return fakeImage{manifest: man, digest: "sha256:" + hex.EncodeToString(ms[:]), config: cfg, cfgDig: cfgDig}
}

// fakeOCI is a registry speaking the OCI Distribution API: a catalog and
// tag lists paged by Link headers, manifests by tag and digest, blobs, and
// (when Secret is set) a bearer token challenge whose realm is Realm (by
// default its own /token).
type fakeOCI struct {
	*recorder
	srv      *httptest.Server
	mu       sync.Mutex
	repos    map[string]map[string]fakeImage // repo → tag → image
	PageSize int
	User     string
	Secret   string
	Realm    string // token realm URL; "" for its own /token
	Basic    bool   // ask for basic authentication instead of a token
	// BlobRedirect sends blob downloads to this base URL (storage on another host).
	BlobRedirect string
	// NextHost puts the catalog's next page on another host.
	NextHost  string
	NoCatalog bool
}

const fakeToken = "registry-issued-token"

func newFakeOCI(t *testing.T) *fakeOCI {
	f := &fakeOCI{recorder: &recorder{}, repos: map[string]map[string]fakeImage{}, PageSize: 2}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOCI) URL() string { return f.srv.URL }

func (f *fakeOCI) push(repo, tag string, im fakeImage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repos[repo] == nil {
		f.repos[repo] = map[string]fakeImage{}
	}
	f.repos[repo][tag] = im
}

func (f *fakeOCI) deleteTag(repo, tag string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.repos[repo], tag)
}

func (f *fakeOCI) deleteRepo(repo string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.repos, repo)
}

func page(w http.ResponseWriter, r *http.Request, items []string, n int, key string, nextHost string) {
	sort.Strings(items)
	last := r.URL.Query().Get("last")
	start := 0
	if last != "" {
		start = sort.SearchStrings(items, last)
		if start < len(items) && items[start] == last {
			start++
		}
	}
	end := min(start+n, len(items))
	if end < len(items) {
		host := ""
		if nextHost != "" {
			host = "https://" + nextHost
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s%s?n=%d&last=%s>; rel="next"`, host, r.URL.Path, n, url.QueryEscape(items[end-1])))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{key: items[start:end]})
}

func (f *fakeOCI) serve(w http.ResponseWriter, r *http.Request) {
	f.add(r, "")
	if r.URL.Path == "/token" {
		u, p, ok := r.BasicAuth()
		if f.Secret != "" && (!ok || u != f.User || p != f.Secret) {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": fakeToken})
		return
	}
	if f.Secret != "" {
		authorized := false
		if f.Basic {
			u, p, ok := r.BasicAuth()
			authorized = ok && u == f.User && p == f.Secret
		} else {
			authorized = r.Header.Get("Authorization") == "Bearer "+fakeToken
		}
		if !authorized {
			if f.Basic {
				w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			} else {
				realm := f.Realm
				if realm == "" {
					realm = f.srv.URL + "/token"
				}
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s",service="fake",scope="%s"`, realm, scopeFor(r.URL.Path)))
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`))
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	n := f.PageSize
	if q, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && q < n {
		n = q
	}
	if path == "_catalog" {
		if f.NoCatalog {
			w.WriteHeader(404)
			return
		}
		var names []string
		for k := range f.repos {
			names = append(names, k)
		}
		page(w, r, names, n, "repositories", f.NextHost)
		return
	}
	for repo, tags := range f.repos {
		switch rest := strings.TrimPrefix(path, repo+"/"); {
		case rest == path:
			continue
		case rest == "tags/list":
			var names []string
			for t := range tags {
				names = append(names, t)
			}
			page(w, r, names, n, "tags", "")
			return
		case strings.HasPrefix(rest, "manifests/"):
			ref := strings.TrimPrefix(rest, "manifests/")
			for tag, im := range tags {
				if tag == ref || im.digest == ref {
					w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
					w.Header().Set("Docker-Content-Digest", im.digest)
					if r.Method != http.MethodHead {
						_, _ = w.Write(im.manifest)
					}
					return
				}
			}
		case strings.HasPrefix(rest, "blobs/"):
			d := strings.TrimPrefix(rest, "blobs/")
			for _, im := range tags {
				if im.cfgDig == d {
					if f.BlobRedirect != "" {
						http.Redirect(w, r, f.BlobRedirect+"/storage/"+d, http.StatusTemporaryRedirect)
						return
					}
					_, _ = w.Write(im.config)
					return
				}
			}
		}
	}
	w.WriteHeader(404)
	_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`))
}

// storage stands in for blob storage on another host: it serves any blob
// path from the given registry's images and records what it received.
type fakeOther struct {
	*recorder
	srv *httptest.Server
}

func newFakeOther(t *testing.T, serve func(w http.ResponseWriter, r *http.Request)) *fakeOther {
	o := &fakeOther{recorder: &recorder{}}
	o.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.add(r, "")
		if serve != nil {
			serve(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "stolen"})
	}))
	t.Cleanup(o.srv.Close)
	return o
}

// on returns the server's URL under another host name (resolved to the
// loopback address by TestMain's resolver).
func on(srvURL, host string) string {
	u, _ := url.Parse(srvURL)
	return "https://" + host + ":" + u.Port()
}
