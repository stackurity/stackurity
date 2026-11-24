package webscan

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
)

// UserAgent names the scanner to the sites it reads, with a page that says
// what it does.
const UserAgent = "StackurityWebCheck/0.1 (+https://stackurity.ai/website-check)"

// errBudget is returned once a scan has made all the requests it may.
var errBudget = errors.New("request budget used up")

// fetcher makes every request of one scan. It dials only public addresses
// (netguard refuses private, loopback and link-local ones, again after DNS
// and on every redirect), reads at most a fixed number of bytes from each
// response and stops after maxRequests.
type fetcher struct {
	client   *http.Client
	noFollow *http.Client

	mu          sync.Mutex
	requests    int
	maxRequests int
}

type response struct {
	URL    *url.URL // after redirects
	Status int
	Header http.Header
	Body   []byte
	TLS    *tls.ConnectionState
	// Cut is set when the body was longer than the limit.
	Cut bool
}

func newFetcher(maxRequests int) *fetcher {
	tr := &http.Transport{
		DialContext:           netguard.DialContext,
		Proxy:                 nil, // never through an environment proxy, which would bypass the address check
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
		DisableCompression:    false,
	}
	check := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("more than 5 redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s address", req.URL.Scheme)
		}
		return netguard.CheckHost(req.URL.Hostname())
	}
	return &fetcher{
		client: &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: check},
		noFollow: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		maxRequests: maxRequests,
	}
}

func (f *fetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *fetcher) take() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests >= f.maxRequests {
		return errBudget
	}
	f.requests++
	return nil
}

// get reads u, following redirects, keeping at most limit bytes of body.
func (f *fetcher) get(ctx context.Context, u string, limit int64) (*response, error) {
	return f.do(ctx, f.client, u, limit)
}

// head reads u without following a redirect.
func (f *fetcher) getNoFollow(ctx context.Context, u string, limit int64) (*response, error) {
	return f.do(ctx, f.noFollow, u, limit)
}

func (f *fetcher) do(ctx context.Context, c *http.Client, u string, limit int64) (*response, error) {
	if err := f.take(); err != nil {
		return nil, err
	}
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if err := netguard.CheckHost(pu.Hostname()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil && len(body) == 0 {
		return nil, err
	}
	r := &response{URL: resp.Request.URL, Status: resp.StatusCode, Header: resp.Header, TLS: resp.TLS}
	if int64(len(body)) > limit {
		body, r.Cut = body[:limit], true
	}
	r.Body = body
	return r, nil
}

// robots is what robots.txt says to every crawler and to this one.
type robots struct {
	found    bool
	disallow []string
	sitemaps []string
}

func parseRobots(data []byte) robots {
	r := robots{found: true}
	applies := false
	inGroup := false
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "sitemap":
			r.sitemaps = append(r.sitemaps, v)
		case "user-agent":
			if !inGroup {
				applies = false
			}
			inGroup = true
			ua := strings.ToLower(v)
			if ua == "*" || strings.Contains(ua, "stackurity") {
				applies = true
			}
		case "disallow":
			inGroup = false
			if applies && v != "" {
				r.disallow = append(r.disallow, v)
			}
		default:
			inGroup = false
		}
	}
	return r
}

func (r robots) allowed(p string) bool {
	for _, d := range r.disallow {
		d = strings.TrimSuffix(d, "*")
		if strings.HasSuffix(d, "$") {
			if p == strings.TrimSuffix(d, "$") {
				return false
			}
			continue
		}
		if strings.HasPrefix(p, d) {
			return false
		}
	}
	return true
}

// sitemapDoc is a sitemap or a sitemap index.
type sitemapDoc struct {
	XMLName xml.Name
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func parseSitemap(data []byte) (pages, children []string, ok bool) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, nil, false
		}
		data, _ = io.ReadAll(io.LimitReader(zr, 10<<20))
	}
	var d sitemapDoc
	if err := xml.Unmarshal(data, &d); err != nil {
		return nil, nil, false
	}
	for _, u := range d.URLs {
		if s := strings.TrimSpace(u.Loc); s != "" {
			pages = append(pages, s)
		}
	}
	for _, s := range d.Sitemaps {
		if l := strings.TrimSpace(s.Loc); l != "" {
			children = append(children, l)
		}
	}
	return pages, children, d.XMLName.Local == "urlset" || d.XMLName.Local == "sitemapindex"
}
