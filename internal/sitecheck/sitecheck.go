// Package sitecheck is the website check (docs/website-check.md): what a
// public website shows anyone who visits it, read the way a browser does,
// and matched against stored vulnerability, known-exploited and end-of-life
// data.
//
// A check is passive: one GET of the page asked for (following up to five
// redirects), then the first few kilobytes of up to MaxScripts of the
// scripts and stylesheets it loads. Nothing else is requested: no ports, no
// paths that are not linked, no payloads. Every connection goes through a
// netguard policy that refuses private, loopback, link-local and metadata
// addresses whatever the server's own setting, checked again on the address
// dialled (DNS rebinding). Only ports 80 and 443.
//
// The package needs no database: matching is an Intel the caller provides
// (internal/intel.SiteCheckIntel on the server).
package sitecheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/netguard"
)

// Limits of one check.
const (
	MaxScripts     = 20
	maxPageBytes   = 2 << 20
	maxScriptBytes = 16 << 10
	maxRedirects   = 5
	checkTimeout   = 30 * time.Second
	fetchTimeout   = 15 * time.Second
	// UserAgent says who is visiting and where to read what the check does.
	UserAgent = "Mozilla/5.0 (compatible; StackurityWebsiteCheck/1.0; +https://stackurity.ai/website-check)"
)

// ErrTarget is an address the check will not visit.
var ErrTarget = errors.New("not a public website address")

// Report is the result of one check.
type Report struct {
	URL       string    `json:"url"`
	FinalURL  string    `json:"final_url"`
	Host      string    `json:"host"`
	CheckedAt time.Time `json:"checked_at"`
	Status    int       `json:"status"`
	// TLS of the final page (nil when it was served over http).
	TLS *TLSInfo `json:"tls"`
	// Software found, each with what the stored data says about it.
	Software []Software `json:"software"`
	// Headers lists browser protections the page does or does not send.
	Headers []HeaderCheck `json:"headers"`
	Summary Summary       `json:"summary"`
	// Notes say what the check could not do (a script that did not load).
	Notes []string `json:"notes"`
}

// TLSInfo describes the connection the final page came over.
type TLSInfo struct {
	Version  string    `json:"version"`
	Issuer   string    `json:"issuer"`
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	// Outdated: TLS 1.0 or 1.1 was negotiated (the check does not offer
	// them, so a site that needs them fails with a message instead).
	Outdated bool `json:"outdated"`
}

// Software is one product or library the site shows, with a version.
type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Kind: server (web server, language runtime), cms, library.
	Kind string `json:"kind"`
	// Where says how it was seen: "Server header", "page generator tag",
	// or the script's address.
	Where string `json:"where"`
	// Ecosystem and Package are what it is matched as: npm and the package
	// name, or "vendor" and a catalogued product (internal/vendorbuilds),
	// or "" when only its end of life is known.
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	// Lifecycle is the endoflife.date product, when one applies.
	Lifecycle string  `json:"lifecycle,omitempty"`
	Issues    []Issue `json:"issues"`
	EndOfLife *EOL    `json:"end_of_life"`
	// Coverage is set when its vulnerabilities could not be checked, and
	// says why ("no vulnerability data stored for Apache HTTP Server").
	Coverage string `json:"coverage,omitempty"`
}

// Issue is one vulnerability a version is affected by.
type Issue struct {
	ID             string   `json:"id"`
	Aliases        []string `json:"aliases,omitempty"`
	Summary        string   `json:"summary,omitempty"`
	Severity       string   `json:"severity"`
	Score          float64  `json:"score,omitempty"`
	KnownExploited bool     `json:"known_exploited"`
	FixedIn        string   `json:"fixed_in,omitempty"`
}

// EOL is the release line a version belongs to.
type EOL struct {
	Product string     `json:"product"`
	Cycle   string     `json:"cycle"`
	Ended   bool       `json:"ended"`
	EOLDate *time.Time `json:"eol_date,omitempty"`
	Latest  string     `json:"latest,omitempty"`
	Link    string     `json:"link,omitempty"`
}

// HeaderCheck is one browser protection header.
type HeaderCheck struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Advice  string `json:"advice,omitempty"`
}

// Summary counts the report.
type Summary struct {
	Software       int `json:"software"`
	Issues         int `json:"issues"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	KnownExploited int `json:"known_exploited"`
	EndOfLife      int `json:"end_of_life"`
	// HeadersMissing counts HeaderCheck entries not present.
	HeadersMissing int `json:"headers_missing"`
}

// Intel answers what the stored data says about one piece of software.
type Intel interface {
	// Vulnerabilities returns the issues of sw's version; coverage is set
	// (and issues nil) when they could not be checked.
	Vulnerabilities(ctx context.Context, sw Software) (issues []Issue, coverage string, err error)
	// EndOfLife returns sw's release line, or nil when none is known.
	EndOfLife(ctx context.Context, sw Software) (*EOL, error)
}

// Checker runs checks. The zero value is ready; Client is for tests.
type Checker struct {
	Intel Intel
	// Client, when set, is used instead of the guarded client (tests with
	// httptest servers on loopback).
	Client *http.Client
	// Now is for tests.
	Now func() time.Time
}

// Target normalises what someone typed ("example.com", "https://example.com/shop")
// into the address the check visits: http or https (https when none is
// given), a host name (not an IP address, not localhost, with a dot), port
// 80 or 443 only, no user or password.
func Target(input string) (*url.URL, error) {
	s := strings.TrimSpace(input)
	if s == "" || len(s) > 2048 {
		return nil, fmt.Errorf("%w: enter a domain such as example.com", ErrTarget)
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTarget, err)
	}
	if err := checkURL(u); err != nil {
		return nil, err
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func checkURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: only http and https addresses", ErrTarget)
	}
	if u.User != nil {
		return fmt.Errorf("%w: an address with a user name or password", ErrTarget)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || !strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") || host == "localhost" ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("%w: enter a public domain name", ErrTarget)
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return fmt.Errorf("%w: enter a domain name, not an IP address", ErrTarget)
	}
	if err := netguard.CheckHost(host); err != nil {
		return fmt.Errorf("%w: %v", ErrTarget, err)
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return fmt.Errorf("%w: only the standard ports (80 and 443)", ErrTarget)
	}
	return nil
}

// guardedClient never reaches a private address, follows at most
// maxRedirects redirects, each to an address Target would accept.
func guardedClient() *http.Client {
	tr := &http.Transport{
		DialContext:           netguard.Policy{}.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: fetchTimeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       10 * time.Second,
		DisableCompression:    false,
		// Certificates are verified and TLS 1.2 is the minimum (Go's
		// default): a broken certificate or a site that offers only TLS
		// 1.0 or 1.1 is reported (describeFetchError), not looked past.
		Proxy: nil,
	}
	return &http.Client{Transport: tr, Timeout: fetchTimeout, CheckRedirect: checkRedirect}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return fmt.Errorf("more than %d redirects", maxRedirects)
	}
	return checkURL(req.URL)
}

// Check visits target (from Target) and returns the report.
func (c *Checker) Check(ctx context.Context, target *url.URL) (*Report, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	client := c.Client
	if client == nil {
		client = guardedClient()
	}
	r := &Report{URL: target.String(), Host: strings.ToLower(target.Hostname()), CheckedAt: now().UTC(),
		Software: []Software{}, Headers: []HeaderCheck{}, Notes: []string{}}

	resp, body, err := get(ctx, client, target.String(), maxPageBytes, false)
	if err != nil {
		return nil, describeFetchError(target, err)
	}
	r.Status, r.FinalURL = resp.StatusCode, resp.Request.URL.String()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		r.TLS = &TLSInfo{Version: tls.VersionName(resp.TLS.Version), Issuer: cert.Issuer.CommonName, Subject: cert.Subject.CommonName,
			NotAfter: cert.NotAfter.UTC(), DaysLeft: int(cert.NotAfter.Sub(now()).Hours() / 24),
			Outdated: resp.TLS.Version < tls.VersionTLS12}
	}
	if resp.Request.URL.Scheme == "http" {
		r.Notes = append(r.Notes, "the page was served over plain http, without encryption")
	}

	found := newFound()
	fromHeaders(resp.Header, found)
	fromGenerator(body, found)
	for _, m := range apps.ParsePage(body) {
		found.add(Software{Name: m[0], Version: m[1], Kind: "library", Where: m[2], Ecosystem: "npm", Package: m[0]})
	}
	c.fromScripts(ctx, client, resp.Request.URL, body, found, r)
	r.Headers = headerChecks(resp.Header, resp.Request.URL.Scheme == "https")

	for _, sw := range found.list() {
		if c.Intel != nil {
			if sw.Ecosystem != "" {
				issues, coverage, err := c.Intel.Vulnerabilities(ctx, sw)
				if err != nil {
					return nil, err
				}
				sw.Issues, sw.Coverage = issues, coverage
			} else {
				sw.Coverage = "no vulnerability data for " + sw.Name + "; its end of life is checked"
			}
			eol, err := c.Intel.EndOfLife(ctx, sw)
			if err != nil {
				return nil, err
			}
			sw.EndOfLife = eol
		}
		if sw.Issues == nil {
			sw.Issues = []Issue{}
		}
		sortIssues(sw.Issues)
		r.Software = append(r.Software, sw)
	}
	r.Summary = summarise(r)
	return r, nil
}

// describeFetchError turns a failed first request into a message for the
// person who asked.
func describeFetchError(target *url.URL, err error) error {
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, netguard.ErrBlocked):
		return fmt.Errorf("%w: %s points to a private or internal address", ErrTarget, target.Hostname())
	case errors.As(err, &dnsErr):
		return fmt.Errorf("%w: %s does not resolve (no DNS record)", ErrTarget, target.Hostname())
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s did not answer in time", target.Hostname())
	}
	if strings.Contains(err.Error(), "protocol version") {
		return fmt.Errorf("%s offers only outdated TLS (1.0 or 1.1), which browsers no longer accept", target.Hostname())
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return fmt.Errorf("%s has a certificate browsers reject: %v", target.Hostname(), cert.Err)
	}
	return fmt.Errorf("could not load %s: %v", target.String(), err)
}

// get fetches u, reading at most limit bytes of the body. partial asks for
// the first bytes only (a Range request; servers may ignore it).
func get(ctx context.Context, client *http.Client, u string, limit int64, partial bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	if partial {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil && len(b) == 0 {
		return nil, nil, err
	}
	return resp, b, nil
}

// found collects software once per name and version.
type found struct {
	mu    sync.Mutex
	seen  map[string]int
	items []Software
}

func newFound() *found { return &found{seen: map[string]int{}} }

func (f *found) add(sw Software) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.ToLower(sw.Ecosystem + "|" + sw.Package + "|" + sw.Name + "|" + sw.Version)
	if _, ok := f.seen[k]; ok {
		return
	}
	f.seen[k] = len(f.items)
	f.items = append(f.items, sw)
}

func (f *found) list() []Software {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]Software(nil), f.items...)
	order := map[string]int{"server": 0, "cms": 1, "library": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if order[out[i].Kind] != order[out[j].Kind] {
			return order[out[i].Kind] < order[out[j].Kind]
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// product is how a name seen in a header or generator tag is matched.
type product struct {
	label, kind, ecosystem, pkg, lifecycle string
}

// products maps the lower-case token a server sends ("nginx" in
// "nginx/1.24.0") to what it is matched as.
var products = map[string]product{
	"nginx":            {"nginx", "server", "vendor", "nginx", "nginx"},
	"openresty":        {"OpenResty", "server", "", "", ""},
	"apache":           {"Apache HTTP Server", "server", "", "", "apache-http-server"},
	"php":              {"PHP", "server", "vendor", "php", "php"},
	"openssl":          {"OpenSSL", "server", "", "", "openssl"},
	"microsoft-iis":    {"Microsoft IIS", "server", "", "", "iis"},
	"asp.net":          {"ASP.NET", "server", "", "", ""},
	"express":          {"Express", "server", "npm", "express", ""},
	"next.js":          {"Next.js", "server", "npm", "next", "nextjs"},
	"tomcat":           {"Apache Tomcat", "server", "", "", "tomcat"},
	"apache-coyote":    {"Apache Tomcat", "server", "", "", ""},
	"jetty":            {"Eclipse Jetty", "server", "", "", "eclipse-jetty"},
	"node.js":          {"Node.js", "server", "vendor", "nodejs", "nodejs"},
	"wordpress":        {"WordPress", "cms", "", "", "wordpress"},
	"drupal":           {"Drupal", "cms", "", "", "drupal"},
	"joomla!":          {"Joomla!", "cms", "", "", "joomla"},
	"joomla":           {"Joomla!", "cms", "", "", "joomla"},
	"typo3":            {"TYPO3", "cms", "", "", "typo3"},
	"ghost":            {"Ghost", "cms", "", "", "ghost"},
	"magento":          {"Magento", "cms", "", "", "magento"},
	"mediawiki":        {"MediaWiki", "cms", "", "", "mediawiki"},
	"x-aspnet-version": {"ASP.NET", "server", "", "", ""},
}

// token is name/version in a Server or X-Powered-By header
// ("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f").
var token = regexp.MustCompile(`(?i)([a-z][a-z0-9._!-]*)/(\d+(?:\.\d+){0,3}[a-z0-9.-]*)`)

// spaced is "Next.js 14.1.0" or "WordPress 6.4.2" (generator tags and some
// X-Powered-By values).
var spaced = regexp.MustCompile(`(?i)^\s*([a-z][a-z0-9._!-]*(?: [a-z][a-z0-9._!-]*)?)\s+v?(\d+(?:\.\d+){0,3})\b`)

func fromHeaders(h http.Header, f *found) {
	for _, name := range []string{"Server", "X-Powered-By"} {
		for _, v := range h.Values(name) {
			ms := token.FindAllStringSubmatch(v, -1)
			if len(ms) == 0 {
				if m := spaced.FindStringSubmatch(v); m != nil {
					ms = [][]string{m}
				}
			}
			for _, m := range ms {
				addProduct(f, m[1], m[2], name+" header")
			}
		}
	}
	if v := strings.TrimSpace(h.Get("X-AspNet-Version")); v != "" {
		addProduct(f, "x-aspnet-version", v, "X-AspNet-Version header")
	}
}

var generatorTag = regexp.MustCompile(`(?is)<meta\s+[^>]*name\s*=\s*["']generator["'][^>]*>`)
var contentAttr = regexp.MustCompile(`(?is)content\s*=\s*["']([^"']+)["']`)

func fromGenerator(body []byte, f *found) {
	for _, tag := range generatorTag.FindAll(body, 5) {
		c := contentAttr.FindSubmatch(tag)
		if c == nil {
			continue
		}
		if m := spaced.FindStringSubmatch(string(c[1])); m != nil {
			addProduct(f, m[1], m[2], "page generator tag")
		}
	}
}

func addProduct(f *found, name, version, where string) {
	p, ok := products[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return
	}
	f.add(Software{Name: p.label, Version: version, Kind: p.kind, Where: where, Ecosystem: p.ecosystem, Package: p.pkg, Lifecycle: p.lifecycle})
}

var scriptSrc = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)
var styleHref = regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']?stylesheet["']?[^>]*>`)
var hrefAttr = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)

// fromScripts reads the first bytes of the scripts and stylesheets the
// page loads (not those already known from their CDN address) for a
// version banner.
func (c *Checker) fromScripts(ctx context.Context, client *http.Client, base *url.URL, body []byte, f *found, r *Report) {
	var refs []string
	for _, m := range scriptSrc.FindAllSubmatch(body, -1) {
		refs = append(refs, string(m[1]))
	}
	for _, tag := range styleHref.FindAll(body, -1) {
		if m := hrefAttr.FindSubmatch(tag); m != nil {
			refs = append(refs, string(m[1]))
		}
	}
	seen := map[string]bool{}
	var todo []*url.URL
	for _, ref := range refs {
		u, err := base.Parse(strings.TrimSpace(ref))
		if err != nil || checkURL(u) != nil {
			continue
		}
		u.Fragment = ""
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		if _, _, ok := apps.ParseCDNURL(u.String()); ok {
			continue // ParsePage has it
		}
		todo = append(todo, u)
	}
	if len(todo) > MaxScripts {
		r.Notes = append(r.Notes, fmt.Sprintf("the page loads %d scripts and stylesheets; the first %d were read", len(todo), MaxScripts))
		todo = todo[:MaxScripts]
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	var mu sync.Mutex
	failed := 0
	for _, u := range todo {
		wg.Add(1)
		go func(u *url.URL) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, head, err := get(ctx, client, u.String(), maxScriptBytes, true)
			if err != nil || resp.StatusCode >= 400 {
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			for _, m := range apps.ParseBanner(path.Base(u.Path), head) {
				f.add(Software{Name: m[0], Version: m[1], Kind: "library", Where: u.String(), Ecosystem: "npm", Package: m[0]})
			}
		}(u)
	}
	wg.Wait()
	if failed > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d of the page's scripts and stylesheets could not be loaded", failed))
	}
}

// headerChecks lists the browser protections a page should send.
func headerChecks(h http.Header, https bool) []HeaderCheck {
	csp := h.Get("Content-Security-Policy")
	checks := []HeaderCheck{
		{Name: "Content-Security-Policy", Present: csp != "", Advice: "limits where scripts may load from, which blunts cross-site scripting"},
		{Name: "X-Content-Type-Options", Present: strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff"),
			Advice: "send nosniff so browsers do not guess file types"},
		{Name: "Clickjacking protection", Present: h.Get("X-Frame-Options") != "" || strings.Contains(strings.ToLower(csp), "frame-ancestors"),
			Advice: "X-Frame-Options or a frame-ancestors policy stops other sites framing yours"},
		{Name: "Referrer-Policy", Present: h.Get("Referrer-Policy") != "", Advice: "keeps full addresses out of other sites' logs"},
	}
	if https {
		checks = append([]HeaderCheck{{Name: "Strict-Transport-Security", Present: h.Get("Strict-Transport-Security") != "",
			Advice: "tells browsers to always use https for this site"}}, checks...)
	}
	for i := range checks {
		if checks[i].Present {
			checks[i].Advice = ""
		}
	}
	return checks
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func rank(s string) int {
	if r, ok := severityRank[strings.ToLower(s)]; ok {
		return r
	}
	return 4
}

func sortIssues(is []Issue) {
	sort.SliceStable(is, func(i, j int) bool {
		if is[i].KnownExploited != is[j].KnownExploited {
			return is[i].KnownExploited
		}
		if rank(is[i].Severity) != rank(is[j].Severity) {
			return rank(is[i].Severity) < rank(is[j].Severity)
		}
		return is[i].Score > is[j].Score
	})
}

func summarise(r *Report) Summary {
	s := Summary{Software: len(r.Software)}
	for _, sw := range r.Software {
		for _, is := range sw.Issues {
			s.Issues++
			switch strings.ToLower(is.Severity) {
			case "critical":
				s.Critical++
			case "high":
				s.High++
			}
			if is.KnownExploited {
				s.KnownExploited++
			}
		}
		if sw.EndOfLife != nil && sw.EndOfLife.Ended {
			s.EndOfLife++
		}
	}
	for _, h := range r.Headers {
		if !h.Present {
			s.HeadersMissing++
		}
	}
	return s
}

// Teaser is what someone who is not signed in sees: the counts, each piece
// of software with how many issues it has, and the single worst issue. The
// issue lists, fixes and advice come with the full report.
type Teaser struct {
	URL       string           `json:"url"`
	Host      string           `json:"host"`
	CheckedAt time.Time        `json:"checked_at"`
	Summary   Summary          `json:"summary"`
	Software  []TeaserSoftware `json:"software"`
	Worst     *Issue           `json:"worst,omitempty"`
	// WorstIn names the software the worst issue is in.
	WorstIn string   `json:"worst_in,omitempty"`
	TLS     *TLSInfo `json:"tls"`
}

// TeaserSoftware is one line of the teaser.
type TeaserSoftware struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Kind      string `json:"kind"`
	Issues    int    `json:"issues"`
	EndOfLife bool   `json:"end_of_life"`
}

// Teaser cuts r down to what an anonymous visitor sees.
func (r *Report) Teaser() Teaser {
	t := Teaser{URL: r.URL, Host: r.Host, CheckedAt: r.CheckedAt, Summary: r.Summary, Software: []TeaserSoftware{}, TLS: r.TLS}
	for _, sw := range r.Software {
		t.Software = append(t.Software, TeaserSoftware{Name: sw.Name, Version: sw.Version, Kind: sw.Kind, Issues: len(sw.Issues),
			EndOfLife: sw.EndOfLife != nil && sw.EndOfLife.Ended})
		if len(sw.Issues) > 0 {
			w := sw.Issues[0]
			if t.Worst == nil || worse(w, *t.Worst) {
				w := Issue{ID: w.ID, Severity: w.Severity, Score: w.Score, KnownExploited: w.KnownExploited}
				t.Worst, t.WorstIn = &w, sw.Name+" "+sw.Version
			}
		}
	}
	return t
}

func worse(a, b Issue) bool {
	if a.KnownExploited != b.KnownExploited {
		return a.KnownExploited
	}
	if rank(a.Severity) != rank(b.Severity) {
		return rank(a.Severity) < rank(b.Severity)
	}
	return a.Score > b.Score
}
