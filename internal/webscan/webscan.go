// Package webscan checks a public website from the outside: it reads the
// pages a visitor's browser would (the home page, pages from the sitemap
// and links), the scripts and stylesheets they load, the response headers,
// the TLS certificate and the domain's email records, and reports what an
// attacker could use. With Options.Owner it also asks for a short list of
// files that should never be served (.env, .git), which is only for a
// site whose owner asked for the check.
package webscan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/stackurity/stackurity/internal/netguard"
)

// Finding is one problem, with what to do about it.
type Finding struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"` // critical, high, medium, low, info
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix"`
	Where    []string `json:"where,omitempty"`
	Refs     []string `json:"refs,omitempty"`
}

// Library is a front-end library the site loads.
type Library struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Source  string   `json:"source"` // "CDN address" or "file banner"
	Where   []string `json:"where"`
	Vulns   []Vuln   `json:"vulns,omitempty"`
}

// Report is the result of one scan.
type Report struct {
	Target       string         `json:"target"`
	Site         string         `json:"site"`
	Domain       string         `json:"domain"`
	StartedAt    time.Time      `json:"started_at"`
	Seconds      float64        `json:"seconds"`
	Grade        string         `json:"grade"`
	Score        int            `json:"score"`
	Counts       map[string]int `json:"counts"`
	Findings     []Finding      `json:"findings"`
	Libraries    []Library      `json:"libraries"`
	Technologies []string       `json:"technologies"`
	Pages        []string       `json:"pages"`
	Assets       int            `json:"assets"`
	SitemapURLs  int            `json:"sitemap_urls"`
	Robots       bool           `json:"robots"`
	Owner        bool           `json:"owner_checks"`
	Requests     int            `json:"requests"`
	TLS          *TLSInfo       `json:"tls,omitempty"`
	Notes        []string       `json:"notes,omitempty"`
}

// TLSInfo describes the certificate and protocol of the home page.
type TLSInfo struct {
	Version  string    `json:"version"`
	Issuer   string    `json:"issuer"`
	Expires  time.Time `json:"expires"`
	DaysLeft int       `json:"days_left"`
	Names    []string  `json:"names"`
}

// Options bounds a scan.
type Options struct {
	// Owner runs the checks for files that should never be served. Only for
	// a site whose owner asked for the check.
	Owner     bool
	MaxPages  int // pages read, home page included (default 20)
	MaxAssets int // scripts and stylesheets read (default 60)
	// Progress receives a short line as each step starts.
	Progress func(string)
}

var rank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// ErrUnreachable means neither https:// nor http:// gave an answer.
var ErrUnreachable = errors.New("site did not answer")

type scan struct {
	ctx    context.Context
	opt    Options
	f      *fetcher
	rep    *Report
	site   *url.URL // scheme and host the home page settled on
	domain string   // registrable domain (example.co.uk)
	// blocked: the home page answered with an error, so most checks saw
	// an error page rather than the site.
	blocked bool

	mu        sync.Mutex
	findings  []Finding
	pages     []*page
	headers   []http.Header // of every page read
	libs      map[string]*Library
	techs     map[string]bool
	assetSeen map[string]bool
}

func (s *scan) progress(format string, a ...any) {
	if s.opt.Progress != nil {
		s.opt.Progress(fmt.Sprintf(format, a...))
	}
}

func (s *scan) add(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, f)
}

func (s *scan) tech(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.techs[t] = true
}

func (s *scan) note(n string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rep.Notes = append(s.rep.Notes, n)
}

// sameSite reports whether u is on the scanned site's registrable domain.
func (s *scan) sameSite(u *url.URL) bool {
	return registrable(u.Hostname()) == s.domain
}

// registrable is host's registrable domain (shop.example.co.uk →
// example.co.uk), or host itself for an IP address or a single label.
func registrable(host string) string {
	host = strings.ToLower(host)
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// Normalize turns what a visitor typed into the address to scan.
func Normalize(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("enter a website address")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("that is not a website address")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http and https addresses can be checked")
	}
	if u.Hostname() == "" || u.User != nil {
		return nil, errors.New("that is not a website address")
	}
	if !strings.Contains(u.Hostname(), ".") {
		return nil, errors.New("enter a public website address, such as example.com")
	}
	if err := netguard.CheckHost(u.Hostname()); err != nil {
		return nil, err
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// Scan checks the site at target.
func Scan(ctx context.Context, target string, opt Options) (*Report, error) {
	if opt.MaxPages <= 0 {
		opt.MaxPages = 20
	}
	if opt.MaxAssets <= 0 {
		opt.MaxAssets = 60
	}
	u, err := Normalize(target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	s := &scan{
		ctx: ctx, opt: opt,
		f:         newFetcher(opt.MaxPages + opt.MaxAssets + 40),
		rep:       &Report{Target: u.String(), StartedAt: time.Now().UTC(), Owner: opt.Owner},
		libs:      map[string]*Library{},
		techs:     map[string]bool{},
		assetSeen: map[string]bool{},
	}

	s.progress("Connecting to %s", u.Host)
	home, err := s.fetchHome(u)
	if err != nil {
		return nil, err
	}
	s.site = &url.URL{Scheme: home.URL.Scheme, Host: home.URL.Host}
	s.rep.Site = s.site.String()
	s.domain = registrable(home.URL.Hostname())
	s.rep.Domain = s.domain
	if home.Status >= 400 {
		s.blocked = true
		s.note(fmt.Sprintf("The home page answered %d. If the site blocks automated visitors (a firewall or bot check), the report covers less than it should.", home.Status))
	}

	// Independent checks run alongside the crawl.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.checkTLS(home) }()
	go func() { defer wg.Done(); s.checkEmailDNS() }()

	s.progress("Reading robots.txt and the sitemap")
	rb, sitemapPages := s.readRobotsAndSitemaps()

	homePage := s.addPage(home)
	s.progress("Reading pages")
	s.crawl(homePage, rb, sitemapPages)

	s.progress("Reading %d scripts and stylesheets", min(s.countAssets(), opt.MaxAssets))
	s.readAssets()

	s.progress("Looking up known vulnerabilities")
	s.checkLibraries()
	s.checkSoftware(home)
	s.checkHeaders(home)
	s.checkCookies()
	s.checkContent()

	if opt.Owner {
		s.progress("Checking for files that should not be public")
		s.checkExposedFiles()
	} else {
		s.note("Only what a browser loads was read. Checks for files that should never be public (.env, .git, backups, phpinfo) run once you verify you own the site.")
	}
	wg.Wait()

	s.finish(time.Since(s.rep.StartedAt))
	return s.rep, nil
}

// fetchHome reads the home page over https, falling back to http.
func (s *scan) fetchHome(u *url.URL) (*response, error) {
	httpsURL := *u
	httpsURL.Scheme = "https"
	r, err := s.f.get(s.ctx, httpsURL.String(), 2<<20)
	if err == nil {
		return r, nil
	}
	if errors.Is(err, netguard.ErrBlocked) || errors.Is(err, netguard.ErrAmbiguousHost) {
		return nil, errors.New("that address is not on the public internet")
	}
	// A slow first answer (a sleeping app, a cold cache) is not a site
	// without HTTPS: try once more before saying so.
	if r, err2 := s.f.get(s.ctx, httpsURL.String(), 2<<20); err2 == nil {
		return r, nil
	}
	httpsErr := err
	httpURL := *u
	httpURL.Scheme = "http"
	r, err = s.f.get(s.ctx, httpURL.String(), 2<<20)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, httpsErr)
	}
	if r.URL.Scheme == "https" {
		// http redirected to https, which works after all; the first
		// failure was something else (a timeout).
		return r, nil
	}
	msg := httpsErr.Error()
	switch {
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate"):
		s.add(Finding{ID: "tls-cert-invalid", Severity: "high", Category: "Encryption",
			Title:  "The HTTPS certificate is not trusted",
			Detail: "Browsers show a full-page warning on https://" + u.Host + ": " + shortErr(msg) + ". Visitors who click through can be intercepted.",
			Fix:    "Install a valid certificate for every name the site answers on (Let's Encrypt is free), including the full chain."})
	default:
		s.add(Finding{ID: "no-https", Severity: "high", Category: "Encryption",
			Title:  "The site does not work over HTTPS",
			Detail: "Everything visitors send and receive, including passwords and form data, travels unencrypted and can be read or changed on the way.",
			Fix:    "Turn on HTTPS with a free Let's Encrypt certificate and redirect http:// to https://."})
	}
	return r, nil
}

func shortErr(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i > 10 {
		s = s[i+2:]
	}
	return s
}

func (s *scan) readRobotsAndSitemaps() (robots, []string) {
	var rb robots
	if r, err := s.f.get(s.ctx, s.site.String()+"/robots.txt", 512<<10); err == nil && r.Status == 200 && !looksHTML(r) {
		rb = parseRobots(r.Body)
		s.rep.Robots = true
	}
	queue := rb.sitemaps
	if len(queue) == 0 {
		queue = []string{s.site.String() + "/sitemap.xml", s.site.String() + "/sitemap_index.xml"}
	}
	var pages []string
	seen := map[string]bool{}
	for read := 0; len(queue) > 0 && read < 5; {
		sm := queue[0]
		queue = queue[1:]
		if seen[sm] {
			continue
		}
		seen[sm] = true
		su, err := url.Parse(sm)
		if err != nil || !s.sameSite(su) {
			continue
		}
		read++
		r, err := s.f.get(s.ctx, sm, 10<<20)
		if err != nil || r.Status != 200 {
			continue
		}
		p, children, ok := parseSitemap(r.Body)
		if !ok {
			continue
		}
		pages = append(pages, p...)
		queue = append(queue, children...)
		if len(pages) > 0 && len(rb.sitemaps) == 0 {
			break // found the default sitemap; no need for the index too
		}
	}
	s.rep.SitemapURLs = len(pages)
	return rb, pages
}

func looksHTML(r *response) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "html") {
		return true
	}
	head := strings.ToLower(string(r.Body[:min(len(r.Body), 512)]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype html")
}

var skipExt = map[string]bool{".pdf": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".svg": true,
	".zip": true, ".gz": true, ".mp4": true, ".mp3": true, ".xml": true, ".json": true, ".css": true, ".js": true, ".ico": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".woff": true, ".woff2": true, ".txt": true}

func (s *scan) addPage(r *response) *page {
	p := parsePage(r.URL, r.Body)
	s.mu.Lock()
	s.pages = append(s.pages, p)
	s.headers = append(s.headers, r.Header)
	s.rep.Pages = append(s.rep.Pages, r.URL.String())
	s.mu.Unlock()
	return p
}

// crawl reads up to MaxPages-1 more pages: spread over the sitemap, then
// links from the home page.
func (s *scan) crawl(home *page, rb robots, sitemap []string) {
	want := s.opt.MaxPages - 1
	seen := map[string]bool{canon(home.URL): true, canon(s.site) + "/": true}
	var pick []string
	consider := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || !s.sameSite(u) || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		if skipExt[strings.ToLower(path.Ext(u.Path))] || !rb.allowed(u.Path) {
			return
		}
		if k := canon(u); !seen[k] {
			seen[k] = true
			pick = append(pick, u.String())
		}
	}
	// Spread the choice over the whole sitemap: blogs list posts first.
	if n := len(sitemap); n > 0 {
		step := max(1, n/want)
		for i := 0; i < n && len(pick) < want; i += step {
			consider(sitemap[i])
		}
	}
	for _, l := range home.Links {
		if len(pick) >= want {
			break
		}
		consider(l.String())
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				r, err := s.f.get(s.ctx, u, 2<<20)
				if err != nil || r.Status >= 400 || !looksHTML(r) {
					continue
				}
				s.addPage(r)
			}
		}()
	}
	for _, u := range pick {
		jobs <- u
	}
	close(jobs)
	wg.Wait()
}

func canon(u *url.URL) string {
	return strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/") + "?" + u.RawQuery
}

func (s *scan) finish(d time.Duration) {
	s.rep.Seconds = d.Round(100 * time.Millisecond).Seconds()
	s.rep.Requests = s.f.count()
	sort.SliceStable(s.findings, func(a, b int) bool { return rank[s.findings[a].Severity] > rank[s.findings[b].Severity] })
	s.rep.Findings = s.findings
	if s.rep.Findings == nil {
		s.rep.Findings = []Finding{}
	}
	s.rep.Counts = map[string]int{}
	score := 100
	worst := 0
	for _, f := range s.findings {
		s.rep.Counts[f.Severity]++
		score -= map[string]int{"critical": 30, "high": 15, "medium": 6, "low": 2}[f.Severity]
		worst = max(worst, rank[f.Severity])
	}
	score = max(score, 0)
	s.rep.Score = score
	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 65:
		grade = "C"
	case score >= 50:
		grade = "D"
	}
	// One serious problem outweighs many good headers.
	if worst == 4 && grade < "D" {
		grade = "D"
	}
	if worst == 4 && score < 50 {
		grade = "F"
	}
	if worst == 3 && grade < "C" {
		grade = "C"
	}
	s.rep.Grade = grade
	for _, l := range s.libs {
		s.rep.Libraries = append(s.rep.Libraries, *l)
	}
	sort.Slice(s.rep.Libraries, func(a, b int) bool {
		la, lb := s.rep.Libraries[a], s.rep.Libraries[b]
		if len(la.Vulns) != len(lb.Vulns) {
			return len(la.Vulns) > len(lb.Vulns)
		}
		return la.Name < lb.Name
	})
	for t := range s.techs {
		s.rep.Technologies = append(s.rep.Technologies, t)
	}
	sort.Strings(s.rep.Technologies)
	if s.rep.Libraries == nil {
		s.rep.Libraries = []Library{}
	}
	if s.rep.Technologies == nil {
		s.rep.Technologies = []string{}
	}
	if s.blocked {
		// The site turned the scanner away; a good grade would mislead.
		s.rep.Grade = "?"
	}
}
