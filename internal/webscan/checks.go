package webscan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/version"
)

// ---- TLS ----------------------------------------------------------------

func (s *scan) checkTLS(home *response) {
	if home.TLS == nil || len(home.TLS.PeerCertificates) == 0 {
		return
	}
	c := home.TLS.PeerCertificates[0]
	days := int(time.Until(c.NotAfter).Hours() / 24)
	info := &TLSInfo{Version: tls.VersionName(home.TLS.Version), Issuer: c.Issuer.CommonName, Expires: c.NotAfter, DaysLeft: days, Names: c.DNSNames}
	if info.Issuer == "" && len(c.Issuer.Organization) > 0 {
		info.Issuer = c.Issuer.Organization[0]
	}
	s.mu.Lock()
	s.rep.TLS = info
	s.mu.Unlock()
	switch {
	case days < 7:
		s.add(Finding{ID: "tls-expiring", Severity: "high", Category: "Encryption",
			Title:  fmt.Sprintf("The HTTPS certificate expires in %d days", days),
			Detail: "When it expires, browsers block the site with a full-page warning.",
			Fix:    "Renew it now, and check why automatic renewal did not run."})
	case days < 21:
		s.add(Finding{ID: "tls-expiring", Severity: "medium", Category: "Encryption",
			Title:  fmt.Sprintf("The HTTPS certificate expires in %d days", days),
			Detail: "Let's Encrypt certificates renew 30 days before expiry; one this close usually means renewal is failing.",
			Fix:    "Check that automatic renewal works (certbot renew --dry-run) or renew by hand."})
	}
	host := home.URL.Hostname()
	port := home.URL.Port()
	if port == "" {
		port = "443"
	}
	if acceptsOldTLS(s.ctx, host, port) {
		fix := "Allow only TLS 1.2 and 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;)."
		if strings.EqualFold(home.Header.Get("Server"), "cloudflare") {
			fix = "The site is behind Cloudflare, which answers TLS itself: in the Cloudflare dashboard, SSL/TLS → Edge Certificates → Minimum TLS Version, choose TLS 1.2."
		}
		s.add(Finding{ID: "tls-old-versions", Severity: "medium", Category: "Encryption",
			Title:  "The server still accepts TLS 1.0 or 1.1",
			Detail: "Both versions have known weaknesses and every current browser has dropped them. PCI DSS and most audits fail a site that accepts them.",
			Fix:    fix})
	}

	// Does http:// send visitors to https://?
	r, err := s.f.getNoFollow(s.ctx, "http://"+home.URL.Host+"/", 64<<10)
	if err == nil {
		loc := r.Header.Get("Location")
		if r.Status < 300 || r.Status >= 400 || !strings.HasPrefix(strings.ToLower(loc), "https://") {
			s.add(Finding{ID: "no-https-redirect", Severity: "medium", Category: "Encryption",
				Title:  "http:// does not redirect to https://",
				Detail: "Visitors who type the address or follow an old link stay on an unencrypted connection.",
				Fix:    "Redirect every http:// request to https:// with a 301."})
		}
	}
}

func acceptsOldTLS(ctx context.Context, host, port string) bool {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := netguard.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	// Certificates are still verified. The server picks the protocol version
	// before its certificate is checked, so a verification error also means
	// it agreed to TLS 1.0/1.1 (an expired certificate is reported separately).
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}) //nolint:gosec // probing whether old versions are accepted is the point
	_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
	err = tc.HandshakeContext(ctx)
	var verr *tls.CertificateVerificationError
	return err == nil || errors.As(err, &verr)
}

// ---- Email (SPF, DMARC) -------------------------------------------------

func (s *scan) checkEmailDNS() {
	// A site on a hosting platform's domain (app.herokuapp.com,
	// shop.myshopify.com) has no email records of its own to fix.
	if _, icann := publicsuffix.PublicSuffix(s.domain); !icann {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	r := net.DefaultResolver
	mx, _ := r.LookupMX(ctx, s.domain)
	sendsMail := len(mx) > 0
	txt, _ := r.LookupTXT(ctx, s.domain)
	var spf string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
		}
	}
	sev := "low"
	if sendsMail {
		sev = "medium"
	}
	switch {
	case spf == "":
		fix := "Publish an SPF record listing the services that send your mail, such as v=spf1 include:_spf.google.com ~all."
		if !sendsMail {
			fix = "The domain receives no mail, so publish v=spf1 -all to say it sends none either."
		}
		s.add(Finding{ID: "no-spf", Severity: sev, Category: "Email",
			Title:  "No SPF record for " + s.domain,
			Detail: "Without SPF, anyone can send email that claims to come from @" + s.domain + ", which is how phishing in your name works.",
			Fix:    fix})
	case strings.Contains(spf, "+all"):
		s.add(Finding{ID: "spf-allows-all", Severity: "high", Category: "Email",
			Title:  "The SPF record allows every server to send as " + s.domain,
			Detail: "The record ends in +all: " + spf,
			Fix:    "End it in ~all or -all."})
	}
	dm, _ := r.LookupTXT(ctx, "_dmarc."+s.domain)
	var dmarc string
	for _, t := range dm {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarc = t
		}
	}
	switch {
	case dmarc == "":
		s.add(Finding{ID: "no-dmarc", Severity: sev, Category: "Email",
			Title:  "No DMARC record for " + s.domain,
			Detail: "DMARC tells receiving mail servers to reject mail that fails SPF and DKIM. Without it, spoofed mail from your domain is usually delivered, and Google and Yahoo throttle bulk senders that have none.",
			Fix:    "Start with v=DMARC1; p=none; rua=mailto:dmarc@" + s.domain + " at _dmarc." + s.domain + ", then move to p=quarantine."})
	case regexp.MustCompile(`(?i)\bp\s*=\s*none\b`).MatchString(dmarc):
		s.add(Finding{ID: "dmarc-none", Severity: "low", Category: "Email",
			Title:  "DMARC only monitors: spoofed mail is still delivered",
			Detail: "The policy is p=none: " + dmarc,
			Fix:    "Once the reports show your own mail passes, change it to p=quarantine and then p=reject."})
	}
}

// ---- Scripts, stylesheets and libraries ---------------------------------

type asset struct {
	url    *url.URL
	script bool
	page   string
}

func (s *scan) assets() []asset {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	var out []asset
	for _, p := range s.pages {
		for _, r := range p.Scripts {
			if k := r.URL.String(); !seen[k] {
				seen[k] = true
				out = append(out, asset{r.URL, true, p.URL.String()})
			}
		}
		for _, r := range p.Styles {
			if k := r.URL.String(); !seen[k] {
				seen[k] = true
				out = append(out, asset{r.URL, false, p.URL.String()})
			}
		}
	}
	return out
}

func (s *scan) countAssets() int { return len(s.assets()) }

func (s *scan) addLib(name, ver, source, where string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := name + "@" + ver
	l := s.libs[k]
	if l == nil {
		l = &Library{Name: name, Version: ver, Source: source}
		s.libs[k] = l
	}
	if len(l.Where) < 5 && !contains(l.Where, where) {
		l.Where = append(l.Where, where)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// leakSeen collects one finding per leaked value.
type leakSeen struct {
	mu sync.Mutex
	by map[string]*Finding
}

func (s *scan) readAssets() {
	all := s.assets()
	ls := &leakSeen{by: map[string]*Finding{}}
	// Leaks in the pages themselves (inline scripts, markup).
	s.mu.Lock()
	pages := append([]*page(nil), s.pages...)
	s.mu.Unlock()
	for _, p := range pages {
		for _, in := range p.Inline {
			s.scanLeaks(ls, "inline.js", p.URL.String(), in)
		}
	}
	jobs := make(chan asset)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				s.readAsset(ls, a)
			}
		}()
	}
	n := 0
	for _, a := range all {
		// A library named by its CDN address needs no download.
		if name, ver, ok := apps.WebLibFromURL(a.url.String()); ok {
			s.addLib(name, ver, "CDN address", a.url.String())
			continue
		}
		if n >= s.opt.MaxAssets {
			continue
		}
		n++
		jobs <- a
	}
	close(jobs)
	wg.Wait()
	s.rep.Assets = len(all)
	for _, f := range ls.by {
		s.add(*f)
	}
}

func (s *scan) readAsset(ls *leakSeen, a asset) {
	own := s.sameSite(a.url)
	limit := int64(8 << 10) // third party: the banner is enough
	if own && a.script {
		limit = 3 << 20
	}
	r, err := s.f.get(s.ctx, a.url.String(), limit)
	if err != nil || r.Status != 200 {
		return
	}
	for _, l := range apps.WebLibsFromBanner(path.Base(a.url.Path), r.Body) {
		s.addLib(l[0], l[1], "file banner", a.url.String())
	}
	if own && a.script {
		s.scanLeaks(ls, path.Base(a.url.Path), a.url.String(), r.Body)
	}
}

func (s *scan) scanLeaks(ls *leakSeen, name, where string, data []byte) {
	if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".mjs") {
		name += ".js" // the rules choose by extension; this is script
	}
	for _, l := range leaks.Scan(name, data) {
		ls.mu.Lock()
		f := ls.by[l.Fingerprint]
		if f == nil {
			f = &Finding{ID: "leak-" + l.Rule, Category: "Leaked keys", Severity: "critical",
				Title:  l.Title + " in public page code",
				Detail: "Anyone who opens the page can read this key" + preview(l.Preview) + ". Whoever has it can use the account it belongs to.",
				Fix:    "Revoke the key now and issue a new one. Keep secret keys on the server; the browser should only ever get a publishable key or a short-lived token."}
			if l.Rule == "google-api-key" {
				f.Severity = "low"
				f.Title = "Google API key in page code"
				f.Detail = "Google browser keys are public by design" + preview(l.Preview) + ", but an unrestricted one can be used by anyone, on your bill."
				f.Fix = "In Google Cloud Console, restrict the key to your site's address (HTTP referrers) and to the APIs the site uses."
			}
			ls.by[l.Fingerprint] = f
		}
		if len(f.Where) < 5 && !contains(f.Where, where) {
			f.Where = append(f.Where, where)
		}
		ls.mu.Unlock()
	}
}

func preview(p string) string {
	if p == "" {
		return ""
	}
	return " (" + p + ")"
}

func (s *scan) checkLibraries() {
	var q [][2]string
	for _, l := range s.libs {
		q = append(q, [2]string{l.Name, l.Version})
	}
	sort.Slice(q, func(a, b int) bool { return q[a][0]+q[a][1] < q[b][0]+q[b][1] })
	vulns, err := npmVulns(s.ctx, q)
	if err != nil {
		s.note("The vulnerability lookup for front-end libraries failed (" + err.Error() + "); libraries are listed without it.")
		return
	}
	for k, vs := range vulns {
		l := s.libs[k]
		if l == nil || len(vs) == 0 {
			continue
		}
		l.Vulns = vs
		fix := ""
		for _, v := range vs {
			if v.Fixed == "" {
				continue
			}
			if fix == "" {
				fix = v.Fixed
			} else if c, err := version.CompareSemver(v.Fixed, fix); err == nil && c > 0 {
				fix = v.Fixed
			}
		}
		var lines, refs []string
		for i, v := range vs {
			if i == 6 {
				lines = append(lines, fmt.Sprintf("and %d more", len(vs)-6))
				break
			}
			id := v.ID
			for _, a := range v.Aliases {
				if strings.HasPrefix(a, "CVE-") {
					id = a
					break
				}
			}
			lines = append(lines, fmt.Sprintf("%s (%s): %s", id, v.Severity, v.Summary))
			refs = append(refs, v.URL)
		}
		fixText := "Upgrade " + l.Name + " to the latest release."
		if fix != "" {
			fixText = "Upgrade " + l.Name + " to " + fix + " or later, which fixes all of these."
		}
		s.add(Finding{ID: "vulnerable-library", Severity: vs[0].Severity, Category: "Outdated software",
			Title:  fmt.Sprintf("%s %s has %d known %s", l.Name, l.Version, len(vs), plural(len(vs), "vulnerability", "vulnerabilities")),
			Detail: strings.Join(lines, "\n"),
			Fix:    fixText, Where: l.Where, Refs: refs})
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---- Server software, CMS -----------------------------------------------

var softwareRe = regexp.MustCompile(`(?i)\b(nginx|apache|php|openresty|microsoft-iis|litespeed|express|asp\.net)[/ ]v?(\d+(?:\.\d+)+)`)

func (s *scan) checkSoftware(home *response) {
	var shown []string
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		v := home.Header.Get(h)
		if v == "" {
			continue
		}
		if strings.EqualFold(h, "Server") && !regexp.MustCompile(`\d`).MatchString(v) {
			s.tech(v) // a product name without version gives little away
			continue
		}
		shown = append(shown, h+": "+v)
		for _, m := range softwareRe.FindAllStringSubmatch(v, -1) {
			prod, ver := strings.ToLower(m[1]), m[2]
			s.tech(m[1] + " " + ver)
			product := map[string]string{"php": "php", "nginx": "nginx", "apache": "apache-http-server"}[prod]
			if product == "" {
				continue
			}
			if cycle, date, eol := eolCycle(s.ctx, product, ver); eol {
				since := ""
				if date != "" {
					since = " since " + date
				}
				s.add(Finding{ID: "eol-" + prod, Severity: "high", Category: "Outdated software",
					Title:  fmt.Sprintf("%s %s is no longer supported", m[1], cycle),
					Detail: fmt.Sprintf("The server says it runs %s %s. That release line has had no security fixes%s, so new vulnerabilities in it stay open.", m[1], ver, since),
					Fix:    "Upgrade to a supported release line.",
					Refs:   []string{"https://endoflife.date/" + product}})
			}
		}
	}
	if len(shown) > 0 {
		s.add(Finding{ID: "version-disclosure", Severity: "low", Category: "Information shown",
			Title:  "The server announces its software and version",
			Detail: strings.Join(shown, "\n") + "\nAttackers use this to pick exploits that match.",
			Fix:    "Hide versions: nginx server_tokens off; Apache ServerTokens Prod; PHP expose_php = Off."})
	}
	s.checkCMS()
}

var (
	wpGenerator = regexp.MustCompile(`(?i)^WordPress (\d+\.\d+(?:\.\d+)?)`)
	drupalGen   = regexp.MustCompile(`(?i)^Drupal (\d+)`)
	wpPlugin    = regexp.MustCompile(`/wp-content/plugins/([a-z0-9_-]+)/`)
	wpTheme     = regexp.MustCompile(`/wp-content/themes/([a-z0-9_-]+)/`)
	verParam    = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
)

func (s *scan) checkCMS() {
	s.mu.Lock()
	pages := append([]*page(nil), s.pages...)
	s.mu.Unlock()
	var wpVersion, generator string
	wp := false
	plugins := map[string]string{} // slug → ?ver
	for _, p := range pages {
		if p.Generator != "" && generator == "" {
			generator = p.Generator
		}
		for _, r := range append(append([]tagRef{}, p.Scripts...), p.Styles...) {
			u := r.URL.String()
			if !s.sameSite(r.URL) {
				continue
			}
			if strings.Contains(u, "/wp-content/") || strings.Contains(u, "/wp-includes/") {
				wp = true
			}
			if m := wpPlugin.FindStringSubmatch(r.URL.Path); m != nil {
				if v := r.URL.Query().Get("ver"); verParam.MatchString(v) && plugins[m[1]] == "" {
					plugins[m[1]] = v
				} else if _, ok := plugins[m[1]]; !ok {
					plugins[m[1]] = ""
				}
			}
			if m := wpTheme.FindStringSubmatch(r.URL.Path); m != nil {
				s.tech("WordPress theme " + m[1])
			}
			if strings.Contains(r.URL.Path, "/wp-includes/") && wpVersion == "" {
				if v := r.URL.Query().Get("ver"); verParam.MatchString(v) && strings.Count(v, ".") >= 1 && !strings.HasPrefix(v, "0.") {
					// wp-includes files carry the WordPress version, except
					// bundled libraries (jQuery) which carry their own.
					if !strings.Contains(r.URL.Path, "jquery") {
						wpVersion = v
					}
				}
			}
		}
	}
	if m := wpGenerator.FindStringSubmatch(generator); m != nil {
		wp, wpVersion = true, m[1]
	}
	if generator != "" {
		s.tech(generator)
	}
	if m := drupalGen.FindStringSubmatch(generator); m != nil {
		if cycle, _, eol := eolCycle(s.ctx, "drupal", m[1]); eol {
			s.add(Finding{ID: "eol-drupal", Severity: "high", Category: "Outdated software",
				Title:  "Drupal " + cycle + " is no longer supported",
				Detail: "The site says it runs Drupal " + m[1] + ", which no longer gets security fixes.",
				Fix:    "Upgrade to a supported Drupal release."})
		}
	}
	if !wp {
		return
	}
	s.tech("WordPress")
	if wpVersion != "" {
		s.tech("WordPress " + wpVersion)
		switch wordpressStatus(s.ctx, wpVersion) {
		case "insecure":
			s.add(Finding{ID: "wordpress-insecure", Severity: "high", Category: "Outdated software",
				Title:  "WordPress " + wpVersion + " has known security problems",
				Detail: "WordPress.org lists " + wpVersion + " as insecure: a later release fixes vulnerabilities in it.",
				Fix:    "Update WordPress from Dashboard → Updates, and turn on automatic minor updates.",
				Refs:   []string{"https://wordpress.org/news/category/security/"}})
		case "outdated":
			s.add(Finding{ID: "wordpress-outdated", Severity: "low", Category: "Outdated software",
				Title:  "WordPress " + wpVersion + " is not the latest release",
				Detail: "It still gets security fixes, but the newest release has more.",
				Fix:    "Update WordPress from Dashboard → Updates."})
		}
		if wpGenerator.MatchString(generator) {
			s.add(Finding{ID: "wordpress-version-shown", Severity: "low", Category: "Information shown",
				Title:  "Pages announce the WordPress version",
				Detail: `Every page carries <meta name="generator" content="` + generator + `">.`,
				Fix:    "Remove it with remove_action('wp_head', 'wp_generator'); in the theme, or a security plugin."})
		}
	}
	slugs := make([]string, 0, len(plugins))
	for p := range plugins {
		slugs = append(slugs, p)
	}
	sort.Strings(slugs)
	var outdated []string
	for i, slug := range slugs {
		s.tech("WordPress plugin " + slug)
		if i >= 15 {
			continue
		}
		v := plugins[slug]
		if v == "" || v == wpVersion {
			continue // ?ver is often the WordPress version, not the plugin's
		}
		latest := wordpressPluginLatest(s.ctx, slug)
		if latest == "" {
			continue
		}
		if c, err := version.CompareGeneric(v, latest); err == nil && c < 0 {
			outdated = append(outdated, fmt.Sprintf("%s %s (latest %s)", slug, v, latest))
		}
	}
	if len(outdated) > 0 {
		s.add(Finding{ID: "wordpress-plugins-outdated", Severity: "medium", Category: "Outdated software",
			Title:  fmt.Sprintf("%d WordPress %s look out of date", len(outdated), plural(len(outdated), "plugin", "plugins")),
			Detail: strings.Join(outdated, "\n") + "\nVersions are read from ?ver= on the plugin's files, which plugins usually set to their own version. Most WordPress break-ins come through plugins.",
			Fix:    "Update plugins from Dashboard → Plugins, and remove the ones you do not use."})
	}
	if len(slugs) > 0 {
		s.note("WordPress plugin vulnerabilities are not matched yet; the report lists plugins that look out of date.")
	}
}

// ---- Headers -------------------------------------------------------------

func (s *scan) checkHeaders(home *response) {
	if home.Status >= 400 {
		return
	}
	h := home.Header
	https := home.URL.Scheme == "https"
	if https {
		hsts := h.Get("Strict-Transport-Security")
		if hsts == "" {
			s.add(Finding{ID: "no-hsts", Severity: "medium", Category: "Security headers",
				Title:  "No HSTS header",
				Detail: "Without Strict-Transport-Security, a visitor's first request can go over plain http, where an attacker on the same network (public Wi-Fi) can intercept it.",
				Fix:    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains"})
		} else if m := regexp.MustCompile(`max-age=(\d+)`).FindStringSubmatch(hsts); m != nil {
			if n, _ := strconv.Atoi(m[1]); n < 15552000 {
				s.add(Finding{ID: "hsts-short", Severity: "low", Category: "Security headers",
					Title:  "HSTS lasts less than six months",
					Detail: "Strict-Transport-Security: " + hsts,
					Fix:    "Raise max-age to 31536000 (one year)."})
			}
		}
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		s.add(Finding{ID: "no-csp", Severity: "low", Category: "Security headers",
			Title:  "No Content-Security-Policy",
			Detail: "A CSP limits which scripts a page may run, so an injected script (XSS) or a compromised third-party script can do much less.",
			Fix:    "Start with Content-Security-Policy-Report-Only listing the script sources you use, then enforce it."})
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		s.add(Finding{ID: "no-frame-protection", Severity: "low", Category: "Security headers",
			Title:  "Other sites can show this site in a frame",
			Detail: "Neither X-Frame-Options nor CSP frame-ancestors is set, so a hostile page can load the site invisibly and trick visitors into clicking (clickjacking).",
			Fix:    "Send X-Frame-Options: SAMEORIGIN, or Content-Security-Policy: frame-ancestors 'self'."})
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		s.add(Finding{ID: "no-nosniff", Severity: "low", Category: "Security headers",
			Title:  "No X-Content-Type-Options: nosniff",
			Detail: "Browsers may guess a file's type and run an uploaded file as a script.",
			Fix:    "Send X-Content-Type-Options: nosniff"})
	}
	if h.Get("Referrer-Policy") == "" {
		s.add(Finding{ID: "no-referrer-policy", Severity: "info", Category: "Security headers",
			Title:  "No Referrer-Policy",
			Detail: "Browsers default to strict-origin-when-cross-origin, which is fine; setting it makes the choice explicit.",
			Fix:    "Send Referrer-Policy: strict-origin-when-cross-origin"})
	}
	if h.Get("Access-Control-Allow-Origin") == "*" && strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
		s.add(Finding{ID: "cors-wildcard-credentials", Severity: "medium", Category: "Security headers",
			Title:  "CORS allows any site with credentials",
			Detail: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
			Fix:    "List the origins that need access instead of *."})
	}
}

// ---- Cookies -------------------------------------------------------------

var sessionCookie = regexp.MustCompile(`(?i)(sess|sid$|^sid|token|auth|login|jwt|remember|logged_in|laravel|connect\.sid|csrftoken)`)

func (s *scan) checkCookies() {
	s.mu.Lock()
	hs := append([]http.Header(nil), s.headers...)
	s.mu.Unlock()
	https := s.site.Scheme == "https"
	seen := map[string]bool{}
	var noSecure, noHTTPOnly, noSameSite []string
	sessionNoSecure := false
	for _, h := range hs {
		for _, c := range (&http.Response{Header: h}).Cookies() {
			if seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			sess := sessionCookie.MatchString(c.Name)
			if https && !c.Secure {
				noSecure = append(noSecure, c.Name)
				sessionNoSecure = sessionNoSecure || sess
			}
			if sess && !c.HttpOnly && !strings.Contains(strings.ToLower(c.Name), "csrf") {
				noHTTPOnly = append(noHTTPOnly, c.Name)
			}
			if sess && c.SameSite == http.SameSiteDefaultMode {
				noSameSite = append(noSameSite, c.Name)
			}
		}
	}
	if len(noSecure) > 0 {
		sev := "low"
		if sessionNoSecure {
			sev = "medium"
		}
		s.add(Finding{ID: "cookie-no-secure", Severity: sev, Category: "Cookies",
			Title:  "Cookies set without the Secure flag",
			Detail: "These cookies can also be sent over plain http, where they can be read: " + strings.Join(noSecure, ", "),
			Fix:    "Set Secure on every cookie (PHP: session.cookie_secure = 1)."})
	}
	if len(noHTTPOnly) > 0 {
		s.add(Finding{ID: "cookie-no-httponly", Severity: "medium", Category: "Cookies",
			Title:  "Session cookies readable by JavaScript",
			Detail: "Without HttpOnly, any injected script can steal these and take over the session: " + strings.Join(noHTTPOnly, ", "),
			Fix:    "Set HttpOnly on session and login cookies (PHP: session.cookie_httponly = 1)."})
	}
	if len(noSameSite) > 0 {
		s.add(Finding{ID: "cookie-no-samesite", Severity: "low", Category: "Cookies",
			Title:  "Session cookies without SameSite",
			Detail: "Browsers default to Lax, but older ones send the cookie with requests from other sites (CSRF): " + strings.Join(noSameSite, ", "),
			Fix:    "Set SameSite=Lax (or Strict) on session cookies."})
	}
}

// ---- Page content: mixed content, forms, SRI, directory listings --------

var staticCDN = regexp.MustCompile(`(?i)^(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com|(stackpath|maxcdn|netdna)\.bootstrapcdn\.com|ajax\.googleapis\.com|cdn\.datatables\.net)$`)

func (s *scan) checkContent() {
	s.mu.Lock()
	pages := append([]*page(nil), s.pages...)
	s.mu.Unlock()
	var activeMixed, passiveMixed, insecureForms, noSRI, listings []string
	add := func(list *[]string, v string) {
		if len(*list) < 8 && !contains(*list, v) {
			*list = append(*list, v)
		}
	}
	for _, p := range pages {
		https := p.URL.Scheme == "https"
		if p.DirListing {
			add(&listings, p.URL.String())
		}
		for _, r := range append(append([]tagRef{}, p.Scripts...), p.Styles...) {
			if https && r.URL.Scheme == "http" {
				add(&activeMixed, r.URL.String())
			}
			if !s.sameSite(r.URL) && !r.Integrity && staticCDN.MatchString(r.URL.Hostname()) {
				add(&noSRI, r.URL.String())
			}
		}
		for _, r := range p.Media {
			if https && r.URL.Scheme == "http" {
				if r.Tag == "iframe" || r.Tag == "object" || r.Tag == "embed" {
					add(&activeMixed, r.URL.String())
				} else {
					add(&passiveMixed, r.URL.String())
				}
			}
		}
		for _, f := range p.Forms {
			if f.Password && (p.URL.Scheme == "http" || f.Action.Scheme == "http") {
				add(&insecureForms, p.URL.String())
			}
		}
	}
	if len(insecureForms) > 0 {
		s.add(Finding{ID: "password-over-http", Severity: "high", Category: "Encryption",
			Title:  "Passwords are sent without encryption",
			Detail: "A login or sign-up form is on an http:// page or posts to an http:// address.",
			Fix:    "Serve the form over https:// and post it to an https:// address.", Where: insecureForms})
	}
	if len(activeMixed) > 0 {
		s.add(Finding{ID: "mixed-content-active", Severity: "medium", Category: "Encryption",
			Title:  "HTTPS pages load scripts or frames over http://",
			Detail: "Browsers block these, which can break the page; where they load, an attacker on the network can replace them.",
			Fix:    "Load them over https://.", Where: activeMixed})
	}
	if len(passiveMixed) > 0 {
		s.add(Finding{ID: "mixed-content-passive", Severity: "low", Category: "Encryption",
			Title:  "HTTPS pages load images or media over http://",
			Detail: "Browsers show the page as not fully secure.",
			Fix:    "Load them over https://.", Where: passiveMixed})
	}
	if len(noSRI) > 0 {
		s.add(Finding{ID: "no-sri", Severity: "low", Category: "Third-party code",
			Title:  "Scripts from public CDNs load without an integrity check",
			Detail: "If the CDN or the package is compromised (as with polyfill.io in 2024), the changed file runs on your pages. A fixed-version CDN file can be pinned with Subresource Integrity.",
			Fix:    `Add integrity="sha384-…" crossorigin="anonymous" to these tags (srihash.org computes the value), or host the files yourself.`, Where: noSRI})
	}
	if len(listings) > 0 {
		s.add(Finding{ID: "directory-listing", Severity: "medium", Category: "Information shown",
			Title:  "Directory listing is on",
			Detail: "The server lists the files in a folder, which can reveal backups and files not meant to be linked.",
			Fix:    "Turn it off (nginx: autoindex off; Apache: Options -Indexes).", Where: listings})
	}
}

// ---- Files that should never be served (owner only) ---------------------

type probe struct {
	path, id, sev, title, fix string
	match                     func(body string) bool
}

var probes = []probe{
	{"/.env", "exposed-env", "critical", "The .env file can be downloaded",
		"Block dotfiles in the web server (nginx: location ~ /\\. { deny all; }), move .env outside the web root, and change every password and key in it.",
		func(b string) bool {
			return regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`).MatchString(b) && !strings.Contains(strings.ToLower(b), "<html")
		}},
	{"/.git/HEAD", "exposed-git", "critical", "The .git folder can be downloaded, with the site's source code and history",
		"Block /.git in the web server or deploy without it, then check the history for passwords and keys and change them.",
		func(b string) bool { return strings.HasPrefix(b, "ref: refs/") }},
	{"/.git/config", "exposed-git", "critical", "The .git folder can be downloaded, with the site's source code and history",
		"Block /.git in the web server or deploy without it, then check the history for passwords and keys and change them.",
		func(b string) bool {
			return strings.Contains(b, "[core]") && !strings.Contains(strings.ToLower(b), "<html")
		}},
	{"/wp-config.php.bak", "exposed-wpconfig-backup", "critical", "A copy of wp-config.php can be downloaded",
		"Delete the copy and change the database password and the keys in it.",
		func(b string) bool { return strings.Contains(b, "DB_PASSWORD") }},
	{"/wp-config.php~", "exposed-wpconfig-backup", "critical", "A copy of wp-config.php can be downloaded",
		"Delete the copy and change the database password and the keys in it.",
		func(b string) bool { return strings.Contains(b, "DB_PASSWORD") }},
	{"/.aws/credentials", "exposed-aws-credentials", "critical", "AWS credentials can be downloaded",
		"Delete the file from the web root and deactivate the keys in AWS IAM now.",
		func(b string) bool { return strings.Contains(b, "aws_access_key_id") }},
	{"/backup.sql", "exposed-db-dump", "critical", "A database dump can be downloaded",
		"Delete it from the web root; treat everything in it, including customer data and password hashes, as leaked.",
		func(b string) bool {
			return strings.Contains(b, "CREATE TABLE") || strings.HasPrefix(b, "-- MySQL dump")
		}},
	{"/dump.sql", "exposed-db-dump", "critical", "A database dump can be downloaded",
		"Delete it from the web root; treat everything in it, including customer data and password hashes, as leaked.",
		func(b string) bool {
			return strings.Contains(b, "CREATE TABLE") || strings.HasPrefix(b, "-- MySQL dump")
		}},
	{"/.htpasswd", "exposed-htpasswd", "high", "The .htpasswd file can be downloaded",
		"Block dotfiles in the web server and change the passwords in it.",
		func(b string) bool {
			return regexp.MustCompile(`(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\})`).MatchString(b)
		}},
	{"/.vscode/sftp.json", "exposed-sftp-config", "high", "An editor's SFTP settings, with the server password, can be downloaded",
		"Delete .vscode from the web root and change the server password.",
		func(b string) bool { return strings.Contains(b, `"host"`) && strings.Contains(b, `"username"`) }},
	{"/phpinfo.php", "exposed-phpinfo", "medium", "A phpinfo() page is public",
		"Delete it: it shows the PHP version, modules, paths and environment variables.",
		func(b string) bool {
			return strings.Contains(b, "phpinfo()") || strings.Contains(b, "PHP Version") && strings.Contains(b, "PHP License")
		}},
	{"/info.php", "exposed-phpinfo", "medium", "A phpinfo() page is public",
		"Delete it: it shows the PHP version, modules, paths and environment variables.",
		func(b string) bool {
			return strings.Contains(b, "phpinfo()") || strings.Contains(b, "PHP Version") && strings.Contains(b, "PHP License")
		}},
	{"/server-status", "exposed-server-status", "medium", "Apache's server-status page is public",
		"Allow it only from localhost (Require local).",
		func(b string) bool { return strings.Contains(b, "Apache Server Status") }},
	{"/.DS_Store", "exposed-ds-store", "low", "A .DS_Store file lists the folder's files",
		"Delete .DS_Store files from the web root and block dotfiles.",
		func(b string) bool { return strings.HasPrefix(b, "\x00\x00\x00\x01Bud1") }},
	{"/docker-compose.yml", "exposed-compose", "medium", "docker-compose.yml can be downloaded",
		"Move it out of the web root: it describes the services behind the site and often their passwords.",
		func(b string) bool { return regexp.MustCompile(`(?m)^services:`).MatchString(b) }},
}

func (s *scan) checkExposedFiles() {
	type hit struct {
		p probe
		u string
	}
	var mu sync.Mutex
	var hits []hit
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, p := range probes {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u := s.site.String() + p.path
			r, err := s.f.get(s.ctx, u, 64<<10)
			if err != nil || r.Status != 200 || r.URL.Path != p.path {
				return
			}
			if p.match(string(r.Body)) {
				mu.Lock()
				hits = append(hits, hit{p, u})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	done := map[string]*Finding{}
	for _, h := range hits {
		if f := done[h.p.id]; f != nil {
			f.Where = append(f.Where, h.u)
			continue
		}
		f := &Finding{ID: h.p.id, Severity: h.p.sev, Category: "Exposed files", Title: h.p.title,
			Detail: "Anyone can download it. The report does not show what is in it.", Fix: h.p.fix, Where: []string{h.u}}
		done[h.p.id] = f
	}
	for _, f := range done {
		s.add(*f)
	}
}
