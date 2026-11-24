package sitecheck

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

	"github.com/stackurity/stackurity/internal/collect/leaks"
)

// Finding is a problem the check saw that is not a software version:
// a leaked key in the page's code, a cookie or form setting, mixed content,
// TLS 1.0/1.1 still accepted, missing email records.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical, high, medium, low
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
	// Where lists up to 8 addresses it was seen at.
	Where []string `json:"where,omitempty"`
}

// Resolver answers the DNS questions of the email checks.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// fetched is a script whose first bytes were read.
type fetched struct {
	url  *url.URL
	head []byte
}

// pageRef is an address the page loads.
type pageRef struct {
	tag       string
	url       *url.URL
	integrity bool
}

// pageInfo is what the page loads and contains, from its HTML.
type pageInfo struct {
	scripts, styles, media []pageRef
	inline                 [][]byte
	passwordForms          []*url.URL // the action of each form with a password field
	title                  string
}

func parsePage(base *url.URL, body []byte) *pageInfo {
	p := &pageInfo{}
	z := html.NewTokenizer(bytes.NewReader(body))
	var inScript, inTitle bool
	var buf bytes.Buffer
	var form *url.URL
	formHasPassword := false
	endForm := func() {
		if form != nil && formHasPassword {
			p.passwordForms = append(p.passwordForms, form)
		}
		form, formHasPassword = nil, false
	}
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			endForm()
			p.title = strings.TrimSpace(p.title)
			return p
		case html.TextToken:
			if inScript {
				buf.Write(z.Text())
			} else if inTitle {
				p.title += string(z.Text())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script":
				if inScript && buf.Len() > 0 {
					p.inline = append(p.inline, bytes.Clone(buf.Bytes()))
				}
				inScript = false
				buf.Reset()
			case "title":
				inTitle = false
			case "form":
				endForm()
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			tag := string(name)
			switch tag {
			case "title":
				inTitle = p.title == ""
			case "form":
				endForm()
				form = resolveRef(base, attrs["action"])
				if form == nil {
					form = base
				}
			case "input":
				formHasPassword = formHasPassword || (form != nil && strings.EqualFold(attrs["type"], "password"))
			default:
				if p.addRef(base, tag, attrs) && tt == html.StartTagToken {
					inScript = true
				}
			}
		}
	}
}

// addRef records what one tag loads. It reports whether the tag is an
// inline script whose text follows.
func (p *pageInfo) addRef(base *url.URL, tag string, attrs map[string]string) bool {
	_, integ := attrs["integrity"]
	switch tag {
	case "script":
		if u := resolveRef(base, attrs["src"]); u != nil {
			p.scripts = append(p.scripts, pageRef{tag, u, integ})
			return false
		}
		return strings.TrimSpace(attrs["src"]) == ""
	case "link":
		if u := resolveRef(base, attrs["href"]); u != nil && strings.Contains(strings.ToLower(attrs["rel"]), "stylesheet") {
			p.styles = append(p.styles, pageRef{tag, u, integ})
		}
	case "img", "iframe", "audio", "video", "source", "embed":
		if u := resolveRef(base, attrs["src"]); u != nil {
			p.media = append(p.media, pageRef{tag: tag, url: u})
		}
	case "object":
		if u := resolveRef(base, attrs["data"]); u != nil {
			p.media = append(p.media, pageRef{tag: tag, url: u})
		}
	}
	return false
}

// resolveRef is ref as an http(s) address, or nil.
func resolveRef(base *url.URL, ref string) *url.URL {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return nil
	}
	u, err := base.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	u.Fragment = ""
	return u
}

// registrable is host's registrable domain (shop.example.co.uk →
// example.co.uk), or host itself when it has none.
func registrable(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func sameSite(a, b *url.URL) bool { return registrable(a.Hostname()) == registrable(b.Hostname()) }

// findingList collects findings, capping each one's Where at 8 entries.
type findingList struct{ items []Finding }

func (fl *findingList) add(f Finding) { fl.items = append(fl.items, f) }

func addWhere(list *[]string, v string) {
	if len(*list) < 8 && !contains(*list, v) {
		*list = append(*list, v)
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// findings runs the checks that read the page already fetched, plus one
// TLS handshake and the domain's SPF and DMARC records.
func (c *Checker) findings(ctx context.Context, final *url.URL, h http.Header, p *pageInfo, heads []fetched) []Finding {
	fl := &findingList{}
	leakFindings(fl, final, p, heads)
	cookieFindings(fl, final, h)
	contentFindings(fl, final, p)
	if final.Scheme == "https" {
		probe := c.OldTLS
		if probe == nil {
			probe = acceptsOldTLS
		}
		if probe(ctx, final) {
			fix := "Allow only TLS 1.2 and 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3;)."
			if strings.EqualFold(h.Get("Server"), "cloudflare") {
				fix = "The site is behind Cloudflare, which answers TLS itself: in the Cloudflare dashboard, SSL/TLS > Edge Certificates > Minimum TLS Version, choose TLS 1.2."
			}
			fl.add(Finding{ID: "tls-old-versions", Severity: "medium", Category: "Encryption",
				Title:  "The server still accepts TLS 1.0 or 1.1",
				Detail: "Both versions have known weaknesses and every current browser has dropped them. PCI DSS and most audits fail a site that accepts them.",
				Fix:    fix})
		}
	}
	c.emailFindings(ctx, fl, final)
	sort.SliceStable(fl.items, func(i, j int) bool { return rank(fl.items[i].Severity) < rank(fl.items[j].Severity) })
	return fl.items
}

// leakFindings looks for keys in the page's inline scripts and in the
// first bytes of the site's own scripts. Only the masked preview is kept.
func leakFindings(fl *findingList, final *url.URL, p *pageInfo, heads []fetched) {
	by := map[string]*Finding{}
	var order []string
	scan := func(name, where string, data []byte) {
		if !strings.HasSuffix(name, ".js") && !strings.HasSuffix(name, ".mjs") {
			name += ".js" // the rules choose by extension; this is script
		}
		for _, l := range leaks.Scan(name, data) {
			f := by[l.Fingerprint]
			if f == nil {
				f = leakFinding(l.Rule, l.Title, l.Preview)
				by[l.Fingerprint] = f
				order = append(order, l.Fingerprint)
			}
			addWhere(&f.Where, where)
		}
	}
	for _, s := range p.inline {
		scan("inline.js", final.String(), s)
	}
	for _, h := range heads {
		if sameSite(h.url, final) && !strings.HasSuffix(strings.ToLower(h.url.Path), ".css") {
			scan(path.Base(h.url.Path), h.url.String(), h.head)
		}
	}
	for _, k := range order {
		fl.add(*by[k])
	}
}

func leakFinding(rule, title, preview string) *Finding {
	if preview != "" {
		preview = " (" + preview + ")"
	}
	if rule == "google-api-key" {
		return &Finding{ID: "leak-" + rule, Severity: "low", Category: "Leaked keys",
			Title:  "Google API key in page code",
			Detail: "Google browser keys are public by design" + preview + ", but an unrestricted one can be used by anyone, on your bill.",
			Fix:    "In Google Cloud Console, restrict the key to your site's address (HTTP referrers) and to the APIs the site uses."}
	}
	return &Finding{ID: "leak-" + rule, Severity: "critical", Category: "Leaked keys",
		Title:  title + " in public page code",
		Detail: "Anyone who opens the page can read this key" + preview + ". Whoever has it can use the account it belongs to.",
		Fix:    "Revoke the key now and issue a new one. Keep secret keys on the server; the browser should only get a publishable key or a short-lived token."}
}

var sessionCookie = regexp.MustCompile(`(?i)(sess|sid$|^sid|token|auth|login|jwt|remember|logged_in|laravel|connect\.sid|csrftoken)`)

// cookieFindings reads the cookies the page sets.
func cookieFindings(fl *findingList, final *url.URL, h http.Header) {
	https := final.Scheme == "https"
	var noSecure, noHTTPOnly, noSameSite []string
	sessionNoSecure := false
	seen := map[string]bool{}
	for _, ck := range (&http.Response{Header: h}).Cookies() {
		if seen[ck.Name] {
			continue
		}
		seen[ck.Name] = true
		sess := sessionCookie.MatchString(ck.Name)
		if https && !ck.Secure {
			noSecure = append(noSecure, ck.Name)
			sessionNoSecure = sessionNoSecure || sess
		}
		if sess && !ck.HttpOnly && !strings.Contains(strings.ToLower(ck.Name), "csrf") {
			noHTTPOnly = append(noHTTPOnly, ck.Name)
		}
		if sess && ck.SameSite == http.SameSiteDefaultMode {
			noSameSite = append(noSameSite, ck.Name)
		}
	}
	if len(noSecure) > 0 {
		sev := "low"
		if sessionNoSecure {
			sev = "medium"
		}
		fl.add(Finding{ID: "cookie-no-secure", Severity: sev, Category: "Cookies",
			Title:  "Cookies set without the Secure flag",
			Detail: "These cookies can also be sent over plain http, where they can be read: " + strings.Join(noSecure, ", "),
			Fix:    "Set Secure on every cookie (PHP: session.cookie_secure = 1)."})
	}
	if len(noHTTPOnly) > 0 {
		fl.add(Finding{ID: "cookie-no-httponly", Severity: "medium", Category: "Cookies",
			Title:  "Session cookies readable by JavaScript",
			Detail: "Without HttpOnly, any injected script can steal these and take over the session: " + strings.Join(noHTTPOnly, ", "),
			Fix:    "Set HttpOnly on session and login cookies (PHP: session.cookie_httponly = 1)."})
	}
	if len(noSameSite) > 0 {
		fl.add(Finding{ID: "cookie-no-samesite", Severity: "low", Category: "Cookies",
			Title:  "Session cookies without SameSite",
			Detail: "Browsers default to Lax, but older ones send the cookie with requests from other sites (CSRF): " + strings.Join(noSameSite, ", "),
			Fix:    "Set SameSite=Lax (or Strict) on session cookies."})
	}
}

// staticCDN are public CDNs that serve fixed-version files, which
// Subresource Integrity can pin.
var staticCDN = regexp.MustCompile(`(?i)^(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com|(stackpath|maxcdn|netdna)\.bootstrapcdn\.com|ajax\.googleapis\.com|cdn\.datatables\.net)$`)

// contentFindings: mixed content, password forms over http, CDN files
// without an integrity check, and a directory listing.
func contentFindings(fl *findingList, final *url.URL, p *pageInfo) {
	https := final.Scheme == "https"
	var active, passive, forms, noSRI []string
	for _, r := range append(append([]pageRef{}, p.scripts...), p.styles...) {
		if https && r.url.Scheme == "http" {
			addWhere(&active, r.url.String())
		}
		if !sameSite(r.url, final) && !r.integrity && staticCDN.MatchString(r.url.Hostname()) {
			addWhere(&noSRI, r.url.String())
		}
	}
	for _, r := range p.media {
		if https && r.url.Scheme == "http" {
			if r.tag == "iframe" || r.tag == "object" || r.tag == "embed" {
				addWhere(&active, r.url.String())
			} else {
				addWhere(&passive, r.url.String())
			}
		}
	}
	for _, action := range p.passwordForms {
		if !https || action.Scheme == "http" {
			addWhere(&forms, action.String())
		}
	}
	if len(forms) > 0 {
		fl.add(Finding{ID: "password-over-http", Severity: "high", Category: "Encryption",
			Title:  "Passwords are sent without encryption",
			Detail: "A login or sign-up form is on an http:// page or posts to an http:// address.",
			Fix:    "Serve the form over https:// and post it to an https:// address.", Where: forms})
	}
	if len(active) > 0 {
		fl.add(Finding{ID: "mixed-content-active", Severity: "medium", Category: "Encryption",
			Title:  "The https page loads scripts or frames over http://",
			Detail: "Browsers block these, which can break the page; where they load, an attacker on the network can replace them.",
			Fix:    "Load them over https://.", Where: active})
	}
	if len(passive) > 0 {
		fl.add(Finding{ID: "mixed-content-passive", Severity: "low", Category: "Encryption",
			Title:  "The https page loads images or media over http://",
			Detail: "Browsers show the page as not fully secure.",
			Fix:    "Load them over https://.", Where: passive})
	}
	if len(noSRI) > 0 {
		fl.add(Finding{ID: "no-sri", Severity: "low", Category: "Third-party code",
			Title:  "Files from public CDNs load without an integrity check",
			Detail: "If the CDN or the package is compromised (as with polyfill.io in 2024), the changed file runs on your pages. A fixed-version CDN file can be pinned with Subresource Integrity.",
			Fix:    `Add integrity="sha384-..." crossorigin="anonymous" to these tags, or host the files yourself.`, Where: noSRI})
	}
	if strings.HasPrefix(p.title, "Index of /") {
		fl.add(Finding{ID: "directory-listing", Severity: "medium", Category: "Information shown",
			Title:  "Directory listing is on",
			Detail: "The server lists the files in a folder, which can reveal backups and files not meant to be linked.",
			Fix:    "Turn it off (nginx: autoindex off; Apache: Options -Indexes).", Where: []string{final.String()}})
	}
}

var dmarcNone = regexp.MustCompile(`(?i)\bp\s*=\s*none\b`)

// emailFindings checks the SPF and DMARC records of the site's registrable
// domain. A site on a hosting platform's domain (app.herokuapp.com) has no
// email records of its own to fix, so it is skipped.
func (c *Checker) emailFindings(ctx context.Context, fl *findingList, final *url.URL) {
	domain := registrable(final.Hostname())
	if _, icann := publicsuffix.PublicSuffix(domain); !icann {
		return
	}
	var r Resolver = net.DefaultResolver
	if c.DNS != nil {
		r = c.DNS
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	mx, _ := r.LookupMX(ctx, domain)
	sev := "low"
	if len(mx) > 0 {
		sev = "medium" // the domain sends or receives mail
	}
	spf := firstWithPrefix(r, ctx, domain, "v=spf1")
	switch {
	case spf == "":
		fix := "Publish an SPF record listing the services that send your mail, such as v=spf1 include:_spf.google.com ~all."
		if len(mx) == 0 {
			fix = "The domain receives no mail, so publish v=spf1 -all to say it sends none either."
		}
		fl.add(Finding{ID: "no-spf", Severity: sev, Category: "Email",
			Title:  "No SPF record for " + domain,
			Detail: "Without SPF, anyone can send email that claims to come from @" + domain + ", which is how phishing in your name works.",
			Fix:    fix})
	case strings.Contains(spf, "+all"):
		fl.add(Finding{ID: "spf-allows-all", Severity: "high", Category: "Email",
			Title:  "The SPF record allows every server to send as " + domain,
			Detail: "The record ends in +all: " + spf,
			Fix:    "End it in ~all or -all."})
	}
	dmarc := firstWithPrefix(r, ctx, "_dmarc."+domain, "v=dmarc1")
	switch {
	case dmarc == "":
		fl.add(Finding{ID: "no-dmarc", Severity: sev, Category: "Email",
			Title:  "No DMARC record for " + domain,
			Detail: "DMARC tells receiving mail servers to reject mail that fails SPF and DKIM. Without it, spoofed mail from your domain is usually delivered.",
			Fix:    "Start with v=DMARC1; p=none; rua=mailto:dmarc@" + domain + " at _dmarc." + domain + ", then move to p=quarantine."})
	case dmarcNone.MatchString(dmarc):
		fl.add(Finding{ID: "dmarc-none", Severity: "low", Category: "Email",
			Title:  "DMARC only monitors: spoofed mail is still delivered",
			Detail: "The policy is p=none: " + dmarc,
			Fix:    "Once the reports show your own mail passes, change it to p=quarantine and then p=reject."})
	}
}

func firstWithPrefix(r Resolver, ctx context.Context, name, prefix string) string {
	txt, _ := r.LookupTXT(ctx, name)
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), prefix) {
			return t
		}
	}
	return ""
}

var (
	wpPlugin = regexp.MustCompile(`/wp-content/plugins/([a-z0-9_-]+)/`)
	verParam = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
)

// wordpressPlugins adds the WordPress plugins the page loads files from,
// with the version in their ?ver= parameter. There is no stored
// vulnerability data for plugins, and the report says so.
func wordpressPlugins(final *url.URL, p *pageInfo, f *found) {
	seen := map[string]bool{}
	for _, r := range append(append([]pageRef{}, p.scripts...), p.styles...) {
		if !sameSite(r.url, final) {
			continue
		}
		m := wpPlugin.FindStringSubmatch(r.url.Path)
		if m == nil || seen[m[1]] {
			continue
		}
		v := r.url.Query().Get("ver")
		if !verParam.MatchString(v) {
			continue
		}
		seen[m[1]] = true
		f.add(Software{Name: m[1], Version: v, Kind: "plugin", Where: r.url.String(),
			Coverage: "WordPress plugin vulnerabilities are not in the stored data; check the plugin's page on wordpress.org for updates"})
	}
}
