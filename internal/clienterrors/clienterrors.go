// Package clienterrors checks, scrubs and fingerprints error reports: errors
// people hit in the dashboard, and 5xx answers from the API
// (docs/install.md#error-reports). Reports are counted per fingerprint on
// this installation and never sent anywhere else.
//
// The browser scrubs what it sends (web/src/clientErrors.ts); everything is
// scrubbed again here, because the endpoint also takes reports from pages
// before sign-in, and nothing a browser sends is trusted.
package clienterrors

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits on one report.
const (
	MaxBody     = 16 << 10 // a request, all reports together
	MaxReports  = 20       // reports in one request (and per page load)
	MaxMessage  = 300
	MaxRoute    = 200
	MaxFrames   = 8
	maxFrameLen = 200
)

// Kinds of report.
const (
	KindClient = "client" // the dashboard
	KindServer = "server" // a 5xx answer or a panic in an API handler
)

// Sources of a client report: what caught it.
var sources = map[string]bool{"api": true, "error": true, "rejection": true, "render": true}

// Report is one report as the browser sends it.
type Report struct {
	Source   string   `json:"source"`
	Route    string   `json:"route"`
	Method   string   `json:"method,omitempty"`
	APIRoute string   `json:"api_route,omitempty"`
	Status   int      `json:"status,omitempty"`
	Code     string   `json:"code,omitempty"`
	Name     string   `json:"name,omitempty"`
	Message  string   `json:"message,omitempty"`
	Stack    []string `json:"stack,omitempty"`
	Version  string   `json:"version,omitempty"`
	Browser  string   `json:"browser,omitempty"`
	PageID   string   `json:"page_id,omitempty"`
}

// Clean is a report after checking and scrubbing: what is stored.
type Clean struct {
	Kind     string   `json:"kind"`
	Source   string   `json:"source,omitempty"`
	Route    string   `json:"route,omitempty"`
	Method   string   `json:"method,omitempty"`
	APIRoute string   `json:"api_route,omitempty"`
	Status   int      `json:"status,omitempty"`
	Code     string   `json:"code,omitempty"`
	Name     string   `json:"name,omitempty"`
	Message  string   `json:"message,omitempty"`
	Stack    []string `json:"stack,omitempty"`
	Version  string   `json:"version,omitempty"`
	Browser  string   `json:"browser,omitempty"`
	PageID   string   `json:"page_id,omitempty"`
}

// TopFrame is the first frame of the stack, or "".
func (c Clean) TopFrame() string {
	if len(c.Stack) == 0 {
		return ""
	}
	return c.Stack[0]
}

// Fingerprint identifies the error: kind, route, API route and method,
// status, code, error name and top frame. The message is left out (it can
// differ for the same fault).
func (c Clean) Fingerprint() string {
	h := sha256.New()
	for _, p := range []string{c.Kind, c.Route, c.Method, c.APIRoute, strconv.Itoa(c.Status), c.Code, c.Name, c.TopFrame()} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

var (
	reMethod  = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$`)
	reCode    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	reName    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.$]{0,63}$`)
	reVersion = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,40}$`)
	reBrowser = regexp.MustCompile(`^[A-Za-z][A-Za-z ]{0,23} [0-9]{1,4}$`)
	rePageID  = regexp.MustCompile(`^[A-Za-z0-9]{8,40}$`)
	// A frame of our own bundle: static/<file>.js:line[:col], after any
	// origin and leading slash are removed.
	reFrame = regexp.MustCompile(`^static/[A-Za-z0-9_.-]{1,100}\.js:[0-9]{1,7}(:[0-9]{1,7})?$`)
	// The content hash Vite adds to a bundle's name (index-Dk3x_a9Q.js).
	reBundleHash = regexp.MustCompile(`-[A-Za-z0-9_-]{6,12}(\.js:)`)
)

// Check validates and scrubs a browser's report. ok is false for a report
// with nothing usable in it; the request is not refused for one bad report.
func Check(r Report) (Clean, bool) {
	c := Clean{Kind: KindClient}
	if !sources[r.Source] {
		return c, false
	}
	c.Source = r.Source
	c.Route = Path(r.Route, ":id")
	if r.Method != "" && reMethod.MatchString(r.Method) {
		c.Method = r.Method
	}
	c.APIRoute = Path(r.APIRoute, "{id}")
	if r.Status >= 100 && r.Status <= 599 {
		c.Status = r.Status
	}
	if reCode.MatchString(r.Code) {
		c.Code = r.Code
	}
	if reName.MatchString(r.Name) {
		c.Name = r.Name
	}
	c.Message = Scrub(r.Message)
	for _, f := range r.Stack {
		if len(c.Stack) == MaxFrames {
			break
		}
		if f = Frame(f); f != "" {
			c.Stack = append(c.Stack, f)
		}
	}
	if reVersion.MatchString(r.Version) {
		c.Version = r.Version
	}
	if reBrowser.MatchString(r.Browser) {
		c.Browser = r.Browser
	}
	if rePageID.MatchString(r.PageID) {
		c.PageID = r.PageID
	}
	if c.Route == "" {
		return c, false
	}
	return c, true
}

// Frame reduces a stack frame to file:line[:col] of our own bundle, without
// the origin or the bundle's content hash, or "" for a frame from anywhere
// else (an extension, another origin's script, eval).
func Frame(f string) string {
	f = strings.TrimSpace(f)
	if len(f) > 2*maxFrameLen {
		return ""
	}
	if i := strings.Index(f, "://"); i >= 0 {
		rest := f[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return ""
		}
		f = rest[j:]
	}
	f = strings.TrimPrefix(f, "/")
	if !reFrame.MatchString(f) {
		return ""
	}
	return reBundleHash.ReplaceAllString(f, "$1")
}

// Path reduces a route or API path to a pattern: no origin, query string or
// fragment, and every segment that looks like an identifier (a number, a
// UUID, a long hex or random string, an email address, a CVE or package
// name with digits and separators) replaced by placeholder. Segments that
// already are parameters (":id", "{id}", "*") are kept.
func Path(p, placeholder string) string {
	p = strings.TrimSpace(p)
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return ""
		}
		p = rest[j:]
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" {
			continue
		}
		if !plainSegment(s) {
			segs[i] = placeholder
		}
	}
	out := strings.Join(segs, "/")
	if len(out) > MaxRoute || !utf8.ValidString(out) {
		return ""
	}
	return out
}

var (
	// A segment of a route people did not type: lower-case words and
	// hyphens or underscores, a few letters with an optional number at
	// the end are not enough to identify anyone. Anything else is
	// replaced.
	rePlainSegment = regexp.MustCompile(`^([a-z][a-z_-]{0,39}[0-9]?|:[A-Za-z_]{1,30}|\{[A-Za-z_]{1,30}\}|\*)$`)
)

func plainSegment(s string) bool { return rePlainSegment.MatchString(s) }

var scrubbers = []struct {
	re   *regexp.Regexp
	with string
}{
	// URLs: keep the path pattern only (no host, query string or ids).
	{regexp.MustCompile(`https?://[^\s"'<>]+`), "[url]"},
	{regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), "[email]"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "[uuid]"},
	// JSON web tokens, well-known key formats (ours, GitHub, Slack,
	// Stripe-style, AWS access keys) and bearer credentials.
	{regexp.MustCompile(`\b(?:stk[a-z]*|ghp|gho|ghs|ghu|github_pat|xox[abpr]|sk|pk|rk|whsec)[_-][A-Za-z0-9_-]{8,}|\bAKIA[A-Z0-9]{12,}`), "[token]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`), "[token]"},
	{regexp.MustCompile(`(?i)\b(bearer|token|secret|password|passwd|api[_-]?key|authorization)\b(\s*[:=]\s*|\s+)\S+`), "$1 [redacted]"},
	// Long random-looking strings: 20 or more letters, digits, _ or -
	// with at least one digit (keys, session ids, hashes).
	{regexp.MustCompile(`\b[A-Za-z0-9_-]*[0-9][A-Za-z0-9_-]*\b`), ""},
	{regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "[ip]"},
	// Values a database error quotes (Key (name)=(acme-prod)) and text in
	// double quotes, which in our messages is what someone typed or named.
	{regexp.MustCompile(`\)=\([^()]*\)`), ")=[value]"},
	{regexp.MustCompile(`"[^"]*"`), `"[text]"`},
	{regexp.MustCompile(`\d{5,}`), "[number]"},
}

// Scrub removes from a message what could identify a person, a customer
// or a secret: URLs, email addresses, UUIDs, tokens, IP addresses, long
// random strings and runs of five or more digits. It truncates to
// MaxMessage characters.
func Scrub(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, s)
	// Truncate first, generously, so the expressions run on bounded input.
	if len(s) > 4*MaxMessage {
		s = s[:4*MaxMessage]
	}
	for _, sc := range scrubbers {
		if sc.with == "" {
			s = sc.re.ReplaceAllStringFunc(s, longRandom)
			continue
		}
		s = sc.re.ReplaceAllString(s, sc.with)
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > MaxMessage {
		r := []rune(s)
		s = string(r[:MaxMessage-1]) + "…"
	}
	return s
}

func longRandom(w string) string {
	if len(w) >= 20 {
		return "[token]"
	}
	return w
}

// Server builds the report for a 5xx answer or a panic in an API handler:
// the route pattern (never the path), the method, status and error code,
// "panic" or "error" with the scrubbed message, and for a panic the frame
// in our own code where it happened.
func Server(method, pattern string, status int, code, name, message, frame, version string) Clean {
	c := Clean{Kind: KindServer, Status: status, Version: version}
	if reMethod.MatchString(method) {
		c.Method = method
	}
	c.APIRoute = Path(pattern, "{id}")
	if reCode.MatchString(code) {
		c.Code = code
	}
	if reName.MatchString(name) {
		c.Name = name
	}
	c.Message = Scrub(message)
	if frame != "" && len(frame) <= maxFrameLen {
		c.Stack = []string{frame}
	}
	if !reVersion.MatchString(version) {
		c.Version = ""
	}
	return c
}

// ServerFrame picks, from a goroutine stack (runtime/debug.Stack), the
// first frame in this module's own code below the panic, as
// path/file.go:line relative to the module, or "".
func ServerFrame(stack []byte, module string) string {
	lines := strings.Split(string(stack), "\n")
	seenPanic := false
	for i := 0; i+1 < len(lines); i++ {
		fn := strings.TrimSpace(lines[i])
		if strings.HasPrefix(fn, "panic(") {
			seenPanic = true
			continue
		}
		if !seenPanic || !strings.HasPrefix(fn, module+"/") {
			continue
		}
		loc := strings.TrimSpace(lines[i+1])
		if j := strings.LastIndex(loc, " +0x"); j >= 0 {
			loc = loc[:j]
		}
		// The file is an absolute path on the build machine: keep it from
		// the module's top-level directory.
		for _, top := range []string{"/internal/", "/cmd/", "/pkg/"} {
			if k := strings.LastIndex(loc, top); k >= 0 {
				return loc[k+1:]
			}
		}
		return ""
	}
	return ""
}
