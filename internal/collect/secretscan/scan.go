// Package secretscan finds secrets left in files: API keys, tokens, private
// keys and passwords in a repository's tracked files or in the files a
// deployed web application serves to browsers.
//
// A secret's value never leaves the scan: a finding carries the rule, the
// file and line, a masked preview (ghp_…4f2a) and a fingerprint. For a key
// that looks random the fingerprint is the SHA-256 of the value, so the
// same key in several places is one secret; a shorter or guessable value
// (a password) is fingerprinted by where it was found instead, so its hash
// can never be used to guess it.
package secretscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/model"
)

// Exposure says who can read the file a secret was found in.
const (
	// ExposurePublic: a file the web server sends to anyone (a front-end
	// bundle, a source map, a .env in the document root).
	ExposurePublic = "public"
	// ExposureRepository: a file committed to a repository, readable by
	// everyone with access to it and kept in its history.
	ExposureRepository = "repository"
)

// Limits of one scan.
const (
	maxFileSize = 2 << 20  // larger files are skipped (minified bundles are smaller)
	maxBytes    = 96 << 20 // bytes read per scan
	maxFiles    = 20000    // files read per scan
	maxFindings = 500      // findings kept per scan
	sniffSize   = 8 << 10  // a NUL in the first 8 KiB marks a binary file
)

// skipDirs are never entered: other people's code, build caches and
// version control.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true, "bower_components": true,
	"venv": true, ".venv": true, "__pycache__": true, "site-packages": true, ".tox": true, ".cache": true,
	"target": true, ".gradle": true, ".terraform": true,
}

// skipExt: binary and generated formats with nothing to read.
var skipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".svg": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true, ".mp3": true, ".mp4": true, ".webm": true,
	".zip": true, ".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".jar": true,
	".pdf": true, ".exe": true, ".dll": true, ".so": true, ".dylib": true, ".class": true, ".pyc": true, ".o": true,
	".wasm": true, ".lock": true, ".sum": true,
}

// lockfiles hold integrity hashes that look random and are not secrets.
var lockfiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "composer.lock": true, "Gemfile.lock": true,
	"Cargo.lock": true, "poetry.lock": true, "Pipfile.lock": true, "go.sum": true, "pubspec.lock": true, "bun.lockb": true,
	"packages.lock.json": true, "mix.lock": true, "flake.lock": true,
}

// Options says what a scan reads and how its findings are rated.
type Options struct {
	// Exposure of every file read (ExposurePublic or ExposureRepository).
	Exposure string
	// Ignored: slash paths to leave out (git-ignored files and directories,
	// which are not in the repository); nil when unknown.
	Ignored map[string]bool
	// Include, when set, picks the files to read by slash path; the others
	// are skipped. A deployed application reads only what it serves.
	Include func(p string) bool
}

// Scan reads the files below fsys's root and returns what it found. A
// list that is not Complete stopped at a limit or could not read a
// file: a secret it does not list may still be there.
func Scan(ctx context.Context, fsys fs.FS, o Options) *model.SecretList {
	s := &scan{o: o, out: &model.SecretList{Findings: []model.SecretFinding{}, Complete: true}, seen: map[string]bool{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			s.out.Complete = false
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != "." && (skipDirs[d.Name()] || o.Ignored[p]) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || o.Ignored[p] || lockfiles[d.Name()] || skipExt[strings.ToLower(path.Ext(p))] {
			return nil
		}
		if o.Include != nil && !o.Include(p) {
			return nil
		}
		if s.files >= maxFiles || s.bytes >= maxBytes || len(s.out.Findings) >= maxFindings {
			s.out.Complete = false
			return fs.SkipAll
		}
		s.file(fsys, p)
		return nil
	})
	if err != nil {
		s.out.Complete = false
	}
	return s.out
}

type scan struct {
	o     Options
	out   *model.SecretList
	seen  map[string]bool // fingerprint and location
	files int
	bytes int
}

func (s *scan) file(fsys fs.FS, p string) {
	f, err := fsys.Open(p)
	if err != nil {
		s.out.Complete = false
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > maxFileSize {
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		s.out.Complete = false
		return
	}
	if len(data) > maxFileSize {
		return
	}
	s.files++
	s.bytes += len(data)
	if bytes.IndexByte(data[:min(len(data), sniffSize)], 0) >= 0 {
		return // binary
	}
	nth := map[string]int{}
	for _, m := range Find(p, data) {
		if m.Fingerprint == "" {
			nth[m.Rule]++
			m.Fingerprint = Fingerprint(fmt.Sprintf("place\x00%s\x00%s\x00%d", m.Rule, p, nth[m.Rule]))
		}
		key := m.Fingerprint + "\x00" + p
		if s.seen[key] || len(s.out.Findings) >= maxFindings {
			continue
		}
		s.seen[key] = true
		s.out.Findings = append(s.out.Findings, s.rate(p, m))
	}
}

// Match is one secret in one file.
type Match struct {
	Rule  string
	Title string
	Line  int
	// Fingerprint of the value; "" for a weak value, which the caller
	// fingerprints by its place.
	Fingerprint string
	Preview     string
	public      bool
	generic     bool
}

// Find returns the secrets in one file's contents. name is its path, which
// decides whether .env-only rules apply.
func Find(name string, data []byte) []Match {
	env := envFile(path.Base(name))
	var out []Match
	taken := map[string]bool{} // a value found by a specific rule is not reported again by a generic one
	for _, r := range rules {
		if r.envOnly && !env {
			continue
		}
		for _, loc := range r.re.FindAllSubmatchIndex(data, 50) {
			start, end := loc[0], loc[1]
			if n := len(loc); n >= 4 && loc[n-2] >= 0 {
				start, end = loc[n-2], loc[n-1]
			}
			value := string(data[start:end])
			if r.id == "private-key" {
				value = strings.Join(strings.Fields(value), "")
			}
			if taken[value] || allowed(data, start) {
				continue
			}
			if r.generic && (placeholder(value) || entropy(value) < r.minEntropy) {
				continue
			}
			if r.minEntropy > 0 && !r.generic && entropy(value) < r.minEntropy {
				continue
			}
			taken[value] = true
			fp := Fingerprint(value)
			if r.generic && !strong(value) {
				fp = ""
			}
			out = append(out, Match{
				Rule: r.id, Title: r.title, Line: 1 + bytes.Count(data[:start], []byte{'\n'}),
				Fingerprint: fp, Preview: mask(value, r), public: r.public, generic: r.generic,
			})
		}
	}
	return out
}

// Fingerprint identifies a secret without revealing it.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte("stackurity-secret/v1\n" + value))
	return hex.EncodeToString(sum[:])
}

// rate turns a match into a finding: the exposure decides the severity,
// test and example files and keys meant for browsers lower it.
func (s *scan) rate(p string, m Match) model.SecretFinding {
	f := model.SecretFinding{Rule: m.Rule, Title: m.Title, Location: p, Line: m.Line, Fingerprint: m.Fingerprint,
		Preview: m.Preview, Exposure: s.o.Exposure}
	switch {
	case m.public:
		f.Severity = "low"
		f.Note = "usually meant to be in front-end code; check it is restricted to your sites and APIs"
	case testPath(p):
		f.Severity = "low"
		f.Note = "in a test, example or documentation file"
	case s.o.Exposure == ExposurePublic:
		f.Severity = "critical"
		f.Note = "in a file the web server sends to anyone"
	case m.generic:
		f.Severity = "medium"
	default:
		f.Severity = "high"
	}
	return f
}

// allowed: an inline "stackurity:allow" (or gitleaks:allow) on the
// secret's line marks it as known and safe.
func allowed(data []byte, at int) bool {
	ls := bytes.LastIndexByte(data[:at], '\n') + 1
	le := bytes.IndexByte(data[at:], '\n')
	if le < 0 {
		le = len(data) - at
	}
	line := data[ls : at+le]
	return bytes.Contains(line, []byte("stackurity:allow")) || bytes.Contains(line, []byte("gitleaks:allow"))
}

func envFile(name string) bool {
	n := strings.ToLower(name)
	return n == ".env" || strings.HasPrefix(n, ".env.") || strings.HasSuffix(n, ".env") ||
		strings.HasSuffix(n, ".ini") || strings.HasSuffix(n, ".properties") || strings.HasSuffix(n, ".cfg") ||
		strings.HasSuffix(n, ".conf") || n == "credentials"
}

// testPath: tests, fixtures, examples and documentation, where keys are
// usually fake.
func testPath(p string) bool {
	lp := strings.ToLower(p)
	for _, part := range strings.Split(lp, "/") {
		switch part {
		case "test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "testdata", "example", "examples",
			"sample", "samples", "docs", "doc", "mock", "mocks", "__mocks__", "e2e":
			return true
		}
	}
	base := path.Base(lp)
	for _, s := range []string{".test.", ".spec.", "_test.", "example", ".sample", ".dist", "readme"} {
		if strings.Contains(base, s) {
			return true
		}
	}
	return false
}

// placeholder: values that stand in for a secret rather than being one.
func placeholder(v string) bool {
	lv := strings.ToLower(v)
	for _, s := range []string{"example", "sample", "changeme", "change_me", "change-me", "your", "xxxx", "****", "....",
		"placeholder", "dummy", "fake", "redacted", "<", ">", "${", "{{", "%s", "%(", "process.env", "environ", "getenv",
		"env(", "config(", "secret_here", "password", "insert", "replace", "todo", "123456", "abcdef", "test"} {
		if strings.Contains(lv, s) {
			return true
		}
	}
	// An identifier or a path, not a value: letters and underscores only,
	// or a dotted or slashed name.
	letters := true
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || r == '-' || r == '.') {
			letters = false
			break
		}
	}
	return letters
}

// strong: long and random enough that its hash cannot be reversed by
// guessing.
func strong(v string) bool {
	return utf8.RuneCountInString(v) >= 20 && entropy(v) >= 4
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// mask shows what kind of secret it is and its last characters, never
// enough to use it: the vendor prefix and at most 4 characters, and only
// a length for passwords.
func mask(v string, r rule) string {
	n := utf8.RuneCountInString(v)
	if r.generic || r.id == "private-key" {
		return fmt.Sprintf("%d characters", n)
	}
	rs := []rune(v)
	tail := 4
	if n-r.prefix < 16 {
		tail = 2
	}
	if r.prefix+tail >= n {
		return string(rs[:min(r.prefix, n)]) + "…"
	}
	return string(rs[:r.prefix]) + "…" + string(rs[n-tail:])
}
