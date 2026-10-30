package apps

// Web server configuration as a list of sites. A plain PHP or HTML site
// has no manifest for discovery to find, and it may live anywhere: Apache's
// DocumentRoot and Alias and nginx's root and alias say where. The
// configuration is a hint list, read leniently: what cannot be read as a
// plain absolute path (a variable, a regular expression, a relative path)
// is skipped, never expanded, and nothing is run.

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Limits on reading web server configuration.
const (
	maxConfFiles     = 256     // configuration files read per run, in total
	maxConfSize      = 1 << 20 // read from each file
	maxIncludeDepth  = 2       // levels of Include/include followed below a top file
	maxConfRoots     = 1000    // document roots taken from configuration
	maxLinkHops      = 16      // links resolved in one configuration file path
	defaultPageBytes = 16 << 10
)

// webServer is one web server's configuration: its top files (globs) and
// the directory relative includes are resolved against.
type webServer struct {
	name   string
	root   string // ServerRoot (Apache) or the configuration prefix (nginx)
	files  []string
	parser func(data string) (roots, includes []string)
}

var webServers = []webServer{
	{name: "apache", root: "/etc/apache2", files: []string{"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*"}, parser: parseApache},
	{name: "apache", root: "/etc/httpd", files: []string{"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf"}, parser: parseApache},
	{name: "nginx", root: "/etc/nginx", files: []string{"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf"}, parser: parseNginx},
}

// systemDirs never hold a site of their own: what Apache or nginx serves
// from them (/usr/share/phpmyadmin, /usr/share/nginx/html, an ACME
// challenge directory under /var/lib) is installed by an OS package, which
// the package database already inventories, or is not code.
var systemDirs = []string{"/usr", "/etc", "/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
	"/libx32", "/tmp", "/snap", "/var/lib", "/var/log", "/var/cache", "/var/tmp", "/var/run", "/var/spool", "/var/mail"}

// configRoot is a document root named by a web server configuration file.
type configRoot struct {
	dir, source string // host paths; source is "nginx:/etc/nginx/sites-enabled/shop"
}

// configRoots reads the document roots Apache and nginx serve. Each file
// is read once, at most maxConfFiles in all and maxConfSize each. The top
// files (sites-enabled/* and the like) are read first, as level 0 even
// when the main file includes them, and includes are followed
// maxIncludeDepth levels below them.
func (s *Scanner) configRoots() []configRoot {
	type item struct {
		ws    webServer
		host  string
		depth int
	}
	var queue []item
	for _, ws := range webServers {
		for _, pattern := range ws.files {
			for _, m := range s.globConf(pattern) {
				queue = append(queue, item{ws, m, 0})
			}
		}
	}
	var out []configRoot
	read := map[string]bool{}
	for files := 0; len(queue) > 0 && files < maxConfFiles && len(out) < maxConfRoots; {
		it := queue[0]
		queue = queue[1:]
		real, ok := s.resolveFile(it.host)
		if !ok || read[real] {
			continue
		}
		read[real] = true
		f, err := openRegular(s.path(real))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxConfSize))
		f.Close()
		if err != nil {
			continue
		}
		files++
		roots, includes := it.ws.parser(string(data))
		for _, r := range roots {
			if len(out) < maxConfRoots {
				out = append(out, configRoot{dir: r, source: it.ws.name + ":" + it.host})
			}
		}
		if it.depth >= maxIncludeDepth {
			continue
		}
		for _, inc := range includes {
			if !path.IsAbs(inc) {
				inc = path.Join(it.ws.root, inc)
			}
			for _, m := range s.globConf(inc) {
				if len(queue) < 4*maxConfFiles {
					queue = append(queue, item{it.ws, m, it.depth + 1})
				}
			}
		}
	}
	return out
}

// globConf lists the files a configuration path or glob names, as host
// paths; a directory stands for the files in it (Apache's Include of a
// directory).
func (s *Scanner) globConf(pattern string) []string {
	matches, _ := filepath.Glob(s.path(path.Clean(pattern)))
	sort.Strings(matches)
	var out []string
	for _, m := range matches {
		host := s.hostPath(m)
		if strings.HasPrefix(path.Base(host), ".") {
			continue // editor backups and the like
		}
		if real, ok := s.resolveFile(host); ok {
			if fi, err := os.Stat(s.path(real)); err == nil && fi.IsDir() {
				entries, _ := os.ReadDir(s.path(real))
				for _, e := range entries {
					if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
						out = append(out, path.Join(host, e.Name()))
					}
				}
				continue
			}
		}
		out = append(out, host)
	}
	return out
}

// resolveFile resolves the links in host path p (sites-enabled/shop ->
// ../sites-available/shop) inside the scanner's root: an absolute link
// target is taken relative to the root, and ".." never climbs above it.
func (s *Scanner) resolveFile(p string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path.Clean("/"+p), "/"), "/")
	cur, hops := "/", 0
	for i := 0; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		next := path.Join(cur, parts[i])
		fi, err := os.Lstat(s.path(next))
		if err != nil {
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", false
		}
		target, err := os.Readlink(s.path(next))
		if err != nil {
			return "", false
		}
		if !path.IsAbs(target) {
			target = path.Join(cur, target)
		}
		parts = append(strings.Split(strings.TrimPrefix(path.Clean(target), "/"), "/"), parts[i+1:]...)
		cur, i = "/", -1
	}
	return cur, true
}

// siteDir checks a document root from configuration: an existing directory
// outside the system directories, not at or above a discovery base, with
// no hidden part, reached without following a link other than a release
// layout's current link (the rule the walk follows). A document root whose
// parent has a manifest (Laravel's or Symfony's public/) is that parent's
// application. One the agent's user may not reach is taken as written:
// its scan reports that it could not be read.
func (s *Scanner) siteDir(dir string, bases []string) (string, bool) {
	if !path.IsAbs(dir) || strings.ContainsAny(dir, "$*?[]{}%\\") {
		return "", false
	}
	dir = path.Clean(dir)
	if dir == "/" || underAny(dir, systemDirs) {
		return "", false
	}
	cur, denied := "/", false
	for _, part := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if strings.HasPrefix(part, ".") {
			return "", false
		}
		next := path.Join(cur, part)
		fi, err := os.Lstat(s.path(next))
		if errors.Is(err, fs.ErrPermission) {
			cur, denied = dir, true
			break
		}
		if err != nil {
			return "", false
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			rel, ok := s.currentRelease(cur)
			if part != "current" || !ok {
				return "", false
			}
			next = rel
		} else if !fi.IsDir() {
			return "", false
		}
		cur = next
	}
	if underAny(cur, systemDirs) {
		return "", false
	}
	for _, b := range bases {
		if cur == b || strings.HasPrefix(b, cur+"/") {
			return "", false // the walk reads the base, one application at a time
		}
	}
	if parent := path.Dir(cur); !denied && parent != "/" && !underAny(parent, systemDirs) && !slices.Contains(bases, parent) && s.marker(parent, markers) != "" {
		return parent, true
	}
	return cur, true
}

// discoverBases returns the existing discovery bases as host paths.
func (s *Scanner) discoverBases() []string {
	var out []string
	for _, pattern := range DiscoverBases {
		bases, _ := filepath.Glob(s.path(pattern))
		sort.Strings(bases)
		for _, b := range bases {
			out = append(out, s.hostPath(b))
		}
	}
	return out
}

// --- Apache

// parseApache returns the DocumentRoot and Alias targets and the
// Include/IncludeOptional arguments of an Apache configuration file.
// Directives are matched without regard to case; lines continue after a
// trailing backslash; a line starting with # is a comment.
func parseApache(data string) (roots, includes []string) {
	lines := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, "\\") + " " + lines[i]
		}
		args := confFields(strings.TrimSpace(line), false)
		if len(args) < 2 || strings.HasPrefix(args[0], "#") {
			continue
		}
		switch strings.ToLower(args[0]) {
		case "documentroot":
			roots = append(roots, args[1])
		case "alias":
			if len(args) >= 3 {
				roots = append(roots, args[2])
			}
		case "include", "includeoptional":
			includes = append(includes, args[1])
		}
	}
	return roots, includes
}

// --- nginx

// parseNginx returns the root and alias arguments and the include globs
// of an nginx configuration file, in any block.
func parseNginx(data string) (roots, includes []string) {
	stmt := []string{}
	for _, tok := range confFields(data, true) {
		if tok != ";" && tok != "{" && tok != "}" {
			stmt = append(stmt, tok)
			continue
		}
		if tok == ";" && len(stmt) == 2 {
			switch stmt[0] {
			case "root", "alias":
				roots = append(roots, stmt[1])
			case "include":
				includes = append(includes, stmt[1])
			}
		}
		stmt = stmt[:0]
	}
	return roots, includes
}

// confFields splits configuration text into words: quotes ("..." or
// '...') group a word and a backslash escapes the next character. With
// nginx set, # starts a comment to the end of the line anywhere outside
// quotes, and ; { } are words of their own.
func confFields(text string, nginx bool) []string {
	var out []string
	var w strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			out = append(out, w.String())
		}
		w.Reset()
		inWord = false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '"' || c == '\'':
			inWord = true
			for i++; i < len(text) && text[i] != c; i++ {
				if text[i] == '\\' && i+1 < len(text) {
					i++
				}
				w.WriteByte(text[i])
			}
		case c == '\\' && i+1 < len(text):
			i++
			w.WriteByte(text[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case nginx && c == '#' && !inWord:
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case nginx && (c == ';' || c == '{' || c == '}'):
			flush()
			out = append(out, string(c))
		default:
			w.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return out
}

// --- helpers

// defaultPage reports whether the index file in dir is a web server's or
// distribution's placeholder page (Debian's and Ubuntu's "Apache2 Default
// Page", Apache's "It works!", nginx's welcome page): a fresh install, not
// a site.
func (s *Scanner) defaultPage(dir, index string) bool {
	f, err := openRegular(s.path(path.Join(dir, index)))
	if err != nil {
		return false
	}
	data, _ := io.ReadAll(io.LimitReader(f, defaultPageBytes))
	f.Close()
	for _, title := range []string{"Apache2 Debian Default Page", "Apache2 Ubuntu Default Page", "Apache2 Default Page",
		"Test Page for the Apache HTTP Server", "Test Page for the HTTP Server", "Welcome to nginx!", "<h1>It works!</h1>"} {
		if bytes.Contains(data, []byte(title)) {
			return true
		}
	}
	return false
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
