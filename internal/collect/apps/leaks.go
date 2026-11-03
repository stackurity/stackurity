package apps

// Keys, tokens and passwords written into an application's files
// (internal/collect/leaks). On a server a password in the application's
// configuration is where it belongs; what matters is who else can read
// the file. A file under a directory the web server serves, sent as it is
// rather than run, may be downloaded by anyone.

import (
	"context"
	"os"
	"path"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/model"
)

// executed are the extensions a web server runs instead of sending: PHP.
// Anything else in a document root (.env, .sql, config.php.bak, .js, .py)
// is sent as it is unless the configuration denies it, which the agent
// does not try to work out.
var executed = map[string]bool{".php": true, ".phtml": true, ".php3": true, ".php4": true, ".php5": true, ".php7": true,
	".php8": true, ".phar": true}

// Leaks scans the application at host path dir. Applications inside it
// are left to their own scans. What the scan could not read is in the
// result's Reason, not in the application's coverage: an unread file
// says nothing about its packages.
func (s *Scanner) Leaks(ctx context.Context, dir string) *model.LeakScan {
	dir = path.Clean("/" + dir)
	res := leaks.Dir(ctx, s.path(dir), leaks.Options{Skip: func(rel string) bool { return s.nestedApp(dir, path.Join(dir, rel)) }})
	out := &model.LeakScan{Found: []model.Leak{}, Complete: res.Complete, Reason: res.Reason}
	roots := s.servedRoots()
	for _, l := range res.Leaks {
		l.Path = path.Join(dir, l.Path)
		exposure := ""
		if served(l.Path, roots) {
			exposure = model.ExposureServed
		} else if worldReadable(s.path(l.Path)) {
			exposure = model.ExposureWorldReadable
		}
		leaks.Grade(&l, exposure, true)
		out.Found = append(out.Found, l)
	}
	return out
}

// servedRoots are the directories the web server configuration serves
// (document roots and aliases), read once per host scan.
func (s *Scanner) servedRoots() []string {
	s.servedOnce.Do(func() {
		conf, _ := s.configRoots()
		for _, r := range conf {
			s.served = append(s.served, path.Clean(r.dir))
		}
	})
	return s.served
}

// served reports whether the web server sends the file at host path p as
// it is: it is under a served directory and not run as PHP. Apache denies
// .ht* files (.htpasswd) by default.
func served(p string, roots []string) bool {
	name := path.Base(p)
	if executed[strings.ToLower(path.Ext(name))] || strings.HasPrefix(name, ".ht") {
		return false
	}
	for _, r := range roots {
		if r == "/" {
			continue
		}
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func worldReadable(full string) bool {
	info, err := os.Stat(full)
	return err == nil && info.Mode().Perm()&0o004 != 0
}
