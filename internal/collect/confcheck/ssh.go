package confcheck

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// SSH access for root. A key in root's authorized_keys with no restriction
// opens a full root shell from anywhere; that is how small teams run their
// own servers, so an administrator's own key is listed as info and never
// alerted on. A key that looks like a CI or deploy key is different: the
// private half lives in a CI system's secrets, where a compromised workflow
// or third-party action can read it (GTIG's November 2026 report: CI
// credentials used to reach servers). Only fingerprints, comments and
// options are read and reported, never the key itself.

// SSH rules.
const (
	RuleSSHRootCIKey        = "ssh-root-key-ci-unrestricted"
	RuleSSHRootKey          = "ssh-root-key-unrestricted"
	RuleSSHKeySingleSource  = "ssh-root-key-no-from"
	RuleSSHUserCIKey        = "ssh-user-key-ci-unrestricted"
	RuleSSHPermitRootLogin  = "ssh-permit-root-login"
	RuleSSHRootPasswordAuth = "ssh-root-password-login"
)

// authKey is one line of an authorized_keys file, without the key.
type authKey struct {
	Line        int
	Options     []string // as written: restrict, command="...", from="..."
	Type        string
	Fingerprint string // SHA256:… as ssh-keygen -l prints it
	Comment     string
}

func (k authKey) has(opt string) bool {
	for _, o := range k.Options {
		name, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(name, opt) {
			return true
		}
	}
	return false
}

// unrestricted: no forced command, no source address and no restrict.
func (k authKey) unrestricted() bool {
	return !k.has("command") && !k.has("from") && !k.has("restrict")
}

// subject names a key without its material.
func (k authKey) subject() string {
	if k.Comment == "" {
		return k.Fingerprint
	}
	return k.Fingerprint + " " + k.Comment
}

// keyTypes are the public key algorithms OpenSSH accepts in
// authorized_keys (with their certificate forms).
var keyTypes = map[string]bool{"ssh-rsa": true, "ssh-dss": true, "ssh-ed25519": true, "ssh-ed448": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true}

func isKeyType(s string) bool {
	return keyTypes[s] || (strings.HasSuffix(s, "-cert-v01@openssh.com") && keyTypes[strings.TrimSuffix(s, "-cert-v01@openssh.com")]) ||
		(strings.HasSuffix(s, "-cert-v01@openssh.com") && keyTypes[strings.TrimSuffix(s, "-cert-v01@openssh.com")+"@openssh.com"])
}

// parseAuthorizedKeys reads an authorized_keys file. Lines it cannot read
// as a key are skipped, as sshd skips them.
func parseAuthorizedKeys(data []byte) []authKey {
	var out []authKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		var opts []string
		first, rest := splitField(l)
		if !isKeyType(first) {
			// Options come first: comma-separated, values in double quotes
			// may hold commas and spaces.
			opts, rest = splitOptions(l)
			first, rest = splitField(rest)
			if !isKeyType(first) {
				continue
			}
		}
		blob, comment := splitField(rest)
		raw, err := base64.StdEncoding.DecodeString(blob)
		if err != nil || len(raw) < 8 {
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, authKey{Line: n, Options: opts, Type: first,
			Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), Comment: clip(strings.TrimSpace(comment), 120)})
	}
	return out
}

// splitField returns the first space-separated field of s and the rest.
func splitField(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

// splitOptions splits the options at the start of an authorized_keys line
// from the rest.
func splitOptions(s string) ([]string, string) {
	var opts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ',' && !inQuote:
			opts = append(opts, cur.String())
			cur.Reset()
		case (c == ' ' || c == '\t') && !inQuote:
			opts = append(opts, cur.String())
			return opts, s[i+1:]
		default:
			cur.WriteByte(c)
		}
	}
	return append(opts, cur.String()), ""
}

// ciWords mark a key's comment as a CI system's or a deployment's.
var ciWords = regexp.MustCompile(`(?i)(github|gitlab|bitbucket|actions|deploy|runner|jenkins|buildkite|circleci|pipeline|travis|drone|teamcity|codebuild|azure-?devops)`)

// ciToken: "ci" as a word of its own (ci@build, gh-ci, ci_deploy), not in
// a name such as lucia or circle.
var ciToken = regexp.MustCompile(`(?i)(^|[^a-z0-9])ci($|[^a-z0-9])`)

func looksCI(comment string) bool {
	return ciWords.MatchString(comment) || ciToken.MatchString(comment)
}

// sshdConfig is what the agent reads of sshd's configuration: the global
// settings (before the first Match block), where the first value given
// wins, as in sshd.
type sshdConfig struct {
	Found bool
	// values by lower-case keyword, with the file and line they came from.
	values map[string]sshdValue
}

type sshdValue struct {
	Value, File string
	Line        int
}

func (c sshdConfig) get(key, def string) sshdValue {
	if v, ok := c.values[key]; ok {
		return v
	}
	return sshdValue{Value: def}
}

// readSSHD reads /etc/ssh/sshd_config and the files it includes.
func (h *hostFS) readSSHD() sshdConfig {
	c := sshdConfig{values: map[string]sshdValue{}}
	data, _ := h.read("/etc/ssh/sshd_config", 1<<20)
	if data == nil {
		return c
	}
	c.Found = true
	h.sshdFile(&c, "/etc/ssh/sshd_config", data, 0)
	return c
}

func (h *hostFS) sshdFile(c *sshdConfig, file string, data []byte, depth int) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		key, val := splitField(strings.Replace(l, "=", " ", 1))
		key = strings.ToLower(key)
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "match":
			return false // the rest applies only to some connections
		case "include":
			if depth > 4 {
				continue
			}
			for _, pat := range strings.Fields(val) {
				if !path.IsAbs(pat) {
					pat = path.Join("/etc/ssh", pat)
				}
				matches, _ := filepath.Glob(h.full(pat))
				sort.Strings(matches)
				for _, m := range matches {
					rel, err := filepath.Rel(h.full("/"), m)
					if err != nil {
						continue
					}
					hp := "/" + filepath.ToSlash(rel)
					if d, _ := h.read(hp, 1<<20); d != nil && !h.sshdFile(c, hp, d, depth+1) {
						return false
					}
				}
			}
		default:
			if _, ok := c.values[key]; !ok {
				c.values[key] = sshdValue{Value: strings.ToLower(val), File: file, Line: n}
			}
		}
	}
	return true
}

// keyFiles are the authorized_keys files of an account, from sshd's
// AuthorizedKeysFile (%h, %u and %% expanded; relative to the home).
func (c sshdConfig) keyFiles(a account) []string {
	spec := c.get("authorizedkeysfile", ".ssh/authorized_keys .ssh/authorized_keys2").Value
	var out []string
	for _, f := range strings.Fields(spec) {
		if f == "none" {
			continue
		}
		f = strings.NewReplacer("%h", a.Home, "%u", a.Name, "%U", fmt.Sprint(a.UID), "%%", "%").Replace(f)
		if !path.IsAbs(f) {
			f = path.Join(a.Home, f)
		}
		out = append(out, path.Clean(f))
	}
	return out
}

// sshAccess reports root's SSH settings and the keys that log in as root
// or, for CI and deploy keys, as any login user.
func (h *hostFS) sshAccess(accounts []account, logins map[string]*keyUse) []model.ConfigFinding {
	cfg := h.readSSHD()
	if !cfg.Found {
		return nil // no OpenSSH server: its key files open nothing
	}
	var out []model.ConfigFinding
	prl := cfg.get("permitrootlogin", "prohibit-password")
	pw := cfg.get("passwordauthentication", "yes")
	if prl.Value == "yes" {
		file := prl.File
		if file == "" {
			file = "/etc/ssh/sshd_config"
		}
		if pw.Value != "no" {
			out = append(out, finding(RuleSSHRootPasswordAuth, model.ConfigSSH, "Root can log in over SSH with a password", "medium",
				file, prl.Line, "PermitRootLogin yes",
				"PermitRootLogin yes with password authentication on (PasswordAuthentication "+pw.Value+
					") lets anyone who guesses or reuses root's password log in as root from anywhere.",
				"Set PermitRootLogin prohibit-password (keys only) in "+file+", then reload sshd."))
		} else {
			out = append(out, finding(RuleSSHPermitRootLogin, model.ConfigSSH, "Root login over SSH is allowed with any method", "medium",
				file, prl.Line, "PermitRootLogin yes",
				"PermitRootLogin yes allows every login method for root: password authentication is off today, but turning it "+
					"on for anyone also opens root to password guessing.",
				"Set PermitRootLogin prohibit-password (keys only) in "+file+", then reload sshd."))
		}
	}
	rootLogin := prl.Value != "no"
	for _, a := range accounts {
		if a.UID == 0 && !rootLogin {
			continue
		}
		for _, f := range cfg.keyFiles(a) {
			data, _ := h.read(f, 1<<20)
			for _, k := range parseAuthorizedKeys(data) {
				if a.UID == 0 && prl.Value == "forced-commands-only" && !k.has("command") {
					continue // sshd refuses this key for root
				}
				if fd, ok := keyFinding(a, f, k, logins[k.Fingerprint]); ok {
					out = append(out, fd)
				}
			}
		}
	}
	return out
}

// keyFinding grades one authorized key of account a.
func keyFinding(a account, file string, k authKey, use *keyUse) (model.ConfigFinding, bool) {
	root := a.UID == 0
	ci := looksCI(k.Comment)
	fromLine := ""
	singleSource := use != nil && root && !k.has("from") && use.single()
	if singleSource {
		fromLine = `from="` + use.onlyIP() + `"`
	}
	join := func(opts ...string) string {
		var keep []string
		for _, o := range opts {
			if o != "" {
				keep = append(keep, o)
			}
		}
		return strings.Join(keep, ",")
	}
	switch {
	case root && ci && k.unrestricted():
		fix := "Prefix the key's line in " + file + " with " + join(`restrict,command="/usr/local/sbin/deploy"`, fromLine) +
			" so it can run only the deployment, or give CI its own non-root user."
		return finding(RuleSSHRootCIKey, model.ConfigSSH, "CI or deploy key has an unrestricted root shell", "medium", file, k.Line, k.subject(),
			fmt.Sprintf("A key whose comment (%q) marks it as a CI or deploy key opens a full root shell with no command or source "+
				"restriction: anyone who reads the CI secret, or a compromised action in the workflow that holds it, owns this server.", k.Comment),
			fix), true
	case singleSource:
		return finding(RuleSSHKeySingleSource, model.ConfigSSH, "Root key used from one address has no from= limit", "medium", file, k.Line, k.subject(),
			fmt.Sprintf("Every root login with this key in the server's log came from %s (%d logins over %d days), but the key "+
				"works from anywhere: whoever copies it can use it from any address.", use.onlyIP(), use.count, len(use.days)),
			"Prefix the key's line in "+file+" with "+fromLine+" (and restrict,command=\"...\" if it runs one task)."), true
	case root && k.unrestricted():
		return finding(RuleSSHRootKey, model.ConfigSSH, "Root key with no restrictions", "info", file, k.Line, k.subject(),
			"This key opens a full root shell from any address. That is normal for an administrator's own key on a small team; "+
				"it is listed so you know which keys can log in as root.",
			`If the key is used from one place, add from="<address>"; if it runs one task, add restrict,command="<script>".`), true
	case !root && ci && k.unrestricted():
		return finding(RuleSSHUserCIKey, model.ConfigSSH, "CI or deploy key has a full shell", "info", file, k.Line, k.subject(),
			fmt.Sprintf("A CI or deploy key (%q) opens a full shell as %s with no command or source restriction; what that "+
				"account can do (sudo, the application's files) is open to anyone who reads the CI secret.", k.Comment, a.Name),
			"Prefix the key's line in "+file+` with restrict,command="<deploy script>" so it can run only the deployment.`), true
	}
	return model.ConfigFinding{}, false
}

// keyUse is where a key logged in from, from the server's log.
type keyUse struct {
	ips   map[string]int
	days  map[string]bool
	count int
}

// minSingleSource are how many logins, over how many days, must all come
// from one address before a missing from= is reported: an administrator
// who logs in a few times from home is not a pattern.
const (
	minSingleSourceLogins = 20
	minSingleSourceDays   = 3
)

func (u *keyUse) single() bool {
	return len(u.ips) == 1 && u.count >= minSingleSourceLogins && len(u.days) >= minSingleSourceDays
}

func (u *keyUse) onlyIP() string {
	for ip := range u.ips {
		return ip
	}
	return ""
}

// acceptedRE is sshd's log line for a key login:
// "Nov 17 03:00:01 web sshd[123]: Accepted publickey for root from 203.0.113.5 port 52314 ssh2: ED25519 SHA256:…".
// The program field must be sshd (or OpenSSH 9.8's sshd-session) with its
// process ID, right after the timestamp and the host name: a line any user
// can write with logger(1) carries their own name there, and "Accepted
// publickey" further into a message is not sshd's.
var acceptedRE = regexp.MustCompile(`^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ sshd(?:-session)?\[\d+\]: ` +
	`Accepted publickey for (\S+) from (\S+) port \d+ \S+: \S+ (SHA256:[A-Za-z0-9+/]{43})`)

// loginAddr is the address of an accepted login, or "" when it is not a
// plain IP address: what is reported, and put into a suggested from="…",
// is only ever a parsed address.
func loginAddr(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return ""
	}
	return a.Unmap().String()
}

// maxAuthLog bounds how much of each log is read: its most recent part.
const maxAuthLog = 16 << 20

// rootKeyLogins reads sshd's logins as root from the system log
// (/var/log/auth.log on Debian and Ubuntu, /var/log/secure on Red Hat),
// by key fingerprint. Hosts that log only to the journal give none, and
// the from= check is skipped.
func (h *hostFS) rootKeyLogins() map[string]*keyUse {
	out := map[string]*keyUse{}
	for _, p := range []string{"/var/log/auth.log.1", "/var/log/auth.log", "/var/log/secure.1", "/var/log/secure"} {
		data := h.tail(p, maxAuthLog)
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			l := sc.Text()
			m := acceptedRE.FindStringSubmatch(l)
			if m == nil || m[1] != "root" {
				continue
			}
			ip := loginAddr(m[2])
			if ip == "" {
				continue
			}
			u := out[m[3]]
			if u == nil {
				u = &keyUse{ips: map[string]int{}, days: map[string]bool{}}
				out[m[3]] = u
			}
			u.ips[ip]++
			u.count++
			u.days[logDay(l)] = true
		}
	}
	return out
}

// logDay is the day a syslog line was written: "Nov 17" or "2026-11-17".
func logDay(l string) string {
	if len(l) >= 10 && l[4] == '-' && l[7] == '-' {
		return l[:10]
	}
	if len(l) >= 6 {
		return strings.Join(strings.Fields(l[:6]), " ")
	}
	return ""
}

// tail reads the last limit bytes of a host file, from the start of a
// line; nil when it cannot be read.
func (h *hostFS) tail(p string, limit int64) []byte {
	f, err := h.open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := readTail(f, limit)
	if err != nil {
		return nil
	}
	return data
}
