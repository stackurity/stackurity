package confcheck

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Lines any local user can write to the auth log (logger(1)) must not
// count as root logins, and what sshd logged as the address goes into a
// suggested from="…" only when it is an IP address.
func TestRootKeyLoginsOnlySSHD(t *testing.T) {
	backup, _ := pubKey("backup", "backup@nas")
	fp := parseAuthorizedKeys([]byte(backup))[0].Fingerprint
	var log strings.Builder
	for d := 10; d < 14; d++ {
		for i := 0; i < 7; i++ {
			// Forged: the program is the user who ran logger, or the text
			// "sshd[1]: Accepted" sits inside another program's message.
			fmt.Fprintf(&log, "Nov %d 03:%02d:01 web mallory: Accepted publickey for root from 203.0.113.66 port 1 ssh2: ED25519 %s\n", d, i, fp)
			fmt.Fprintf(&log, "Nov %d 03:%02d:02 web mallory: sshd[1]: Accepted publickey for root from 203.0.113.66 port 1 ssh2: ED25519 %s\n", d, i, fp)
			// Forged address: a quote to break out of from="…".
			fmt.Fprintf(&log, `Nov %d 03:%02d:03 web sshd[12]: Accepted publickey for root from 1.2.3.4",command="/tmp/x port 1 ssh2: ED25519 %s`+"\n", d, i, fp)
			fmt.Fprintf(&log, "Nov %d 03:%02d:04 web sshd[12]: Accepted publickey for root from fe80::1%%x\" port 1 ssh2: ED25519 %s\n", d, i, fp)
		}
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/passwd": passwd, "etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n",
		"root/.ssh/authorized_keys": backup + "\n", "var/log/auth.log": log.String()})
	h := &hostFS{Root: root}
	if got := h.rootKeyLogins(); len(got) != 0 {
		t.Errorf("forged lines counted: %+v", got[fp])
	}
	for _, f := range Host(context.Background(), root, nil).Found {
		if f.Rule == RuleSSHKeySingleSource || strings.Contains(f.Fix, "203.0.113.66") || strings.Contains(f.Fix, "/tmp/x") {
			t.Errorf("forged: %+v", f)
		}
	}

	// Real sshd lines, the classic and the ISO timestamp, sshd and
	// OpenSSH 9.8's sshd-session, IPv4 and IPv6.
	log.Reset()
	for d := 10; d < 14; d++ {
		for i := 0; i < 3; i++ {
			fmt.Fprintf(&log, "Nov %d 03:%02d:01 web sshd[1%d]: Accepted publickey for root from 192.0.2.10 port 5%d ssh2: ED25519 %s\n", d, i, i, i, fp)
			fmt.Fprintf(&log, "2026-11-%dT04:%02d:01.123456+00:00 web sshd-session[2%d]: Accepted publickey for root from 192.0.2.10 port 6%d ssh2: ED25519 %s\n", d, i, i, i, fp)
		}
	}
	writeTree(t, root, map[string]string{"var/log/auth.log": log.String()})
	got := byRule(Host(context.Background(), root, nil).Found)[RuleSSHKeySingleSource]
	if len(got) != 1 || !strings.Contains(got[0].Fix, `from="192.0.2.10"`) || !strings.Contains(got[0].Why, "24 logins over") {
		t.Errorf("sshd lines: %+v", got)
	}

	if a := loginAddr("2001:db8::1"); a != "2001:db8::1" {
		t.Errorf("v6: %q", a)
	}
	for _, bad := range []string{`1.2.3.4"`, `1.2.3.4",command="x`, "fe80::1%eth0", "host.example", ""} {
		if a := loginAddr(bad); a != "" {
			t.Errorf("%q accepted as %q", bad, a)
		}
	}
}
