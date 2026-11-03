package api

import (
	"regexp"
	"strings"
	"testing"
)

// These tests read agent.ps1 as text, so they run where PowerShell does not.
// They check its structure and the order of its safety steps; running it
// needs a Windows host (see docs/install.md, "Windows hosts").

// psCode returns the script without comments and string contents, so that
// checks look at code only. Strings are replaced by ” or "".
func psCode(t *testing.T, src string) string {
	t.Helper()
	var b strings.Builder
	rs := []rune(src)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == '#':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
			b.WriteRune('\n')
		case c == '\'':
			for i++; ; i++ {
				if i >= len(rs) {
					t.Fatal("unterminated single-quoted string")
				}
				if rs[i] == '\'' {
					if i+1 < len(rs) && rs[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			b.WriteString("''")
		case c == '"':
			for i++; ; i++ {
				if i >= len(rs) {
					t.Fatal("unterminated double-quoted string")
				}
				if rs[i] == '`' {
					i++
					continue
				}
				if rs[i] == '"' {
					break
				}
			}
			b.WriteString(`""`)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func TestInstallPowerShellStructure(t *testing.T) {
	src := agentInstallPowerShell
	for i, r := range src {
		if r > 0x7e || (r < 0x20 && r != '\n') {
			t.Fatalf("non-ASCII or control character %U at byte %d: Windows PowerShell 5.1 may read the script in another code page", r, i)
		}
	}
	code := psCode(t, src)
	// Brackets balance (outside strings and comments).
	for _, p := range []string{"{}", "()", "[]"} {
		if o, c := strings.Count(code, p[:1]), strings.Count(code, p[1:]); o != c {
			t.Errorf("%d %q but %d %q", o, p[:1], c, p[1:])
		}
	}
	// The script runs through iex in the person's own window: all of it in
	// one script block, so that its variables stay local and an error
	// stops it, and never `exit`, which would close the window.
	body := strings.TrimSpace(code)
	if !strings.HasPrefix(body, "& {") || !strings.HasSuffix(body, "}") {
		t.Error("the script is not one script block invoked with &")
	}
	if regexp.MustCompile(`(?i)\bexit\b`).MatchString(code) {
		t.Error("the script calls exit, which closes the window it runs in")
	}
	for _, banned := range []string{"Invoke-Expression", "iex", "Set-ExecutionPolicy", "-ExecutionPolicy", "DownloadString", "Start-Process"} {
		if regexp.MustCompile(`(?i)(^|[^\w-])` + regexp.QuoteMeta(banned) + `\b`).MatchString(code) {
			t.Errorf("the script uses %s", banned)
		}
	}
	if !strings.Contains(code, "$ErrorActionPreference = ''") || !strings.Contains(src, "$ErrorActionPreference = 'Stop'") {
		t.Error("errors do not stop the script")
	}
}

// Safety steps, each before the change it protects.
func TestInstallPowerShellSafetySteps(t *testing.T) {
	src := agentInstallPowerShell
	at := func(s string) int {
		t.Helper()
		i := strings.Index(src, s)
		if i < 0 {
			t.Fatalf("the script lacks %q", s)
		}
		return i
	}
	before := func(a, b, why string) {
		t.Helper()
		if at(a) > at(b) {
			t.Errorf("%s: %q comes after %q", why, a, b)
		}
	}
	// Before the checks, the script only sets variables and defines
	// functions; the first command that changes the host comes after the
	// administrator check.
	checks := at("# Checks before anything changes.")
	depth := 0
	for _, line := range strings.Split(psCode(t, src[:checks]), "\n") {
		line = strings.TrimSpace(line)
		top := depth == 1
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if !top || line == "" || line == "}" || strings.HasPrefix(line, "$") || strings.HasPrefix(line, "function ") ||
			strings.HasPrefix(line, "Set-StrictMode ") || strings.HasPrefix(line, "if (-not $Server)") {
			continue
		}
		t.Errorf("a command before the checks: %q", line)
	}
	admin := at("IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	for _, change := range []string{"New-Item", "Invoke-WebRequest -UseBasicParsing", "Copy-Item", "Remove-Item", "Stop-Agent\n", "sc.exe", "icacls.exe", "New-Service", "New-ItemProperty"} {
		if i := strings.Index(src[checks:], change); i >= 0 && checks+i < admin {
			t.Errorf("%s comes before the administrator check", change)
		}
	}
	before("[Environment]::Is64BitProcess", "Invoke-WebRequest -UseBasicParsing", "32-bit PowerShell sees another Program Files")

	// HTTPS, or a local port, or an explicit override.
	at(`$Server -notmatch '^https://'`)
	before("$env:STACKURITY_ALLOW_HTTP -ne '1'", "Invoke-WebRequest -UseBasicParsing", "the URL is checked before downloading")

	// The binary is installed only after its SHA-256 matches the server's.
	before("Get-FileHash -LiteralPath $tmpExe -Algorithm SHA256", "Copy-Item -LiteralPath $tmpExe -Destination $Bin", "checksum before install")
	before("Die 'checksum mismatch: refusing to install'", "Copy-Item -LiteralPath $tmpExe -Destination $Bin", "checksum before install")
	at(`$want -notmatch '^[0-9a-f]{64}$' -or $want -ne $got`)

	// The settings folder is locked to Administrators before the token is
	// written into it, and the token is then readable by the service
	// account and Administrators only.
	before(`"${Admins}:(OI)(CI)F"`, "& $Bin @enrollArgs", "the folder is restricted before enrollment")
	at("$Admins = '*S-1-5-32-544'")
	tokenACL := at(`@($file, '/inheritance:r', '/grant:r', "${Admins}:F", "${Account}:R", '/Q')`)
	if !strings.Contains(src, "foreach ($file in @($Token, $EnvFile))") || tokenACL < at("foreach ($file in @($Token, $EnvFile))") {
		t.Error("the token and agent.env are not given their own ACL")
	}
	// /grant:r on the folder grants nothing to Users or Everyone.
	for _, wide := range []string{"Users", "Everyone", "*S-1-1-0", "*S-1-5-32-545", "*S-1-5-11"} {
		if regexp.MustCompile(`(?i)` + regexp.QuoteMeta(wide) + `:`).MatchString(src) {
			t.Errorf("an ACL grants %s", wide)
		}
	}

	// The service: its own virtual account, minimal privileges, a
	// write-restricted token, restart on failure, started at boot.
	at(`$Account = "NT SERVICE\$ServiceName"`)
	at(`@('config', $ServiceName, 'obj=', $Account, 'start=', 'delayed-auto')`)
	at(`@('privs', $ServiceName, 'SeChangeNotifyPrivilege')`)
	at(`@('sidtype', $ServiceName, 'restricted')`)
	at(`@('failureflag', $ServiceName, '1')`)
	at(`agent --interval 6h`)
	before("$ServiceName, 'obj=', $Account", "Start-Service", "the account is set before the service first starts")
	before(`"${Account}:R"`, "Start-Service", "the service can read its token when it starts")

	// The code is not kept in the session after use.
	at("Remove-Item Env:STACKURITY_ENROLL_CODE")
	// Upgrades: without a code an enrolled host only gets the new binary.
	before("if (-not $enrolled -and -not $Code)", "Invoke-WebRequest -UseBasicParsing", "a missing code is reported before downloading")
	at("Say 'already enrolled; upgrading the agent only'")
	// Uninstall removes the service, the binary and the token.
	at("if ($env:STACKURITY_UNINSTALL -eq '1')")
	at("@('delete', $ServiceName)")
}
