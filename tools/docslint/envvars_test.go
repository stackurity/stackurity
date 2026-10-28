package docslint

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	// envLiteral is a Go string literal that is exactly a variable name, as
	// passed to os.Getenv, os.LookupEnv and the helpers around them (env,
	// envOrFile, readSecretInput). Messages that mention a variable are
	// longer literals and do not match; a prefix ("STACKURITY_SECRET_") ends
	// in an underscore and does not match either.
	envLiteral = regexp.MustCompile(`"(STACKURITY_[A-Z0-9_]*[A-Z0-9])"`)
	// envOrFile reads NAME and NAME_FILE (cmd/stackurity/server.go).
	envOrFileCall = regexp.MustCompile(`envOrFile\("(STACKURITY_[A-Z0-9_]*[A-Z0-9])"\)`)
	// shellVar is a variable a shell script or Docker Compose expands
	// (${STACKURITY_ALLOW_HTTP:-}, ${STACKURITY_PORT:-8080}).
	shellVar = regexp.MustCompile(`\$\{(STACKURITY_[A-Z0-9_]*[A-Z0-9])`)
	// docVar is a variable named in Markdown. "`STACKURITY_X` / `_FILE`" and
	// "`STACKURITY_X` (or `_FILE`)" name STACKURITY_X_FILE too. A name
	// followed by an underscore is a prefix (STACKURITY_OIDC_*) and skipped.
	docVar = regexp.MustCompile("STACKURITY_([A-Z0-9_]*[A-Z0-9])(_?)(`?\\s*(?:/|or|\\(or)\\s*`_FILE`)?")
)

// userSecretPrefix starts the names operators choose for env: secret
// references (internal/secrets.DefaultEnvPrefix), such as
// STACKURITY_SECRET_GITHUB in an example. STACKURITY_SECRET_KEY is a real
// setting and is checked like any other.
const userSecretPrefix = "STACKURITY_SECRET_"

// envReads returns the variables read under the given directories by Go
// code and shell scripts (such as the agent installer the server serves),
// and separately those read only by Go tests.
func envReads(t *testing.T, dirs ...string) (code, tests map[string]bool) {
	t.Helper()
	code, tests = map[string]bool{}, map[string]bool{}
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(repo, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(repo, p)
			if strings.HasSuffix(p, ".sh") {
				for _, m := range shellVar.FindAllStringSubmatch(read(t, rel), -1) {
					code[m[1]] = true
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			src := read(t, rel)
			into := code
			if strings.HasSuffix(p, "_test.go") {
				into = tests
			}
			for _, m := range envLiteral.FindAllStringSubmatch(src, -1) {
				into[m[1]] = true
			}
			for _, m := range envOrFileCall.FindAllStringSubmatch(src, -1) {
				into[m[1]+"_FILE"] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return code, tests
}

// docEnvVars returns the variables the given Markdown files name, each with
// the first file that names it.
func docEnvVars(docs map[string]string) map[string]string {
	out := map[string]string{}
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		for _, m := range docVar.FindAllStringSubmatch(docs[p], -1) {
			if m[2] == "_" {
				continue
			}
			name := "STACKURITY_" + m[1]
			names := []string{name}
			if m[3] != "" {
				names = append(names, name+"_FILE")
			}
			for _, n := range names {
				if _, ok := out[n]; !ok {
					out[n] = p
				}
			}
		}
	}
	return out
}

// TestEnvVarsDocumented fails when the server, agent or CLI reads a
// STACKURITY_* variable that README.md and docs/*.md never name. Variables
// that need no user documentation (test hooks) are listed with a reason in
// env-undocumented.txt; an entry that is now documented, or no longer read,
// fails too, so the list stays short.
func TestEnvVarsDocumented(t *testing.T) {
	code, _ := envReads(t, "cmd", "internal", "plugins", "pkg")
	documented := docEnvVars(userDocs(t))
	exempt := allowlist(t, "env-undocumented.txt", true)
	for _, v := range sorted(code) {
		_, doc := documented[v]
		switch {
		case !doc && !exempt[v]:
			t.Errorf("%s is read by the Go code but not named in README.md or docs/*.md: document it (install.md lists the server's settings), or list it in tools/docslint/env-undocumented.txt with a reason", v)
		case doc && exempt[v]:
			t.Errorf("%s is documented (%s): remove it from tools/docslint/env-undocumented.txt", v, documented[v])
		}
	}
	for v := range exempt {
		if !code[v] {
			t.Errorf("tools/docslint/env-undocumented.txt: %s is no longer read by the Go code; remove it", v)
		}
	}
}

// TestDocumentedEnvVarsExist fails when the documentation, design notes
// included, names a STACKURITY_* variable nothing reads: a setting that was
// renamed or never built. Read means by the Go code (tests included, for the
// test hooks the docs explain), by a shell script, by
// deploy/docker-compose.yml, or by the licensed build (env-external.txt).
func TestDocumentedEnvVarsExist(t *testing.T) {
	code, tests := envReads(t, "cmd", "internal", "plugins", "pkg", "tools", "examples", "deploy")
	compose := map[string]bool{}
	for _, m := range shellVar.FindAllStringSubmatch(read(t, "deploy/docker-compose.yml"), -1) {
		compose[m[1]] = true
	}
	external := allowlist(t, "env-external.txt", true)
	docs := userDocs(t)
	design, err := filepath.Glob(filepath.Join(repo, "docs", "design", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range design {
		rel, _ := filepath.Rel(repo, f)
		docs[filepath.ToSlash(rel)] = read(t, rel)
	}
	documented := docEnvVars(docs)
	for _, v := range sortedKeys(documented) {
		if strings.HasPrefix(v, userSecretPrefix) && !strings.HasPrefix(v, userSecretPrefix+"KEY") {
			continue
		}
		if !code[v] && !tests[v] && !compose[v] && !external[v] {
			t.Errorf("%s names %s, which nothing reads: fix the name or remove it (a variable read only by the licensed build goes in tools/docslint/env-external.txt)", documented[v], v)
		}
	}
	for v := range external {
		if _, ok := documented[v]; !ok {
			t.Errorf("tools/docslint/env-external.txt: %s is not documented any more; remove it", v)
		}
	}
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
