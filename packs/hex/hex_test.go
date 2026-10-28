package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

// The fixtures are real files from public repositories; testdata/README.md
// says where each one comes from.
func scanFixture(t *testing.T, path string) *pack.Response {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Scan(&pack.Request{Files: []pack.File{{Path: path, Content: data}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func find(out *pack.Response, purl string) *pack.Observation {
	for i := range out.Observations {
		if out.Observations[i].Purl == purl {
			return &out.Observations[i]
		}
	}
	return nil
}

func TestMixLockFormats(t *testing.T) {
	for _, tc := range []struct {
		file     string
		n        int
		want     []string
		coverage string
	}{
		// Mix 1.0: {:hex, :name, "version"}, and a git dependency.
		{"phoenix-1.0.0/mix.lock", 9, []string{"pkg:hex/cowboy@1.0.2", "pkg:hex/plug@1.0.0"}, "partial 1 git dependency"},
		// Mix 1.2-1.5: six elements, no repository.
		{"phoenix-1.2.1/mix.lock", 12, []string{"pkg:hex/plug@1.1.6", "pkg:hex/cowboy@1.0.4"}, "partial 1 git dependency"},
		// Mix 1.6+: eight elements with the repository; git dependencies with
		// options (sparse:, branch:); packages renamed in mix.exs.
		{"plausible/mix.lock", 159, []string{
			"pkg:hex/plug@1.20.3", "pkg:hex/acceptor_pool@1.0.1",
			"pkg:hex/ts_chatterbox@0.16.0", // "chatterbox": {:hex, :ts_chatterbox, ...}
			"pkg:hex/hpack_erl@0.3.0",      // "hpack": {:hex, :hpack_erl, ...}
		}, "partial 11 git dependencies"},
		// A private organisation's package.
		{"private-org/mix.lock", 1, []string{"pkg:hex/renovate_test/private_package@0.1.6"}, "checked"},
	} {
		out := scanFixture(t, tc.file)
		if len(out.Observations) != tc.n {
			t.Errorf("%s: %d packages, want %d", tc.file, len(out.Observations), tc.n)
		}
		for _, p := range tc.want {
			o := find(out, p)
			if o == nil || o.Location != tc.file || o.Confidence != pack.ConfidenceConfirmed || o.Evidence["lockfile"] != "mix.lock" {
				t.Errorf("%s: missing %s: %+v", tc.file, p, o)
			}
		}
		if find(out, "pkg:hex/chatterbox@0.16.0") != nil {
			t.Error("the application name was used instead of the Hex package")
		}
		status, words, _ := strings.Cut(tc.coverage, " ")
		if len(out.Coverage) != 1 || out.Coverage[0].Scope != "hex:"+tc.file || out.Coverage[0].Status != status ||
			!strings.Contains(out.Coverage[0].Reason, words) {
			t.Errorf("%s: coverage %+v, want %s", tc.file, out.Coverage, tc.coverage)
		}
	}
	out := scanFixture(t, "private-org/mix.lock")
	if out.Observations[0].Evidence["repo"] != "hexpm:renovate_test" {
		t.Errorf("private repo evidence: %+v", out.Observations[0].Evidence)
	}
}

func TestMixLockSyntax(t *testing.T) {
	// The older "key" => value form, atoms written as strings, a self-hosted
	// repository, comments and escapes.
	lock := `%{
  # comment
  "a" => {:hex, :"weird-name", "1.0.0", "x", [:mix], [{:b, "~> 1.0", [hex: :b, repo: "hexpm", optional: false]}], "hexpm", "y"},
  "b": {:hex, :b, "1.2.3-rc.1", "x\"y", [:rebar3], [], "my_repo", "z"},
  "c": {:path, "../c"},
  "d": {:unknown_scm, "x"},
}`
	out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "mix.lock", Content: []byte(lock)}}})
	got := []string{}
	for _, o := range out.Observations {
		got = append(got, o.Purl)
	}
	if strings.Join(got, " ") != "pkg:hex/my_repo/b@1.2.3-rc.1 pkg:hex/weird-name@1.0.0" {
		t.Errorf("packages: %v", got)
	}
	if c := out.Coverage[0]; c.Status != "partial" || !strings.Contains(c.Reason, "1 entry was not understood") {
		t.Errorf("coverage: %+v", c)
	}
}

func TestMixLockRejectsBadInput(t *testing.T) {
	for content, want := range map[string]string{
		`%{"a": {:hex, :a, "1.0.0"}`:                        "expected , or }",
		`%{"a": {:hex, :a, "#{System.cmd()}"}}`:             "interpolation",
		`[1, 2]`:                                            "not a map",
		`%{"a": {:hex, :a, "1"}} trailing`:                  "unexpected text",
		strings.Repeat("[", 200) + strings.Repeat("]", 200): "nested too deeply",
	} {
		out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "mix.lock", Content: []byte(content)}}})
		if len(out.Coverage) != 1 || out.Coverage[0].Status != "failed" || !strings.Contains(out.Coverage[0].Reason, want) {
			t.Errorf("%.40q: %+v", content, out.Coverage)
		}
	}
}

func FuzzMixLock(f *testing.F) {
	for _, p := range []string{"phoenix-1.0.0/mix.lock", "plausible/mix.lock", "private-org/mix.lock"} {
		data, _ := os.ReadFile(filepath.Join("testdata", p))
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Scan(&pack.Request{Files: []pack.File{{Path: "mix.lock", Content: data}}})
		if err != nil || len(out.Coverage) != 1 {
			t.Fatalf("%v %+v", err, out)
		}
	})
}
