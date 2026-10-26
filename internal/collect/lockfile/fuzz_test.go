package lockfile

import (
	"context"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

func parserNames() []string {
	var names []string
	for n := range parsers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// FuzzLockfiles feeds arbitrary content to every lockfile parser. Parsing
// must never panic, and what comes out must make a batch that validates
// (a hostile file may fail to parse, but must not break the whole scan).
func FuzzLockfiles(f *testing.F) {
	names := parserNames()
	seeds := []string{
		`{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}`,
		"a@^1:\n  version \"1.0.0\"\n",
		"__metadata:\n  version: 6\n\"a@npm:1\":\n  version: 1.0.0\n",
		"lockfileVersion: '9.0'\npackages:\n  a@1.0.0: {}\n",
		`{"packages":[{"name":"a/b","version":"1.0.0"}]}`,
		"[[package]]\nname = \"a\"\nversion = \"1.0\"\n",
		`{"default":{"a":{"version":"==1.0"}}}`,
		"a==1.0\n-r other.txt\n--index-url http://x\n",
		"module x\nrequire a v1.0.0\n",
		"GEM\n  specs:\n    a (1.0)\n",
		`{"version":1,"dependencies":{"net8.0":{"A":{"type":"Direct","resolved":"1.0.0"}}}}`,
		"packages:\n  a:\n    version: \"1.0.0\"\n    source: hosted\n",
		"a: &a [*a, *a]\nb: &b [*a, *a, *a, *a]\nc: [*b, *b, *b, *b]\n",
	}
	for i, s := range seeds {
		f.Add(uint8(i), []byte(s))
	}
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		name := names[int(which)%len(names)]
		fsys := fstest.MapFS{"app/" + name: {Data: data}}
		obs, cov, err := ScanWith(context.Background(), fsys, nil)
		if err != nil {
			t.Fatalf("scan error (should be coverage): %v", err)
		}
		b := model.NewBatch(model.Collector{ID: "fuzz", Method: "lockfile"},
			model.AssetRef{Kind: model.AssetRepository, Name: "r", Identifiers: []model.Identifier{{Scheme: "git-url", Value: "x"}}})
		b.Observations, b.Coverage = obs, cov
		if len(obs) > model.MaxObservations {
			return
		}
		if err := b.Validate(); err != nil {
			t.Fatalf("%s: a parse result breaks the batch: %v", name, err)
		}
	})
}

// TestHostileLockfiles: alias bombs, deep nesting, huge values and binary
// junk end as coverage (failed or checked), quickly, never as a panic or a
// batch that cannot be submitted.
func TestHostileLockfiles(t *testing.T) {
	bomb := "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n"
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		bomb += n + ": &" + n + " [*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + "]\n"
		prev = n
	}
	deep := strings.Repeat(`{"dependencies":{"a":`, 5000) + `{"version":"1"}` + strings.Repeat(`}}`, 5000)
	huge := strings.Repeat("x", 3000)
	cases := map[string]string{
		"pnpm-lock.yaml":    "lockfileVersion: '9.0'\n" + bomb + "packages:\n  a@1.0.0: *i\n",
		"pubspec.lock":      bomb + "packages: *i\n",
		"package-lock.json": `{"lockfileVersion":1,"dependencies":` + deep + `}`,
		"composer.lock":     `{"packages":[{"name":"` + huge + `","version":"1.0.0"}]}`,
		"requirements.txt":  huge + "==1.0\n",
		"go.mod":            "module x\nrequire " + huge + " v1.0.0\n",
		"Gemfile.lock":      "GEM\n  specs:\n    " + huge + " (1.0)\n",
		"poetry.lock":       "[[package]]\nname = \"" + huge + "\"\nversion = \"1\"\n",
		"yarn.lock":         "\x00\x01\x02\xff" + huge,
		"Pipfile.lock":      `{"default":{"` + huge + `":{"version":"==1"}}}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			obs, cov, err := ScanWith(context.Background(), fstest.MapFS{name: {Data: []byte(content)}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 10*time.Second {
				t.Errorf("took %s", time.Since(start))
			}
			b := model.NewBatch(model.Collector{ID: "t", Method: "lockfile"},
				model.AssetRef{Kind: model.AssetRepository, Name: "r", Identifiers: []model.Identifier{{Scheme: "git-url", Value: "x"}}})
			b.Observations, b.Coverage = obs, cov
			if err := b.Validate(); err != nil {
				t.Errorf("result cannot be submitted: %v", err)
			}
		})
	}
}
