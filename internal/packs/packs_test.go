package packs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

var built = map[string][]byte{}

// TestMain compiles the Java pack and the hostile test pack to WebAssembly.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "packs-test")
	if err != nil {
		panic(err)
	}
	for name, pkg := range map[string]string{"java": "../../packs/java", "evil": "./testdata/evil"} {
		out := filepath.Join(dir, name+".wasm")
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
		if b, err := cmd.CombinedOutput(); err != nil {
			panic(string(b))
		}
		built[name], _ = os.ReadFile(out)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func archive(t *testing.T, name string, m Manifest) *Archive {
	t.Helper()
	raw, _ := json.Marshal(m)
	data, err := (&Archive{ManifestRaw: raw, Wasm: built[name]}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	a, err := ReadArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func manifest(id string) Manifest {
	return Manifest{ABI: pack.ABI, ID: id, Version: "1.0.0", Name: id, Publisher: "acme", License: "MIT",
		Files: []string{"*.txt", "pom.xml"}, PurlTypes: []string{"maven"}, MaxMemoryMB: 64, TimeoutSeconds: 3}
}

func load(t *testing.T, name string) *Loaded {
	t.Helper()
	l, err := Load(context.Background(), archive(t, name, manifest(name)), TrustUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(context.Background()) })
	return l
}

func scan(l *Loaded, file string) ([]string, string, error) {
	obs, cov, err := l.Scan(context.Background(), []pack.File{{Path: "dir/" + file, Content: []byte("x")}})
	var purls []string
	for _, o := range obs {
		purls = append(purls, o.Purl)
	}
	reason := ""
	if len(cov) > 0 {
		reason = cov[0].Scope + " " + cov[0].Reason
	}
	return purls, reason, err
}

func TestJavaPackInSandbox(t *testing.T) {
	l := load(t, "java")
	obs, cov, err := l.Scan(context.Background(), []pack.File{{Path: "pom.xml", Content: []byte(
		`<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.2</version></dependency></dependencies></project>`)}})
	if err != nil || len(obs) != 1 || obs[0].Purl != "pkg:maven/g/a@1.2" || obs[0].Evidence["pack"] != "java@1.0.0" {
		t.Fatalf("java pack: %+v %v", obs, err)
	}
	if len(cov) != 1 || cov[0].Scope != "pack:java:maven:pom.xml" {
		t.Errorf("coverage: %+v", cov)
	}
}

func TestSandboxContainsHostilePacks(t *testing.T) {
	l := load(t, "evil")
	if _, reason, err := scan(l, "escape.txt"); err != nil || !strings.Contains(reason, "file read failed; dial failed") {
		t.Errorf("escape attempt: %q %v", reason, err)
	}
	for file, want := range map[string]string{
		"npm.txt":    "may only report",
		"where.txt":  "was not given",
		"loop.txt":   "ran longer than",
		"memory.txt": "failed",
		"crash.txt":  "failed",
	} {
		if _, _, err := scan(l, file); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", file, want, err)
		}
	}
	// The pack still works after its instances were killed.
	if _, _, err := scan(l, "escape.txt"); err != nil {
		t.Errorf("after failures: %v", err)
	}
}

func TestSignatures(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	k := &Keyring{}
	if err := k.Add("acme", base64.StdEncoding.EncodeToString(pub), false); err != nil {
		t.Fatal(err)
	}

	a := archive(t, "java", manifest("java"))
	if _, err := k.Verify(a); err == nil {
		t.Error("unsigned pack accepted")
	}
	Sign(a, priv)
	data, _ := a.Bytes()
	signed, err := ReadArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if trust, err := k.Verify(signed); err != nil || trust != TrustVerified {
		t.Errorf("valid signature: %s %v", trust, err)
	}

	tampered := *signed
	tampered.Wasm = append(append([]byte{}, signed.Wasm...), 0)
	if _, err := k.Verify(&tampered); err == nil {
		t.Error("tampered module accepted")
	}

	impostor := archive(t, "java", func() Manifest { m := manifest("java"); m.Publisher = "stackurity"; return m }())
	Sign(impostor, priv)
	if _, err := k.Verify(impostor); err == nil || !strings.Contains(err.Error(), "published by") {
		t.Errorf("pack claiming another publisher: %v", err)
	}

	unknown := archive(t, "java", manifest("java"))
	Sign(unknown, otherPriv)
	if _, err := k.Verify(unknown); err == nil || !strings.Contains(err.Error(), "does not trust") {
		t.Errorf("unknown key: %v", err)
	}

	official, err := DefaultKeyring()
	if err != nil || len(official.keys) != 1 {
		t.Fatalf("default keyring: %v", err)
	}
}

func TestManifestValidation(t *testing.T) {
	m := manifest("ok")
	m.Files = []string{"*"}
	m.PurlTypes = []string{"Not A Type"}
	m.ID = "Bad ID"
	err := m.Validate()
	ie, ok := err.(*InvalidError)
	if !ok || len(ie.Problems) != 3 {
		t.Errorf("problems: %v", err)
	}
	if _, err := ReadArchive([]byte("not gzip")); err == nil {
		t.Error("garbage accepted")
	}
}
