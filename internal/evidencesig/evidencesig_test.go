package evidencesig

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var when = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type packOpts struct {
	signer      *Signer
	editFile    bool // change a file after the manifest was made
	editMan     bool // change manifest.json after it was signed
	dropSig     bool
	extra       bool
	generatedAt time.Time
}

// pack builds an evidence-pack-shaped ZIP.
func pack(t *testing.T, o packOpts) []byte {
	t.Helper()
	files := map[string][]byte{"findings.csv": []byte("id,severity\n1,high\n"), "pack.json": []byte(`{"schema_version":2}`)}
	m := Manifest{SchemaVersion: 2, GeneratedAt: when}
	if !o.generatedAt.IsZero() {
		m.GeneratedAt = o.generatedAt
	}
	for _, name := range []string{"findings.csv", "pack.json"} {
		h := sha256.Sum256(files[name])
		m.Files = append(m.Files, ManifestFile{Path: name, SHA256: hex.EncodeToString(h[:]), Bytes: int64(len(files[name]))})
	}
	if o.signer != nil {
		m.Signed, m.KeyID = true, o.signer.KeyID()
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	var sig []byte
	if o.signer != nil {
		sig, _ = json.Marshal(o.signer.Sign(mb))
	}
	if o.editFile {
		files["findings.csv"] = []byte("id,severity\n1,low\n")
	}
	if o.editMan {
		mb = bytes.Replace(mb, []byte(`"schema_version": 2`), []byte(`"schema_version": 3`), 1)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name string, b []byte) {
		w, _ := zw.Create(name)
		_, _ = w.Write(b)
	}
	for _, name := range []string{"findings.csv", "pack.json"} {
		put(name, files[name])
	}
	if o.extra {
		put("extra.txt", []byte("slipped in"))
	}
	put(ManifestName, mb)
	if sig != nil && !o.dropSig {
		put(SignatureName, sig)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func verify(b []byte, ks *KeySet) (*Result, error) {
	return VerifyZIP(bytes.NewReader(b), int64(len(b)), ks)
}

func TestVerifyZIP(t *testing.T) {
	k := NewSigner(newKey(t))
	other := NewSigner(newKey(t))
	ks := &KeySet{Keys: []Key{Entry(k.PublicKey(), when.AddDate(0, -1, 0))}}

	res, err := verify(pack(t, packOpts{signer: k}), ks)
	if err != nil || res.Key == nil || res.Key.KeyID != k.KeyID() || res.Files != 2 {
		t.Fatalf("signed pack: %+v, %v", res, err)
	}
	cases := []struct {
		name string
		o    packOpts
		want error
	}{
		{"file changed", packOpts{signer: k, editFile: true}, ErrTampered},
		{"manifest changed", packOpts{signer: k, editMan: true}, ErrBadSignature},
		{"signature stripped", packOpts{signer: k, dropSig: true}, ErrTampered},
		{"file added", packOpts{signer: k, extra: true}, ErrTampered},
		{"unknown key", packOpts{signer: other}, ErrUnknownKey},
		{"before the key was in use", packOpts{signer: k, generatedAt: when.AddDate(0, -2, 0)}, ErrKeyWindow},
		{"unsigned", packOpts{}, ErrUnsigned},
	}
	for _, c := range cases {
		if _, err := verify(pack(t, c.o), ks); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// An unsigned pack's files are still checked.
	if _, err := verify(pack(t, packOpts{editFile: true}), ks); !errors.Is(err, ErrTampered) {
		t.Errorf("unsigned and changed: %v", err)
	}
}

func TestRotation(t *testing.T) {
	old, cur := NewSigner(newKey(t)), NewSigner(newKey(t))
	retired := when.AddDate(0, 1, 0)
	oldEntry := Entry(old.PublicKey(), when.AddDate(-1, 0, 0))
	oldEntry.Status, oldEntry.NotAfter = StatusRetired, &retired
	ks := &KeySet{Keys: []Key{oldEntry, Entry(cur.PublicKey(), retired)}}

	// A pack the old key signed before it retired still verifies.
	if _, err := verify(pack(t, packOpts{signer: old}), ks); err != nil {
		t.Fatalf("old pack after rotation: %v", err)
	}
	// One it "signed" after retiring does not.
	if _, err := verify(pack(t, packOpts{signer: old, generatedAt: retired.AddDate(0, 0, 1)}), ks); !errors.Is(err, ErrKeyWindow) {
		t.Fatalf("old key after retirement: %v", err)
	}
	if _, err := verify(pack(t, packOpts{signer: cur, generatedAt: retired.AddDate(0, 0, 1)}), ks); err != nil {
		t.Fatalf("new key: %v", err)
	}
	// A revoked key verifies nothing.
	ks.Keys[0].Status = StatusRevoked
	if _, err := verify(pack(t, packOpts{signer: old}), ks); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestParseKeySet(t *testing.T) {
	k := NewSigner(newKey(t))
	good, _ := json.Marshal(KeySet{Keys: []Key{Entry(k.PublicKey(), when)}})
	if _, err := ParseKeySet(good); err != nil {
		t.Fatal(err)
	}
	e := Entry(k.PublicKey(), when)
	e.KeyID = "ed25519:0000000000000000"
	bad, _ := json.Marshal(KeySet{Keys: []Key{e}})
	if _, err := ParseKeySet(bad); err == nil {
		t.Fatal("a key id that does not match its key was accepted")
	}
	e = Entry(k.PublicKey(), when)
	e.Status = "maybe"
	bad, _ = json.Marshal(KeySet{Keys: []Key{e}})
	if _, err := ParseKeySet(bad); err == nil {
		t.Fatal("an unknown status was accepted")
	}
}

func TestLoadSigner(t *testing.T) {
	key := newKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKeyFile, path)
	s, err := SignerFromEnv()
	if err != nil || s == nil || s.KeyID() != KeyID(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("SignerFromEnv: %v, %v", s, err)
	}
	t.Setenv(EnvKeyFile, "")
	if s, err := SignerFromEnv(); s != nil || err != nil {
		t.Fatalf("unset: %v, %v", s, err)
	}
}
