package sitecheck

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestOldClientHelloIsParsed: Go's own TLS server reads our ClientHello and
// sees TLS 1.1 as the highest version offered, with the SNI.
func TestOldClientHelloIsParsed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	got := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		defer b.Close()
		srv := tls.Server(b, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			got <- h
			return nil, io.EOF // stop after reading it
		}})
		_ = srv.Handshake()
	}()
	go func() { _, _ = a.Write(oldClientHello("shop.example.com")); _, _ = io.Copy(io.Discard, a) }()
	h := <-got
	if h.ServerName != "shop.example.com" {
		t.Errorf("SNI %q", h.ServerName)
	}
	max := uint16(0)
	for _, v := range h.SupportedVersions {
		if v > max {
			max = v
		}
	}
	if max != tls.VersionTLS11 {
		t.Errorf("highest version offered %x, want TLS 1.1", max)
	}
}

func TestServerHelloVersion(t *testing.T) {
	hello := func(v uint16) []byte {
		return []byte{22, 3, 3, 0, 46, 2, 0, 0, 42, byte(v >> 8), byte(v)}
	}
	for name, c := range map[string]struct {
		in   []byte
		v    uint16
		want bool
	}{
		"TLS 1.0 chosen":         {hello(0x0301), 0x0301, true},
		"TLS 1.1 chosen":         {hello(0x0302), 0x0302, true},
		"protocol_version alert": {[]byte{21, 3, 1, 0, 2, 2, 70}, 0, false},
		"closed":                 {nil, 0, false},
		"not a ServerHello":      {[]byte{22, 3, 3, 0, 6, 11, 0, 0, 2, 0, 0}, 0, false},
	} {
		v, ok := serverHelloVersion(bytes.NewReader(c.in))
		if ok != c.want || ok && v != c.v {
			t.Errorf("%s: %x %v", name, v, ok)
		}
	}
}

// TestModernServerRefusesOldHello: Go's TLS server with default settings
// (TLS 1.2 minimum) answers our hello with an alert, which reads as "does
// not accept TLS 1.0/1.1". The accepting side is TestServerHelloVersion.
func TestModernServerRefusesOldHello(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		defer b.Close()
		_ = tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	}()
	go func() { _, _ = a.Write(oldClientHello("example.com")) }()
	if v, ok := serverHelloVersion(a); ok {
		t.Errorf("a TLS 1.2+ server answered a ServerHello with version %x", v)
	}
}
