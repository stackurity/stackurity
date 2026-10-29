package auth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBreachCheckSendsOnlyThePrefix(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Add-Padding") != "true" {
			t.Error("no Add-Padding header")
		}
		_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"))
	}))
	defer srv.Close()
	c := &BreachChecker{URL: srv.URL + "/range/"}
	n, err := c.Count(context.Background(), "password")
	if err != nil || n != 3861493 {
		t.Fatalf("count %d %v", n, err)
	}
	if len(paths) != 1 || paths[0] != "/range/5BAA6" {
		t.Fatalf("requested %v; only the 5-character prefix may be sent", paths)
	}
	err = CheckNewPassword(context.Background(), c, "password", nil)
	if err == nil {
		t.Fatal("short and breached password accepted")
	}
	// A long password not in the list passes; one in it is refused with a
	// 400-class error.
	if err := CheckNewPassword(context.Background(), c, "a long password nobody has", nil); err != nil {
		t.Fatalf("unbreached: %v", err)
	}
	long := "correct horse battery staple"
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer every prefix with the suffix of the request's password.
		_, _ = w.Write([]byte(strings.ToUpper(sha1Suffix(long)) + ":42\n"))
	}))
	defer srv2.Close()
	err = CheckNewPassword(context.Background(), &BreachChecker{URL: srv2.URL + "/"}, long, nil)
	var b *ErrBreachedPassword
	if !errors.As(err, &b) || b.Count != 42 || !errors.Is(err, ErrBadPassword) {
		t.Fatalf("breached: %v", err)
	}
}

func TestBreachCheckFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	srv.Close() // unreachable
	var logged error
	err := CheckNewPassword(context.Background(), &BreachChecker{URL: srv.URL + "/"}, "a long password nobody has", func(e error) { logged = e })
	if err != nil || logged == nil {
		t.Fatalf("unreachable service: err %v, logged %v", err, logged)
	}
}

func sha1Suffix(pw string) string {
	sum := sha1.Sum([]byte(pw))
	return hex.EncodeToString(sum[:])[5:]
}
