package apiclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/pkg/plugin"
)

// Every request dials a new connection, so the network policy, which runs
// when a connection is dialled, checks every request: a kept-alive
// connection would carry later requests past it.
func TestEveryRequestDials(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	c := NewHTTP(context.Background())
	for i := 0; i < 3; i++ {
		if err := Do(context.Background(), c, "GET", srv.URL, "t", "", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := conns.Load(); n != 3 {
		t.Errorf("3 requests used %d connections", n)
	}
	ctx := plugin.WithNetwork(context.Background(), netguard.Policy{AllowPrivate: false})
	if err := Do(ctx, NewHTTP(ctx), "GET", srv.URL, "", "", nil, nil); !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("blocked address reached: %v", err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	err := Do(context.Background(), NewHTTP(context.Background()), "GET", srv.URL, "secret-token", "", nil, nil)
	if StatusOf(err) != 302 || hits.Load() != 0 {
		t.Errorf("redirect: %v, target hit %d times", err, hits.Load())
	}
}

func TestErrorShapes(t *testing.T) {
	for body, want := range map[string]string{
		`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"denied","details":[{"reason":"SERVICE_DISABLED"}]}}`: "HTTP 403 PERMISSION_DENIED (SERVICE_DISABLED): denied",
		`{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization"}}`:                      "HTTP 403 AuthorizationFailed: The client does not have authorization",
		`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret.\r\nTrace ID: x"}`:            "HTTP 403 invalid_client: AADSTS7000215: Invalid client secret.",
		`not json`: "HTTP 403",
	} {
		if got := parseError(403, []byte(body)).Error(); got != want {
			t.Errorf("%s:\n got %s\nwant %s", body, got, want)
		}
	}
	if len(parseError(403, []byte(`{"error":{"message":"`+strings.Repeat("x", 1000)+`"}}`)).Error()) > 400 {
		t.Error("long message not cut")
	}
}
