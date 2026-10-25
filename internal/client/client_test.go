package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A result report survives a brief outage, and is not retried when the
// server refuses it.
func TestReportActionRetries(t *testing.T) {
	reportRetryWait = time.Millisecond
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch r.URL.Path {
		case "/api/v1/agent/actions/7/report": // back after two failures
			if n <= 2 {
				w.WriteHeader(502)
				return
			}
			w.WriteHeader(204)
		case "/api/v1/agent/actions/8/report": // stays down
			w.WriteHeader(500)
		default: // already timed out on the server
			w.WriteHeader(409)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "t", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReportAction(context.Background(), 7, map[string]string{"phase": "applied"}); err != nil || calls.Load() != 3 {
		t.Errorf("after an outage: err %v, %d calls", err, calls.Load())
	}
	calls.Store(0)
	var ae *APIError
	if err := c.ReportAction(context.Background(), 9, map[string]string{"phase": "applied"}); !errors.As(err, &ae) || ae.Status != 409 || calls.Load() != 1 {
		t.Errorf("refused report: err %v, %d calls", err, calls.Load())
	}
	calls.Store(0)
	if err := c.ReportAction(context.Background(), 8, nil); err == nil || calls.Load() != 4 {
		t.Errorf("server down: err %v, %d calls", err, calls.Load())
	}
}
