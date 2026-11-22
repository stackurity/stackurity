package main

import (
	"io"
	"log/slog"
	"testing"
)

// A self-hosted server ignores STACKURITY_THREAT_NOTICE_COPY_TO, even a
// malformed one; Stackurity Cloud checks it.
func TestThreatNoticeCopyTo(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	env := func(v string) func(string) string { return func(string) string { return v } }
	if v, err := threatNoticeCopyTo(false, env("not an address"), log); err != nil || v != "" {
		t.Errorf("self-hosted, malformed: %q %v", v, err)
	}
	if v, err := threatNoticeCopyTo(false, env("owner@example.org"), log); err != nil || v != "" {
		t.Errorf("self-hosted: %q %v", v, err)
	}
	if _, err := threatNoticeCopyTo(true, env("Owner <owner@example.org>"), log); err == nil {
		t.Error("cloud accepted a name and address")
	}
	if v, err := threatNoticeCopyTo(true, env("owner@example.org"), log); err != nil || v != "owner@example.org" {
		t.Errorf("cloud: %q %v", v, err)
	}
}
