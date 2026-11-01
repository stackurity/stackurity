//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// execute runs the handler as the service manager would and returns its
// result and every status it reported.
func execute(t *testing.T, a *agentService, requests chan svc.ChangeRequest) (specific bool, code uint32, states []svc.State) {
	t.Helper()
	status := make(chan svc.Status, 16)
	type result struct {
		specific bool
		code     uint32
	}
	res := make(chan result, 1)
	go func() {
		s, c := a.Execute([]string{agentServiceName}, requests, status)
		res <- result{s, c}
	}()
	select {
	case r := <-res:
		close(status)
		for s := range status {
			states = append(states, s.State)
		}
		return r.specific, r.code, states
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not return")
	}
	return
}

func TestServiceStopsTheAgent(t *testing.T) {
	started := make(chan struct{})
	a := &agentService{parent: context.Background(), stopWait: 5 * time.Second, run: func(ctx context.Context) error {
		close(started)
		<-ctx.Done() // the agent's loop returns nil when its context ends
		return nil
	}}
	requests := make(chan svc.ChangeRequest, 2)
	go func() {
		<-started
		requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: svc.Status{State: svc.Running}}
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
	}()
	specific, code, states := execute(t, a, requests)
	if specific || code != 0 || a.err != nil {
		t.Errorf("stop: specific=%v code=%d err=%v", specific, code, a.err)
	}
	want := []svc.State{svc.StartPending, svc.Running, svc.Running, svc.StopPending}
	if fmt.Sprint(states) != fmt.Sprint(want) {
		t.Errorf("states %v, want %v", states, want)
	}
}

func TestServiceShutdownStops(t *testing.T) {
	a := &agentService{parent: context.Background(), stopWait: 5 * time.Second, run: func(ctx context.Context) error { <-ctx.Done(); return nil }}
	requests := make(chan svc.ChangeRequest, 1)
	requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
	if _, code, _ := execute(t, a, requests); code != 0 {
		t.Errorf("shutdown exit code %d", code)
	}
}

// A failed agent (no server, a bad token file) ends the service with a
// service-specific error, which the installer's failure actions restart.
func TestServiceReportsAgentFailure(t *testing.T) {
	a := &agentService{parent: context.Background(), stopWait: time.Second, run: func(context.Context) error { return errors.New("no token") }}
	specific, code, _ := execute(t, a, make(chan svc.ChangeRequest))
	if !specific || code != 1 || a.err == nil || a.err.Error() != "no token" {
		t.Errorf("failure: specific=%v code=%d err=%v", specific, code, a.err)
	}
}

// A stop that the agent does not honour in time still stops the service.
func TestServiceStopWaitIsBounded(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	a := &agentService{parent: context.Background(), stopWait: 50 * time.Millisecond, run: func(context.Context) error { <-block; return nil }}
	requests := make(chan svc.ChangeRequest, 1)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if _, code, _ := execute(t, a, requests); code != 0 {
		t.Errorf("exit code %d", code)
	}
}

type fakeEventLog struct {
	mu            sync.Mutex
	info, warning []string
}

func (f *fakeEventLog) Info(_ uint32, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info = append(f.info, m)
	return nil
}

func (f *fakeEventLog) Warning(_ uint32, m string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.warning = append(f.warning, m)
	return nil
}

func TestOutputToEventLog(t *testing.T) {
	out, errOut := os.Stdout, os.Stderr
	el := &fakeEventLog{}
	restore := outputToEventLog(el)
	fmt.Println("asset 7: 120 observations stored")
	fmt.Fprintln(os.Stderr, "collection failed: timeout")
	restore()
	if os.Stdout != out || os.Stderr != errOut {
		t.Error("standard output and error not restored")
	}
	if strings.Join(el.info, "|") != "asset 7: 120 observations stored" || strings.Join(el.warning, "|") != "collection failed: timeout" {
		t.Errorf("info %q, warning %q", el.info, el.warning)
	}
}
