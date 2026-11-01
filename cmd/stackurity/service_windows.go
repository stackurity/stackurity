//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// agentServiceName is the service agent.ps1 registers, and the event log
// source the agent writes to when it runs as that service.
const agentServiceName = "StackurityAgent"

// agentStopWait is how long a stop request waits for a report in progress
// to finish; the service manager allows about 20 seconds in all.
const agentStopWait = 15 * time.Second

// runAgent runs the agent, as a service when the Windows service control
// manager started it: it then tells the manager it is running, stops when
// asked (or at shutdown), runs below normal priority, and writes its output
// to the Application event log, since a service has no console.
func runAgent(ctx context.Context, run func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return run(ctx)
	}
	if el, err := eventlog.Open(agentServiceName); err == nil {
		defer el.Close()
		restore := outputToEventLog(el)
		defer restore()
	}
	// A background job: the server's own work comes first (Nice=10 in the
	// Linux unit).
	_ = windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
	h := &agentService{parent: ctx, run: run, stopWait: agentStopWait}
	if err := svc.Run(agentServiceName, h); err != nil {
		return err
	}
	return h.err
}

// agentService is the service's handler: Execute runs the agent until it
// returns or the service manager asks it to stop.
type agentService struct {
	parent   context.Context
	run      func(context.Context) error
	stopWait time.Duration
	err      error // what run returned
}

func (a *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(a.parent)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- running
	for {
		select {
		case err := <-done:
			// The agent ended by itself: a configuration or connection
			// error. A service-specific exit code makes the service
			// manager restart it (the installer sets failure actions and
			// the failure flag).
			a.err = err
			if err != nil {
				fmt.Fprintln(os.Stderr, "the agent stopped:", err)
				return true, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(a.stopWait / time.Millisecond)}
				cancel()
				select {
				case a.err = <-done:
				case <-time.After(a.stopWait):
				}
				return false, 0
			}
		}
	}
}

// eventLog is the part of *eventlog.Log the agent uses.
type eventLog interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
}

// Event IDs: EventCreate.exe, the message file the installer registers,
// shows the text of any ID from 1 to 1000.
const (
	eventOutput = 1 // standard output: reports
	eventError  = 2 // standard error: failures and warnings
)

// outputToEventLog sends what the agent prints to the event log, one entry
// per line, and returns a function that restores standard output and error
// and waits for the last lines.
func outputToEventLog(el eventLog) (restore func()) {
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return func() {}
	}
	os.Stdout, os.Stderr = outW, errW
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pumpLines(outR, func(l string) { _ = el.Info(eventOutput, l) }) }()
	go func() { defer wg.Done(); pumpLines(errR, func(l string) { _ = el.Warning(eventError, l) }) }()
	return func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		outW.Close()
		errW.Close()
		wg.Wait()
		outR.Close()
		errR.Close()
	}
}
