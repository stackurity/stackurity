package main

import (
	"fmt"
	"strings"
	"time"
)

// timings are the background clocks that crash tests shorten so that a lease
// or lock timeout passes in seconds instead of minutes. Production always uses
// the defaults; STACKURITY_TEST_TIMINGS exists for tests only, e.g.
//
//	STACKURITY_TEST_TIMINGS=job-lock=3s,task-lease=2s,tick=200ms,poll=200ms,delivery-lease=2s,alerts=1s
type timings struct {
	JobLock       time.Duration // a crashed worker's job is claimed again after this (store default 30m)
	TaskLease     time.Duration // periodic task lease (worker default 2m)
	Tick          time.Duration // how often the scheduler looks for due periodic tasks (15s)
	Poll          time.Duration // how often an idle worker looks for jobs (2s)
	DeliveryLease time.Duration // a claimed notification is retried after this (5m)
	Alerts        time.Duration // how often notifications are planned and delivered (1m)
	SchemaCheck   time.Duration // how often a running server looks for a newer schema (1m)
}

func defaultTimings() timings {
	return timings{TaskLease: 2 * time.Minute, Tick: 15 * time.Second, Poll: 2 * time.Second,
		DeliveryLease: 5 * time.Minute, Alerts: time.Minute, SchemaCheck: time.Minute}
}

// parseTimings applies a STACKURITY_TEST_TIMINGS value to the defaults.
func parseTimings(s string) (timings, error) {
	t := defaultTimings()
	fields := map[string]*time.Duration{
		"job-lock": &t.JobLock, "task-lease": &t.TaskLease, "tick": &t.Tick, "poll": &t.Poll,
		"delivery-lease": &t.DeliveryLease, "alerts": &t.Alerts, "schema-check": &t.SchemaCheck,
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		f, ok := fields[k]
		if !ok {
			return t, fmt.Errorf("STACKURITY_TEST_TIMINGS: unknown setting %q", k)
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return t, fmt.Errorf("STACKURITY_TEST_TIMINGS: %s must be a positive duration, not %q", k, v)
		}
		*f = d
	}
	return t, nil
}
