package risk

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Due-date modes (Policy.DueDates).
const (
	// DueDatesSLA: every finding is due a fixed number of days after first
	// detection, by priority (Policy.SLA).
	DueDatesSLA = "sla"
	// DueDatesPatchCalendar: urgent findings keep the SLA; the rest are due
	// at the end of their asset's next patch window after first detection.
	DueDatesPatchCalendar = "patch_calendar"
)

// Patch window classes of an asset (PatchClass).
const (
	PatchClassTest = "test"
	PatchClassProd = "prod"
)

// PatchClassTag is the asset tag prefix that sets an asset's patch window
// class by hand: "patch-window:test" or "patch-window:prod".
const PatchClassTag = "patch-window:"

// PatchCalendar places each month's patch windows. The test window is a day
// a fixed number of days after Patch Tuesday (the second Tuesday of the
// month); the production window follows it a fixed number of days later.
// Each window is one calendar day in Timezone.
type PatchCalendar struct {
	// TestDaysAfterPatchTuesday: 1, the default, is the Wednesday after
	// Patch Tuesday.
	TestDaysAfterPatchTuesday int `json:"test_days_after_patch_tuesday"`
	// ProdDaysAfterTest: 7 by default, the Wednesday a week later.
	ProdDaysAfterTest int `json:"prod_days_after_test"`
	// Timezone is an IANA zone name; UTC by default.
	Timezone string `json:"timezone"`
}

// DefaultPatchCalendar is the calendar a policy gets when it switches to
// DueDatesPatchCalendar without one, and the base a partial one is read over.
func DefaultPatchCalendar() PatchCalendar {
	return PatchCalendar{TestDaysAfterPatchTuesday: 1, ProdDaysAfterTest: 7, Timezone: "UTC"}
}

func (p Policy) validateDueDates() error {
	switch p.DueDates {
	case "", DueDatesSLA, DueDatesPatchCalendar:
	default:
		return fmt.Errorf("due_dates must be %q or %q", DueDatesSLA, DueDatesPatchCalendar)
	}
	c := p.PatchCalendar
	if c == nil {
		return nil
	}
	if c.TestDaysAfterPatchTuesday < 0 || c.TestDaysAfterPatchTuesday > 20 {
		return errors.New("patch_calendar.test_days_after_patch_tuesday must be between 0 and 20")
	}
	if c.ProdDaysAfterTest < 0 || c.ProdDaysAfterTest > 28 {
		return errors.New("patch_calendar.prod_days_after_test must be between 0 and 28")
	}
	// LoadLocation also accepts "Local", the server's own zone, which is
	// not a setting a workspace should depend on.
	if _, err := time.LoadLocation(c.Timezone); err != nil || c.Timezone == "Local" {
		return fmt.Errorf("patch_calendar.timezone %q is not a time zone name such as Europe/Berlin or UTC", c.Timezone)
	}
	return nil
}

// Urgent reports whether a finding stays on the SLA under a patch calendar:
// P1, SOS or known exploited (CISA KEV), the findings notifications send
// right away by default. Everything else waits for a patch window.
func Urgent(r Result, in Input) bool {
	return r.Priority == "P1" || r.SOS || in.KnownExploited
}

// testWords mark a non-production asset in its environment or name.
var testWords = map[string]bool{"dev": true, "development": true, "test": true, "testing": true, "uat": true, "staging": true, "stage": true, "qa": true}

// hasTestWord reports whether s has a word (letters, optionally followed by
// digits: "dev2", "uat01") that marks a non-production asset.
func hasTestWord(s string) bool {
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if testWords[strings.TrimRight(w, "0123456789")] {
			return true
		}
	}
	return false
}

// PatchClass is an asset's patch window class, PatchClassTest or
// PatchClassProd: the tag patch-window:test or patch-window:prod when it has
// one, else its environment (a production environment of the policy is
// prod, one named like dev, test, uat, staging or qa is test), else its
// name, which is test when it has one of those words. Anything else is
// prod: the later window, so an unclassified asset is never hurried.
func (p Policy) PatchClass(tags []string, environment, name string) string {
	for _, t := range tags {
		if v, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(t)), PatchClassTag); ok && (v == PatchClassTest || v == PatchClassProd) {
			return v
		}
	}
	switch {
	case p.IsProduction(environment):
		return PatchClassProd
	case hasTestWord(environment):
		return PatchClassTest
	case hasTestWord(name):
		return PatchClassTest
	}
	return PatchClassProd
}

// NextWindow returns the first patch window of class that starts after t:
// its start and its end (the next midnight), in the calendar's time zone.
func (c PatchCalendar) NextWindow(class string, t time.Time) (start, end time.Time) {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		loc = time.UTC // validated on save; a zone removed since falls back
	}
	offset := c.TestDaysAfterPatchTuesday
	if class != PatchClassTest {
		offset += c.ProdDaysAfterTest
	}
	local := t.In(loc)
	// Up to 48 days after Patch Tuesday, a window can fall two months after
	// its own: start two months back and stop at the first one after t.
	first := time.Date(local.Year(), local.Month()-2, 1, 0, 0, 0, 0, loc)
	for m := 0; ; m++ {
		month := first.AddDate(0, m, 0)
		tuesday := 1 + (int(time.Tuesday)-int(month.Weekday())+7)%7 + 7
		start = time.Date(month.Year(), month.Month(), tuesday+offset, 0, 0, 0, 0, loc)
		if start.After(t) {
			return start, start.AddDate(0, 0, 1)
		}
	}
}

// FindingDeadlines returns a finding's acknowledgement and fix deadlines
// under the policy's due-date mode, from from (when the asset first had the
// issue) and the asset's patch window class. scheduled says the fix
// deadline is a patch window rather than the SLA. A scheduled finding keeps
// its SLA acknowledgement deadline, but never later than the fix deadline.
func (p Policy) FindingDeadlines(r Result, in Input, class string, from time.Time) (ack, fix time.Time, scheduled bool) {
	ack, fix = p.Deadlines(r.Priority, from)
	if p.DueDates != DueDatesPatchCalendar || Urgent(r, in) {
		return ack, fix, false
	}
	cal := DefaultPatchCalendar() // what Normalize sets when there is none
	if p.PatchCalendar != nil {
		cal = *p.PatchCalendar
	}
	_, fix = cal.NextWindow(class, from)
	if ack.After(fix) {
		ack = fix
	}
	return ack, fix, true
}
