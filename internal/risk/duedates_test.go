package risk

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNextWindow(t *testing.T) {
	utc := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	def := DefaultPatchCalendar()
	wide := PatchCalendar{TestDaysAfterPatchTuesday: 20, ProdDaysAfterTest: 28, Timezone: "UTC"}
	india := PatchCalendar{TestDaysAfterPatchTuesday: 1, ProdDaysAfterTest: 7, Timezone: "Asia/Kolkata"}
	for _, c := range []struct {
		name  string
		cal   PatchCalendar
		class string
		at    string
		start string
	}{
		// Patch Tuesday is 10 November 2026 and 8 December 2026.
		{"test, early in the month", def, PatchClassTest, "2026-11-01T09:00:00Z", "2026-11-11T00:00:00Z"},
		{"prod, a week later", def, PatchClassProd, "2026-11-01T09:00:00Z", "2026-11-18T00:00:00Z"},
		{"on Patch Tuesday", def, PatchClassTest, "2026-11-10T23:59:00Z", "2026-11-11T00:00:00Z"},
		{"during the window: the next one", def, PatchClassTest, "2026-11-11T10:00:00Z", "2026-12-09T00:00:00Z"},
		{"as the window starts: the next one", def, PatchClassTest, "2026-11-11T00:00:00Z", "2026-12-09T00:00:00Z"},
		{"prod after its window", def, PatchClassProd, "2026-11-19T00:00:00Z", "2026-12-16T00:00:00Z"},
		{"across the year", def, PatchClassProd, "2026-12-20T00:00:00Z", "2027-01-20T00:00:00Z"},
		// 13 October + 48 days is 30 November: October's window comes first.
		{"a window in a later month", wide, PatchClassProd, "2026-11-01T00:00:00Z", "2026-11-30T00:00:00Z"},
		// 01:30 on the 11th in India: that day's window has started.
		{"time zone", india, PatchClassTest, "2026-11-10T20:00:00Z", "2026-12-08T18:30:00Z"},
		{"time zone, before the day", india, PatchClassTest, "2026-11-10T18:00:00Z", "2026-11-10T18:30:00Z"},
	} {
		start, end := c.cal.NextWindow(c.class, utc(c.at))
		if !start.Equal(utc(c.start)) || !end.Equal(start.AddDate(0, 0, 1)) {
			t.Errorf("%s: window %s to %s, want from %s for a day", c.name, start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339), c.start)
		}
	}
}

func TestPatchClass(t *testing.T) {
	p := DefaultPolicy()
	for _, c := range []struct {
		tags      []string
		env, name string
		want      string
	}{
		{nil, "", "web-1", PatchClassProd},
		{nil, "", "web-dev-1", PatchClassTest},
		{nil, "", "UAT02.example.com", PatchClassTest},
		{nil, "", "staging", PatchClassTest},
		{nil, "", "devops-1", PatchClassProd}, // a word, not a substring
		{nil, "", "contest-site", PatchClassProd},
		{nil, "staging", "web-1", PatchClassTest},
		{nil, "qa", "web-1", PatchClassTest},
		{nil, "Production", "test-db", PatchClassProd}, // the environment wins over the name
		{nil, "corp", "test-db", PatchClassTest},
		{[]string{"team-a", "Patch-Window:Prod"}, "", "test-db", PatchClassProd},
		{[]string{"patch-window:test"}, "production", "db-1", PatchClassTest},
		{[]string{"patch-window:later"}, "", "db-1", PatchClassProd},
	} {
		if got := p.PatchClass(c.tags, c.env, c.name); got != c.want {
			t.Errorf("tags %v, environment %q, name %q: %s, want %s", c.tags, c.env, c.name, got, c.want)
		}
	}
}

func TestFindingDeadlines(t *testing.T) {
	from := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	sla := DefaultPolicy()
	cal := DefaultPolicy()
	cal.DueDates = DueDatesPatchCalendar
	cal = cal.Normalize()
	if err := cal.Validate(); err != nil {
		t.Fatal(err)
	}
	p3 := Result{Priority: "P3"}
	for _, pr := range []string{"P1", "P2", "P3", "P4"} {
		a, f := sla.Deadlines(pr, from)
		ga, gf, sched := sla.FindingDeadlines(Result{Priority: pr}, Input{}, PatchClassTest, from)
		if !ga.Equal(a) || !gf.Equal(f) || sched {
			t.Errorf("SLA mode, %s: %v %v %v; want the SLA %v %v", pr, ga, gf, sched, a, f)
		}
	}
	// Non-urgent: due when the asset's window ends; acknowledgement keeps
	// the SLA (72 hours for P3).
	ack, fix, sched := cal.FindingDeadlines(p3, Input{}, PatchClassProd, from)
	if !sched || !fix.Equal(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)) || !ack.Equal(from.Add(72*time.Hour)) {
		t.Errorf("P3 in production: ack %v fix %v scheduled %v", ack, fix, sched)
	}
	// The acknowledgement deadline is never after the fix deadline (P4's
	// is 168 hours; the test window is ten days off).
	ack, fix, _ = cal.FindingDeadlines(Result{Priority: "P4"}, Input{}, PatchClassTest, from.AddDate(0, 0, 8))
	if !fix.Equal(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)) || !ack.Equal(fix) {
		t.Errorf("P4 two days before the test window: ack %v fix %v; want both at the window's end", ack, fix)
	}
	// Urgent findings keep the SLA.
	for name, c := range map[string]struct {
		r  Result
		in Input
	}{
		"P1":              {Result{Priority: "P1"}, Input{}},
		"SOS":             {Result{Priority: "P2", SOS: true}, Input{}},
		"known exploited": {Result{Priority: "P3"}, Input{KnownExploited: true}},
	} {
		a, f := cal.Deadlines(c.r.Priority, from)
		ga, gf, sched := cal.FindingDeadlines(c.r, c.in, PatchClassProd, from)
		if sched || !ga.Equal(a) || !gf.Equal(f) {
			t.Errorf("%s: %v %v scheduled %v; want the SLA %v %v", name, ga, gf, sched, a, f)
		}
	}
}

func TestDueDatesPolicy(t *testing.T) {
	// The fields are absent from the default policy, so adding them kept
	// every existing policy's version.
	raw, _ := json.Marshal(DefaultPolicy())
	if strings.Contains(string(raw), "due_dates") || strings.Contains(string(raw), "patch_calendar") {
		t.Errorf("default policy JSON has due-date fields: %s", raw)
	}
	// "sla" is the default and is stored as such.
	p, err := DecodePolicy([]byte(`{"due_dates":"sla"}`), true)
	if err != nil || p.Normalize().Version() != DefaultPolicy().Version() {
		t.Errorf(`"sla": version %s, want the default's (%v)`, p.Normalize().Version(), err)
	}
	// A calendar's missing fields take their defaults.
	p, err = DecodePolicy([]byte(`{"due_dates":"patch_calendar","patch_calendar":{"prod_days_after_test":3}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	p = p.Normalize()
	if c := p.PatchCalendar; c == nil || *c != (PatchCalendar{TestDaysAfterPatchTuesday: 1, ProdDaysAfterTest: 3, Timezone: "UTC"}) || p.Validate() != nil {
		t.Errorf("partial calendar read as %+v (%v)", c, p.Validate())
	}
	if p.Version() == DefaultPolicy().Version() {
		t.Error("switching to a patch calendar kept the version")
	}
	// Switching on without a calendar uses the default one.
	p, _ = DecodePolicy([]byte(`{"due_dates":"patch_calendar"}`), true)
	if p = p.Normalize(); p.PatchCalendar == nil || *p.PatchCalendar != DefaultPatchCalendar() {
		t.Errorf("no calendar: %+v", p.PatchCalendar)
	}
	if _, err := DecodePolicy([]byte(`{"patch_calendar":{"anchor":"x"}}`), true); err == nil {
		t.Error("unknown calendar field accepted")
	}
	for _, bad := range []string{
		`{"due_dates":"weekly"}`,
		`{"due_dates":"patch_calendar","patch_calendar":{"test_days_after_patch_tuesday":-1}}`,
		`{"due_dates":"patch_calendar","patch_calendar":{"test_days_after_patch_tuesday":21}}`,
		`{"due_dates":"patch_calendar","patch_calendar":{"prod_days_after_test":29}}`,
		`{"due_dates":"patch_calendar","patch_calendar":{"timezone":"Mars/Olympus"}}`,
		`{"due_dates":"patch_calendar","patch_calendar":{"timezone":"Local"}}`,
	} {
		p, err := DecodePolicy([]byte(bad), true)
		if err == nil {
			err = p.Normalize().Validate()
		}
		if err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
