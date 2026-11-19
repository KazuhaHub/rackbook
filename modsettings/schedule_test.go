package modsettings

import (
	"testing"
	"time"
)

func at(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDecide(t *testing.T) {
	const tz = "Asia/Shanghai" // UTC+8, no DST
	cases := []struct {
		name   string
		in     Input
		run    bool
		reason string
		req    string
	}{
		{"before the first slot of the day, ran yesterday", Input{Now: at(t, "2026-11-18T07:00:00+08:00"), Times: []string{"08:00"}, Timezone: tz, LastOK: at(t, "2026-11-17T08:05:00+08:00")}, false, ReasonNotDue, ""},
		{"slot passed since the last run", Input{Now: at(t, "2026-11-18T08:10:00+08:00"), Times: []string{"08:00"}, Timezone: tz, LastOK: at(t, "2026-11-17T08:05:00+08:00")}, true, ReasonSlot, ""},
		{"already ran after the slot", Input{Now: at(t, "2026-11-18T09:10:00+08:00"), Times: []string{"08:00"}, Timezone: tz, LastOK: at(t, "2026-11-18T08:05:00+08:00")}, false, ReasonNotDue, ""},
		{"never ran", Input{Now: at(t, "2026-11-18T03:00:00+08:00"), Times: []string{"08:00"}, Timezone: tz}, true, ReasonSlot, ""},
		{"two slots, the second passed", Input{Now: at(t, "2026-11-18T14:00:00+08:00"), Times: []string{"08:00", "13:30"}, Timezone: tz, LastOK: at(t, "2026-11-18T08:05:00+08:00")}, true, ReasonSlot, ""},
		{"two slots, nothing new", Input{Now: at(t, "2026-11-18T12:00:00+08:00"), Times: []string{"08:00", "13:30"}, Timezone: tz, LastOK: at(t, "2026-11-18T08:05:00+08:00")}, false, ReasonNotDue, ""},
		{"slot is a different day in UTC", Input{Now: at(t, "2026-11-17T17:00:00Z"), Times: []string{"01:00"}, Timezone: tz, LastOK: at(t, "2026-11-17T17:30:00Z").Add(-24 * time.Hour)}, true, ReasonSlot, ""},
		{"a request runs before the slot", Input{Now: at(t, "2026-11-18T07:00:00+08:00"), Times: []string{"08:00"}, Timezone: tz, LastOK: at(t, "2026-11-17T08:05:00+08:00"), RunRequest: "r1"}, true, ReasonRequested, "r1"},
		{"paused wins over a slot", Input{Now: at(t, "2026-11-18T08:10:00+08:00"), Times: []string{"08:00"}, Timezone: tz, Paused: true}, false, ReasonPaused, ""},
		{"paused wins over a request", Input{Now: at(t, "2026-11-18T08:10:00+08:00"), Times: []string{"08:00"}, Timezone: tz, Paused: true, RunRequest: "r1"}, false, ReasonPaused, ""},
		{"no times, nothing is due", Input{Now: at(t, "2026-11-18T08:10:00+08:00"), Timezone: tz}, false, ReasonNotDue, ""},
		{"empty zone is UTC", Input{Now: at(t, "2026-11-18T08:10:00Z"), Times: []string{"08:00"}, LastOK: at(t, "2026-11-17T08:05:00Z")}, true, ReasonSlot, ""},
		{"unknown zone falls back to UTC", Input{Now: at(t, "2026-11-18T08:10:00Z"), Times: []string{"08:00"}, Timezone: "Nope/Nowhere", LastOK: at(t, "2026-11-17T08:05:00Z")}, true, ReasonSlot, ""},
	}
	for _, c := range cases {
		got := Decide(c.in)
		if got.Run != c.run || got.Reason != c.reason || got.RunRequest != c.req {
			t.Errorf("%s: got %+v, want run=%v reason=%s request=%q", c.name, got, c.run, c.reason, c.req)
		}
	}
}

func TestSlotsAcrossDaylightSaving(t *testing.T) {
	// America/New_York: DST ended 2026-11-01, so 02:30 that night is 07:30 UTC the second time.
	now := at(t, "2026-11-01T12:00:00Z")
	last, ok := LastSlot(now, []string{"03:00"}, "America/New_York")
	if !ok || !last.Equal(at(t, "2026-11-01T08:00:00Z")) {
		t.Fatalf("last slot %v %v", last, ok)
	}
	next, ok := NextSlot(now, []string{"03:00"}, "America/New_York")
	if !ok || !next.Equal(at(t, "2026-11-02T08:00:00Z")) {
		t.Fatalf("next slot %v %v", next, ok)
	}
}

func TestNextSlot(t *testing.T) {
	now := at(t, "2026-11-18T23:30:00Z")
	next, ok := NextSlot(now, []string{"03:00", "08:00"}, "UTC")
	if !ok || !next.Equal(at(t, "2026-11-19T03:00:00Z")) {
		t.Fatalf("%v %v", next, ok)
	}
	if _, ok := NextSlot(now, nil, "UTC"); ok {
		t.Fatal("no times, no slot")
	}
}
