package modsettings

import (
	"strconv"
	"time"
)

// Reasons of a Decision.
const (
	ReasonPaused    = "paused"
	ReasonRequested = "requested"
	ReasonSlot      = "slot"
	ReasonNotDue    = "not_due"
)

// Input is everything the decision needs. Times are the daily slots
// ("HH:MM") in Timezone; empty means the defaults of the caller (pass them in).
type Input struct {
	Now      time.Time
	Times    []string
	Timezone string
	// LastOK is when the module last finished a run that succeeded (the zero
	// time when it never has). Failed and skipped runs do not count, so a run
	// that failed is tried again at the next check.
	LastOK time.Time
	Paused bool
	// RunRequest is the id of a "run now" request that is waiting ("" = none).
	RunRequest string
}

// Decision says whether the module acts now.
type Decision struct {
	Run    bool
	Reason string
	// RunRequest is the pending request id to report with the run (also set
	// when a slot made the module run anyway, so the request is cleared).
	RunRequest string
}

// Decide is the whole scheduling rule. A module is started every hour by a
// timer; it acts only if
//   - it is not paused, and
//   - a "run now" request is waiting, or a daily slot has passed since the
//     last successful run.
//
// A module that has never run is due at once.
func Decide(in Input) Decision {
	if in.Paused {
		return Decision{Reason: ReasonPaused}
	}
	if in.RunRequest != "" {
		return Decision{Run: true, Reason: ReasonRequested, RunRequest: in.RunRequest}
	}
	if slot, ok := LastSlot(in.Now, in.Times, in.Timezone); ok && in.LastOK.Before(slot) {
		return Decision{Run: true, Reason: ReasonSlot}
	}
	return Decision{Reason: ReasonNotDue}
}

func location(tz string) *time.Location {
	if tz == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}

func clock(s string) (h, m int, ok bool) {
	if !timeRe.MatchString(s) {
		return 0, 0, false
	}
	h, _ = strconv.Atoi(s[:2])
	m, _ = strconv.Atoi(s[3:])
	return h, m, true
}

// slots lists every slot of the days around now, in time order not
// guaranteed; callers pick the extreme they need.
func slots(now time.Time, times []string, tz string, from, to int) []time.Time {
	loc := location(tz)
	day := now.In(loc)
	var out []time.Time
	for d := from; d <= to; d++ {
		for _, t := range times {
			h, m, ok := clock(t)
			if !ok {
				continue
			}
			out = append(out, time.Date(day.Year(), day.Month(), day.Day()+d, h, m, 0, 0, loc))
		}
	}
	return out
}

// LastSlot is the latest slot that is not after now.
func LastSlot(now time.Time, times []string, tz string) (time.Time, bool) {
	var best time.Time
	found := false
	for _, s := range slots(now, times, tz, -2, 0) {
		if !s.After(now) && (!found || s.After(best)) {
			best, found = s, true
		}
	}
	return best, found
}

// NextSlot is the earliest slot after now.
func NextSlot(now time.Time, times []string, tz string) (time.Time, bool) {
	var best time.Time
	found := false
	for _, s := range slots(now, times, tz, 0, 2) {
		if s.After(now) && (!found || s.Before(best)) {
			best, found = s, true
		}
	}
	return best, found
}
