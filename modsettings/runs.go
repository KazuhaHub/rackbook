package modsettings

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Run statuses.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

// MaxRuns is how many runs of a module the server keeps.
const MaxRuns = 30

// MaxErrorLen is the longest error text of a run, in characters.
const MaxErrorLen = 300

// Counts is what a run did. Only the counts that apply to the module are set:
// entra creates, updates and revokes records, notify sends messages.
type Counts struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Revoked int `json:"revoked"`
	Sent    int `json:"sent"`
}

// Run is one run of a module, as the module reports it with
// POST /api/modules/{name}/runs and as the server keeps it.
type Run struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Status   string    `json:"status"` // ok | failed | skipped
	Counts   Counts    `json:"counts"`
	Error    string    `json:"error,omitempty"`
	// RunRequest is the id of the "run now" request this run answers.
	RunRequest string `json:"run_request,omitempty"`
}

// Clean trims the error text to one short line.
func (r *Run) Clean() {
	e := strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f || c == 0x85 || c == 0x2028 || c == 0x2029 {
			return ' '
		}
		return c
	}, r.Error)
	e = strings.TrimSpace(e)
	if rs := []rune(e); len(rs) > MaxErrorLen {
		e = string(rs[:MaxErrorLen]) + "…"
	}
	r.Error = e
	r.RunRequest = strings.TrimSpace(r.RunRequest)
}

// MaxClockSkew is how far ahead of the server a reported run may be before it
// is refused as nonsense. Times within it are stored exactly as reported: the
// module compares its own clock with its own reported times, so they must stay
// consistent with each other.
const MaxClockSkew = 24 * time.Hour

// SkewWorthLogging is the clock difference above which the server logs it.
const SkewWorthLogging = 10 * time.Minute

// Validate checks a reported run against the server's clock.
func (r *Run) Validate(now time.Time) error {
	switch r.Status {
	case StatusOK, StatusFailed, StatusSkipped:
	default:
		return fmt.Errorf("status %q must be ok, failed or skipped", r.Status)
	}
	if r.Started.IsZero() || r.Finished.IsZero() {
		return errors.New("started and finished are required (RFC 3339)")
	}
	if r.Finished.Before(r.Started) {
		return errors.New("finished is before started")
	}
	if r.Finished.After(now.Add(MaxClockSkew)) {
		return errors.New("finished is more than 24 hours in the future")
	}
	for _, n := range []int{r.Counts.Created, r.Counts.Updated, r.Counts.Revoked, r.Counts.Sent} {
		if n < 0 || n > 1_000_000_000 {
			return errors.New("counts must be between 0 and 1000000000")
		}
	}
	if len(r.RunRequest) > 64 {
		return errors.New("run_request is too long")
	}
	return nil
}

// Remote is the answer of GET /api/modules/{name}/settings: what a module
// needs to decide whether to run and with which settings.
type Remote struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Settings holds only the values set in the console; the module applies
	// its own defaults to the rest.
	Settings map[string]any `json:"settings"`
	Version  string         `json:"version"`
	// RunRequest is the id of a waiting "run now" request, or "".
	RunRequest string `json:"runRequest"`
	// LastOK is when the module last started a successful run (zero = never).
	LastOK  time.Time `json:"lastOk"`
	LastRun *Run      `json:"lastRun"`
	Now     time.Time `json:"now"`
}

// ModuleStatus is one entry of GET /api/modules/status.
type ModuleStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Paused  bool   `json:"paused"`
	LastRun *Run   `json:"lastRun"`
}
