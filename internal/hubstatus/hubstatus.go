// Package hubstatus reads the status document of the infra hub
// (`infra-hub status -o json`, apiVersion v1) from a file that a timer on the
// same host keeps fresh. Rackbook only reads it.
package hubstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// MaxAge is how old the document may be before it is not shown as current.
// The file is rewritten every 30 seconds.
const MaxAge = 3 * time.Minute

// MaxFuture is how far ahead of Rackbook's clock the document's time may be (clock differences); more is not believed.
const MaxFuture = time.Minute

// maxSize bounds what is read from the file.
const maxSize = 8 << 20

// Document states.
const (
	StateOK      = "ok"
	StateStale   = "stale"   // older than MaxAge
	StateMissing = "missing" // the file does not exist
	StateInvalid = "invalid" // unreadable, not JSON or an unknown apiVersion
)

// Status is the document, the fields Rackbook uses.
type Status struct {
	APIVersion string  `json:"apiVersion"`
	Time       string  `json:"time"`
	Main       string  `json:"main,omitempty"`
	Hosts      []Host  `json:"hosts"`
	Certs      []Cert  `json:"certs"`
	IPLists    *IPInfo `json:"iplists,omitempty"`
}

// Host is one configured client of the hub.
type Host struct {
	Name   string  `json:"name"`
	Report *Report `json:"report,omitempty"`
}

// Report is the latest report of a host's agent.
type Report struct {
	AppliedCommit string    `json:"appliedCommit,omitempty"`
	Result        string    `json:"result"`
	Message       string    `json:"message,omitempty"`
	Time          string    `json:"time"`
	ReceivedAt    string    `json:"receivedAt,omitempty"`
	Features      []Feature `json:"features,omitempty"`
}

// Feature is the outcome of one feature in a report.
type Feature struct {
	Name    string `json:"name"`
	Result  string `json:"result"`
	Message string `json:"message,omitempty"`
}

// Cert is one certificate name of the hub's allow list.
type Cert struct {
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	NotAfter  string `json:"notAfter,omitempty"`
	Failing   bool   `json:"failing"`
	LastError string `json:"lastError,omitempty"`
}

// IPInfo is the IP list section.
type IPInfo struct {
	Lists []IPList `json:"lists"`
}

// IPList is one named list.
type IPList struct {
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Entries  int      `json:"entries"`
	Warnings []string `json:"warnings"`
}

// Snapshot is the outcome of one read.
type Snapshot struct {
	State string `json:"state"`
	// Error says why the state is invalid.
	Error string `json:"error,omitempty"`
	// Time is when the hub wrote the document (its own clock; the file's
	// modification time when the document carries none). Zero when missing.
	Time time.Time `json:"time"`
	// AgeSeconds is now minus Time.
	AgeSeconds int64 `json:"ageSeconds"`
	// Status is set only when State is ok: a stale document is not shown as
	// if it were current.
	Status *Status `json:"-"`
}

// Available reports that Status may be shown as current.
func (s Snapshot) Available() bool { return s.State == StateOK && s.Status != nil }

// Load reads the file at path as of now.
func Load(path string, now time.Time) Snapshot {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{State: StateMissing}
		}
		return Snapshot{State: StateInvalid, Error: err.Error()}
	}
	defer f.Close()
	var mtime time.Time
	if st, err := f.Stat(); err == nil {
		mtime = st.ModTime()
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return Snapshot{State: StateInvalid, Error: err.Error()}
	}
	if len(raw) > maxSize {
		return Snapshot{State: StateInvalid, Error: "status file is too large"}
	}
	return Parse(raw, mtime, now)
}

// Parse interprets a document. mtime is the fallback for a document that has
// no (or an unreadable) time.
func Parse(raw []byte, mtime, now time.Time) Snapshot {
	var st Status
	if err := json.Unmarshal(raw, &st); err != nil {
		return Snapshot{State: StateInvalid, Error: fmt.Sprintf("not valid JSON: %v", err)}
	}
	if st.APIVersion != "v1" {
		return Snapshot{State: StateInvalid, Error: fmt.Sprintf("unsupported apiVersion %q", st.APIVersion)}
	}
	t, err := time.Parse(time.RFC3339, st.Time)
	if err != nil {
		t = mtime
	}
	if t.IsZero() {
		return Snapshot{State: StateInvalid, Error: "the document has no time"}
	}
	age := now.Sub(t)
	if age < -MaxFuture {
		return Snapshot{State: StateInvalid, Error: "the document's time is in the future"}
	}
	if age < 0 {
		age = 0
	}
	snap := Snapshot{State: StateOK, Time: t, AgeSeconds: int64(age.Seconds()), Status: &st}
	if age > MaxAge {
		snap.State, snap.Status = StateStale, nil
	}
	return snap
}
