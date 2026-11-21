package ansiblerepo

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"
)

// AuditEntry is one action that did not end in a commit: an edit refused by
// the checks, a conflict, a push that failed, a refused revert, a secret revealed. (Commits are
// the history of the repository itself.)
type AuditEntry struct {
	Time    time.Time `json:"time"`
	Who     string    `json:"who"`
	Action  string    `json:"action"`  // what was tried, e.g. "infra(host_vars/alpha): edit"
	Outcome string    `json:"outcome"` // validation_failed, conflict, no_change, push_failed, busy, revert_refused, reauth_required, forbidden, revealed, reveal_failed, rate_limited, no_such_key
	Files   []string  `json:"files,omitempty"`
	Detail  []string  `json:"detail,omitempty"` // issue codes or conflicting commits; never values
}

// Auditor records an AuditEntry.
type Auditor interface{ Record(AuditEntry) }

// AuditLog appends entries to a JSON Lines file (Path may be empty: only the
// log line is written) and logs each one.
type AuditLog struct {
	Path string
	Log  *slog.Logger
	mu   sync.Mutex
}

// Record implements Auditor. A failure to write the file is logged, never returned: the audit must not turn a refusal into an error.
func (a *AuditLog) Record(e AuditEntry) {
	if a == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if a.Log != nil {
		level, msg := slog.LevelWarn, "infra edit not committed"
		if e.Outcome == "revealed" {
			level, msg = slog.LevelInfo, "infra secret revealed"
		}
		a.Log.Log(context.Background(), level, msg, "who", e.Who, "action", e.Action, "outcome", e.Outcome, "files", e.Files, "detail", e.Detail)
	}
	if a.Path == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		if a.Log != nil {
			a.Log.Error("could not write the infra audit file", "path", a.Path, "err", err)
		}
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func sortStrings(s []string) { sort.Strings(s) }
