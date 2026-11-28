package ansiblerepo

import (
	"context"
	"log/slog"
	"sort"
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
	Via     string    `json:"via,omitempty"`    // how Who is an infra administrator: identity, group or app_role
}

// Auditor records an AuditEntry.
type Auditor interface{ Record(AuditEntry) }

// AuditLog logs each entry. The audit file is kept by internal/audit, which wraps
// this Auditor; this one only writes the server log lines.
type AuditLog struct {
	Log *slog.Logger
}

// Record implements Auditor.
func (a *AuditLog) Record(e AuditEntry) {
	if a == nil || a.Log == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	level, msg := slog.LevelWarn, "infra edit not committed"
	if e.Outcome == "revealed" {
		level, msg = slog.LevelInfo, "infra secret revealed"
	}
	a.Log.Log(context.Background(), level, msg, "who", e.Who, "action", e.Action, "outcome", e.Outcome, "files", e.Files, "detail", e.Detail)
}

func sortStrings(s []string) { sort.Strings(s) }
