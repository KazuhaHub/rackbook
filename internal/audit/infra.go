package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kazuhahub/rackbook/internal/ansiblerepo"
)

const migratedName = "migrated"

// FromInfra maps an infra audit entry to an event: the outcome says which one.
func FromInfra(a ansiblerepo.AuditEntry) Event {
	e := Event{Time: a.Time, Identity: a.Who, Action: a.Action, Outcome: a.Outcome, Files: a.Files, Detail: a.Detail, Area: "infra", InfraVia: a.Via}
	switch a.Outcome {
	case "revealed":
		e.Event = "secret_revealed"
	case "reveal_failed", "rate_limited", "no_such_key":
		e.Event = "secret_reveal_refused"
	case "reencrypted":
		e.Event = "reencrypted"
	default:
		e.Event, e.Code = "write_refused", a.Outcome
	}
	if e.Event != "write_refused" {
		// "infra(secrets/<host>): reveal ..." names the host
		if _, rest, ok := strings.Cut(a.Action, "infra(secrets/"); ok {
			e.Host, _, _ = strings.Cut(rest, ")")
		}
	}
	return e
}

// InfraAuditor passes each infra entry to Next first (the existing server log
// lines stay) and then records it in the audit log.
type InfraAuditor struct {
	Log  *Log
	Next ansiblerepo.Auditor
}

// Record implements ansiblerepo.Auditor.
func (a *InfraAuditor) Record(e ansiblerepo.AuditEntry) {
	if a == nil {
		return
	}
	if a.Next != nil {
		a.Next.Record(e)
	}
	a.Log.Record(FromInfra(e))
}

// marker is <dir>/migrated. While the copy runs it says in_progress, with the
// number of source lines and the seq the first copied line gets; so a copy cut
// short by a crash is finished, not repeated.
type marker struct {
	State       string `json:"state"` // in_progress | done
	SourceLines int    `json:"source_lines"`
	FirstSeq    int64  `json:"first_seq"`
}

var errMigrationStopped = errors.New("migration stopped")

// MigrateInfra copies the entries of the old infra-audit.jsonl into the log,
// once. The old file is left where it is. Open calls it before anything else
// can append, so the events from first_seq on are the copied ones (apart from
// chain_problem events the same start wrote), and counting them says how far a
// copy that was cut short had come; that makes the resume deterministic.
func (l *Log) MigrateInfra(oldPath string) error {
	if l == nil || oldPath == "" {
		return nil
	}
	m, found, err := l.readMarker()
	if err != nil {
		return err
	}
	if found && m.State != "in_progress" {
		return nil // "done", or a marker of an unknown shape: leave it alone
	}
	entries, err := readInfra(oldPath, l.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	done := 0
	if found {
		if done, err = l.countMigrated(m.FirstSeq); err != nil {
			return err
		}
		if m.SourceLines != len(entries) {
			l.log.Warn("audit log: the old infra audit file changed since the copy began", "was", m.SourceLines, "now", len(entries))
		}
		if done > len(entries) {
			done = len(entries)
		}
	} else {
		l.mu.Lock()
		m = marker{State: "in_progress", SourceLines: len(entries), FirstSeq: l.seq + 1}
		l.mu.Unlock()
		if err := l.writeMarker(m); err != nil {
			return err
		}
	}
	for i := done; i < len(entries); i++ {
		if l.opts.migrateStop != nil && l.opts.migrateStop(i) {
			return errMigrationStopped
		}
		l.mu.Lock()
		err := l.append(FromInfra(entries[i]))
		l.mu.Unlock()
		if err != nil {
			return err // the marker stays in_progress: the next start continues
		}
	}
	m.State = "done"
	if err := l.writeMarker(m); err != nil {
		return err
	}
	l.log.Info("audit log: copied the old infra audit file", "entries", len(entries)-done, "from", oldPath)
	return nil
}

// readInfra returns the parsable entries of the old file; a line that does
// not parse is skipped with a warning.
func readInfra(path string, log *slog.Logger) ([]ansiblerepo.AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ansiblerepo.AuditEntry
	br := bufio.NewReader(f)
	for {
		line, rerr := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var a ansiblerepo.AuditEntry
			if err := json.Unmarshal(line, &a); err != nil {
				log.Warn("audit log: skipped a line of the old infra audit file that does not parse", "file", path)
			} else {
				out = append(out, a)
			}
		}
		if rerr == io.EOF {
			return out, nil
		}
		if rerr != nil {
			return nil, rerr
		}
	}
}

func (l *Log) readMarker() (marker, bool, error) {
	b, err := os.ReadFile(filepath.Join(l.dir, migratedName))
	if errors.Is(err, os.ErrNotExist) {
		return marker{}, false, nil
	}
	if err != nil {
		return marker{}, false, err
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		return marker{State: "unknown"}, true, nil
	}
	return m, true, nil
}

// writeMarker replaces the marker: temp file, fsync, rename, fsync of the directory.
func (l *Log) writeMarker(m marker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	path := filepath.Join(l.dir, migratedName)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(l.dir)
}

// countMigrated counts the events from seq on that are not chain_problem events.
func (l *Log) countMigrated(seq int64) (int, error) {
	files, err := listFiles(l.dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range files {
		f, err := os.Open(filepath.Join(l.dir, name))
		if err != nil {
			return 0, err
		}
		br := bufio.NewReader(f)
		for {
			line, rerr := br.ReadBytes('\n')
			var e Event
			if len(line) > 0 && line[len(line)-1] == '\n' && json.Unmarshal(line, &e) == nil && e.Seq >= seq && e.Event != ChainProblemEvent {
				n++
			}
			if rerr != nil {
				break
			}
		}
		f.Close()
	}
	return n, nil
}
