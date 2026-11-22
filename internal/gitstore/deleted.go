package gitstore

// Deleted records (docs/design-audit.md, section 3.3): the records whose last
// change removed them. Finding them reads the collection file's whole history, so
// what was found is kept: with a state directory in <state>/history/deleted-<collection>.json,
// without one in memory. The file is a cache and deleting it is always safe. It
// is keyed by the commit the history was read to and extended from there; it is
// built a few hundred commits at a time, so a long history is read over several
// requests.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/kazuhahub/rackbook/internal/ledger"
)

// Limits of the deleted-records list, variables for the tests.
var (
	DeletedBudget    = 200  // commits one request reads
	maxDeletedEvents = 5000 // events kept per collection (the oldest are dropped)
	maxDeletedList   = 200  // records one answer lists
)

const deletedCacheVersion = 1

// DeletedEvent is one record removed by one commit. ID is the id as it is shown
// (redacted when its key holds a secret): the cache never holds a secret.
type DeletedEvent struct {
	ID string `json:"id"`
	// Commit removed the record; Last is the commit that still had it (its first parent).
	Commit string    `json:"commit"`
	Last   string    `json:"last"`
	Time   time.Time `json:"time"`
	// The deleting commit as the activity view shows it.
	Subject   string `json:"subject,omitempty"`
	Author    string `json:"author,omitempty"`
	Email     string `json:"email,omitempty"`
	EditedBy  string `json:"editedBy,omitempty"`
	EditedVia string `json:"editedVia,omitempty"`
}

// deletedState is what is kept for one collection.
type deletedState struct {
	Version    int    `json:"version"`
	Collection string `json:"collection"`
	File       string `json:"file"` // the collection's file the history was read for
	// Tip: the events below are those of every commit reachable from it that
	// touched the file ("" = nothing read yet).
	Tip    string         `json:"tip"`
	Events []DeletedEvent `json:"events"` // newest first
	// Pending is a read that is not finished: commits of the walk from Tip (but not
	// from Base) already read, Events newest first.
	Pending *deletedPending `json:"pending,omitempty"`
}

type deletedPending struct {
	Tip    string         `json:"tip"`
	Base   string         `json:"base,omitempty"` // read only what is not reachable from Base
	Skip   int            `json:"skip"`
	Events []DeletedEvent `json:"events"`
}

// DeletedResult is what DeletedRecords returns.
type DeletedResult struct {
	// Records are the deleted records, the newest deletion first.
	Records []DeletedEvent
	// Complete is false while the history is not yet read to its end: Records is
	// what is known, and a later call goes on.
	Complete bool
}

func (st *deletedState) valid() bool {
	ok := func(e DeletedEvent) bool {
		return hexRe.MatchString(e.Commit) && hexRe.MatchString(e.Last) && e.ID != ""
	}
	if st.Version != deletedCacheVersion || (st.Tip != "" && !hexRe.MatchString(st.Tip)) {
		return false
	}
	for _, e := range st.Events {
		if !ok(e) {
			return false
		}
	}
	if p := st.Pending; p != nil {
		if !hexRe.MatchString(p.Tip) || (p.Base != "" && !hexRe.MatchString(p.Base)) || p.Skip < 0 {
			return false
		}
		for _, e := range p.Events {
			if !ok(e) {
				return false
			}
		}
	}
	return true
}

// deletedFile is the cache file of a collection; a name that is not a plain file
// name is replaced by a hash of it.
func (s *Store) deletedFile(collection string) string {
	if s.opts.StateDir == "" {
		return ""
	}
	name := collection
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$`).MatchString(name) {
		sum := sha256.Sum256([]byte(collection))
		name = "x" + hex.EncodeToString(sum[:6])
	}
	return filepath.Join(s.opts.StateDir, "history", "deleted-"+name+".json")
}

func (s *Store) loadDeleted(collection, file string) *deletedState {
	fresh := &deletedState{Version: deletedCacheVersion, Collection: collection, File: file}
	var st *deletedState
	if p := s.deletedFile(collection); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return fresh
		}
		st = &deletedState{}
		if json.Unmarshal(b, st) != nil {
			return fresh
		}
	} else {
		s.delMu.Lock()
		st = s.delMem[collection]
		s.delMu.Unlock()
		if st != nil {
			cp := *st
			st = &cp
		}
	}
	if st == nil || !st.valid() || st.Collection != collection || st.File != file {
		return fresh
	}
	return st
}

func (s *Store) saveDeleted(st *deletedState) {
	p := s.deletedFile(st.Collection)
	if p == "" {
		cp := *st
		s.delMu.Lock()
		if s.delMem == nil {
			s.delMem = map[string]*deletedState{}
		}
		s.delMem[st.Collection] = &cp
		s.delMu.Unlock()
		return
	}
	b, err := json.Marshal(st)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(p), 0o700)
	}
	if err == nil {
		tmp := p + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			if err = os.Rename(tmp, p); err != nil {
				_ = os.Remove(tmp)
			}
		}
	}
	if err != nil {
		s.log.Warn("could not keep the deleted records of a collection", "collection", st.Collection, "err", err)
	}
}

// DeletedRecords lists the records of the collection whose last change removed
// them, newest deletion first: not the ones deleted and added again, and not the
// ones that were only renamed. It reads at most DeletedBudget commits of the
// collection file's history per call and keeps the result (see the file comment).
func (s *Store) DeletedRecords(ctx context.Context, collection string) (*DeletedResult, error) {
	col := s.cur.Load().Collection(collection)
	if col == nil {
		return nil, fmt.Errorf("unknown collection %q", collection)
	}
	res := &DeletedResult{Complete: true}
	if !s.git || len(col.Key) == 0 {
		return res, nil // without a key a record has no identity to be found by
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return res, nil
	}
	// one build at a time per store: they are bounded, and two would repeat each other's work
	s.delBuild.Lock()
	defer s.delBuild.Unlock()
	st := s.loadDeleted(collection, col.File)
	if st.Pending != nil {
		// a pending read is pinned to the tip it began at; it is dropped when that
		// commit is not on the branch any more (history rewritten)
		if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", st.Pending.Tip, tip); err != nil {
			st.Pending = nil
		}
	}
	if st.Tip != "" && st.Tip != tip {
		if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", st.Tip, tip); err != nil {
			*st = deletedState{Version: deletedCacheVersion, Collection: collection, File: col.File} // rewritten: rebuild
		}
	}
	if st.Pending == nil && st.Tip != tip {
		st.Pending = &deletedPending{Tip: tip, Base: st.Tip}
	}
	if st.Pending != nil {
		if err := s.extendDeleted(ctx, col, st); err != nil {
			return nil, err
		}
		s.saveDeleted(st)
	}
	events := st.Events
	if p := st.Pending; p != nil {
		res.Complete = false
		events = append(append([]DeletedEvent{}, p.Events...), st.Events...)
	}
	cfg := s.Config()
	now := map[string]bool{}
	for _, r := range col.Records {
		now[ledger.SafeID(cfg, collection, r.ID)] = true
	}
	seen := map[string]bool{}
	for _, e := range events {
		if seen[e.ID] {
			continue // an older deletion of an id that was deleted again later
		}
		seen[e.ID] = true
		if now[e.ID] {
			continue // added again
		}
		res.Records = append(res.Records, e)
		if len(res.Records) >= maxDeletedList {
			break
		}
	}
	return res, nil
}

// extendDeleted reads up to DeletedBudget more commits of the pending walk. When
// the walk ends the events replace or extend the finished ones.
func (s *Store) extendDeleted(ctx context.Context, col *ledger.Collection, st *deletedState) error {
	p := st.Pending
	rd := s.newSnapReader(ctx, col.Name)
	cfg := s.Config()
	n := 0
	var inner error
	err := activityLog(ctx, s.repo, p.Tip, ActivityQuery{Skip: p.Skip, Limit: min(DeletedBudget, MaxActivity), Exclude: p.Base},
		[]string{filepath.FromSlash(col.File)}, "", func(c ActivityCommit) bool {
			n++
			if c.Parent == "" || !hexRe.MatchString(c.Parent) {
				return true // the first commit removed nothing
			}
			cur, err := rd.at(c.Hash)
			if err == nil {
				var prev *snapshot
				if prev, err = rd.at(c.Parent); err == nil && !cur.broken && !prev.broken && prev.found {
					for _, r := range prev.recs {
						if cur.byID[r.ID] != nil || prev.byID[r.ID] != r || renamedTo(prev, cur, r) != nil {
							continue
						}
						p.Events = append(p.Events, DeletedEvent{ID: ledger.SafeID(cfg, col.Name, r.ID), Commit: c.Hash, Last: c.Parent, Time: c.Time,
							Subject: c.Subject, Author: c.Author, Email: c.Email, EditedBy: c.EditedBy, EditedVia: c.EditedVia})
						if len(p.Events) > maxDeletedEvents {
							break
						}
					}
				}
			}
			if err != nil {
				inner = err
				return false
			}
			return true
		})
	if err == nil {
		err = inner
	}
	if err != nil {
		return err
	}
	p.Skip += n
	if n >= min(DeletedBudget, MaxActivity) {
		return nil // maybe more
	}
	// the walk is finished
	events := p.Events
	if p.Base != "" && st.Tip == p.Base {
		events = append(append([]DeletedEvent{}, p.Events...), st.Events...)
	}
	if len(events) > maxDeletedEvents {
		events = events[:maxDeletedEvents]
	}
	st.Tip, st.Events, st.Pending = p.Tip, events, nil
	return nil
}

// ActivityCommit is the deleting commit as the activity view shows commits.
func (e DeletedEvent) ActivityCommit() ActivityCommit {
	return ActivityCommit{Hash: e.Commit, Short: e.Commit[:7], Author: e.Author, Email: e.Email, Time: e.Time, Subject: e.Subject,
		EditedBy: e.EditedBy, EditedVia: e.EditedVia, State: StateNone}
}

// DeletedSummary is a deleted record with a few fields of its last version.
type DeletedSummary struct {
	DeletedEvent
	// Fields are the fields a list of the collection shows, with the values of the
	// last version (without the ones the secret scan flags).
	Fields []SummaryField
}

// SummaryField is one field of a summary.
type SummaryField struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// Summaries reads the last version of each deleted record, for a few display
// fields: the collection's list columns, else its label and key fields.
func (s *Store) Summaries(ctx context.Context, collection string, evs []DeletedEvent) ([]DeletedSummary, error) {
	col := s.cur.Load().Collection(collection)
	if col == nil {
		return nil, fmt.Errorf("unknown collection %q", collection)
	}
	fields := append([]string{}, col.List...)
	if len(fields) == 0 {
		if col.Label != "" {
			fields = append(fields, col.Label)
		}
		fields = append(fields, col.Key...)
	}
	if len(fields) > 4 {
		fields = fields[:4]
	}
	cfg := s.Config()
	rd := s.newSnapReader(ctx, collection)
	out := make([]DeletedSummary, 0, len(evs))
	for _, e := range evs {
		d := DeletedSummary{DeletedEvent: e}
		sn, err := rd.at(e.Last)
		if err != nil {
			return nil, err
		}
		if rec := sn.find(cfg, e.ID); rec != nil {
			hidden := hideFindings(rec.Data, scanOf(cfg.SecretScanner(), collection, cfg, sn, rec))
			for _, f := range fields {
				v, ok := hidden[f]
				if !ok {
					continue
				}
				v, _ = scrub(v)
				txt := ledger.Str(v)
				if r := []rune(txt); len(r) > 120 {
					txt = string(r[:120]) + "…"
				}
				d.Fields = append(d.Fields, SummaryField{Field: f, Value: txt})
			}
		}
		out = append(out, d)
	}
	return out, nil
}
