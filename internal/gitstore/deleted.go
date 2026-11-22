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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/ledger"
)

// Limits of the deleted-records list, variables for the tests.
var (
	DeletedBudget    = 200  // commits one request reads
	maxDeletedEvents = 5000 // events kept per collection (the oldest are dropped)
	maxDeletedList   = 200  // records one answer lists
)

const deletedCacheVersion = 2

// DeletedEvent is one record removed by one commit. ID is the id as it is shown
// (redacted when its key holds a secret): the cache never holds a secret.
type DeletedEvent struct {
	ID string `json:"id"`
	// Fields are a few fields of the last version for a summary, already without the
	// values the secret scan flags.
	Fields []SummaryField `json:"fields,omitempty"`
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
	// Fingerprint says what the ids and summaries below were made with (the secret
	// scan, the collection's type, key and list fields): when it is not today's they
	// are made again.
	Fingerprint string `json:"fingerprint"`
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

func cloneEvents(in []DeletedEvent) []DeletedEvent {
	out := make([]DeletedEvent, len(in))
	for i, e := range in {
		out[i] = e
		out[i].Fields = append([]SummaryField(nil), e.Fields...)
	}
	return out
}

// clone is a deep copy: the in-memory cache never shares a slice with a caller.
func (st *deletedState) clone() *deletedState {
	cp := *st
	cp.Events = cloneEvents(st.Events)
	if st.Pending != nil {
		p := *st.Pending
		p.Events = cloneEvents(st.Pending.Events)
		cp.Pending = &p
	}
	return &cp
}

// deletedFingerprint is what the cached ids and summaries depend on besides the history.
func (s *Store) deletedFingerprint(col *ledger.Collection) string {
	cfg := s.Config()
	h := sha256.New()
	for _, part := range [][]byte{[]byte(cfg.SecretScanner().Fingerprint()), col.SchemaRaw, []byte(strings.Join(col.Key, "\x01")), []byte(strings.Join(col.List, "\x01")), []byte(col.Label)} {
		h.Write(part)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
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

func (s *Store) loadDeleted(collection, file, fp string) *deletedState {
	fresh := &deletedState{Version: deletedCacheVersion, Collection: collection, File: file, Fingerprint: fp}
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
			st = st.clone()
		}
	}
	if st == nil || !st.valid() || st.Collection != collection || st.File != file || st.Fingerprint != fp {
		return fresh
	}
	return st
}

func (s *Store) saveDeleted(st *deletedState) {
	p := s.deletedFile(st.Collection)
	if p == "" {
		cp := st.clone()
		s.delMu.Lock()
		if s.delMem == nil {
			s.delMem = map[string]*deletedState{}
		}
		s.delMem[st.Collection] = cp
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
// collection file's history per call (and works at most DeletedTimeBudget) and keeps
// the result (see the file comment). Serving the list reads nothing from Git except
// that every commit it names is checked, once, to be on the tracked branch.
func (s *Store) DeletedRecords(ctx context.Context, collection string) (*DeletedResult, error) {
	col := s.cur.Load().Collection(collection)
	if col == nil {
		return nil, fmt.Errorf("unknown collection %q", collection)
	}
	if !s.git || len(col.Key) == 0 {
		return &DeletedResult{Complete: true}, nil // without a key a record has no identity to be found by
	}
	tip, ok := s.trackedTip(ctx)
	if !ok {
		return &DeletedResult{Complete: true}, nil
	}
	// one build at a time per store: they are bounded, and two would repeat each other's work
	s.delBuild.Lock()
	defer s.delBuild.Unlock()
	res, err := s.deletedOnce(ctx, col, tip)
	if errors.Is(err, errCacheUnreachable) {
		res, err = s.deletedOnce(ctx, col, tip) // the cache was dropped: once more, from nothing
	}
	return res, err
}

// errCacheUnreachable says a cached commit is not on the tracked branch: the cache was dropped.
var errCacheUnreachable = errors.New("the deleted-records cache names a commit that is not on the branch")

func (s *Store) deletedOnce(ctx context.Context, col *ledger.Collection, tip string) (*DeletedResult, error) {
	collection := col.Name
	res := &DeletedResult{Complete: true}
	fp := s.deletedFingerprint(col)
	st := s.loadDeleted(collection, col.File, fp)
	reset := func() {
		*st = deletedState{Version: deletedCacheVersion, Collection: collection, File: col.File, Fingerprint: fp}
		s.delMu.Lock()
		s.delOK = nil
		s.delMu.Unlock()
	}
	if st.Pending != nil {
		// a pending read is pinned to the tip it began at; it is dropped when that
		// commit is not on the branch any more (history rewritten)
		if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", st.Pending.Tip, tip); err != nil {
			st.Pending = nil
		}
	}
	if st.Tip != "" && st.Tip != tip {
		if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", st.Tip, tip); err != nil {
			reset() // rewritten: rebuild
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
	// the cache may have been edited or come from a branch that was rewritten: what is
	// named has to be on the tracked branch (checked once per commit, then remembered)
	for _, e := range res.Records {
		for _, h := range []string{e.Commit, e.Last} {
			ok, err := s.reachableFrom(ctx, h, tip)
			if err != nil {
				return nil, err
			}
			if !ok {
				reset()
				s.saveDeleted(st)
				return nil, errCacheUnreachable
			}
		}
	}
	return res, nil
}

// reachableFrom says whether the commit is on the history of tip; what was found
// reachable is remembered (it stays so while the history is only added to, and the
// memory is cleared when a cache is dropped).
func (s *Store) reachableFrom(ctx context.Context, commit, tip string) (bool, error) {
	s.delMu.Lock()
	ok := s.delOK[commit]
	s.delMu.Unlock()
	if ok {
		return true, nil
	}
	if _, err := s.repo.git(ctx, "merge-base", "--is-ancestor", commit, tip); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	s.delMu.Lock()
	if s.delOK == nil {
		s.delOK = map[string]bool{}
	}
	s.delOK[commit] = true
	s.delMu.Unlock()
	return true, nil
}

// summaryFieldNames are the fields a summary of a record of the collection shows:
// its list columns, else its label and key fields.
func summaryFieldNames(col *ledger.Collection) []string {
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
	return fields
}

// summaryOf makes the summary fields of a record (as it was in sn), without the
// values that are hidden.
func (s *Store) summaryOf(col *ledger.Collection, sn *snapshot, rec *ledger.Record) []SummaryField {
	hidden := hideFindings(rec.Data, s.findingsOf(col.Name, sn, rec))
	var out []SummaryField
	for _, f := range summaryFieldNames(col) {
		v, ok := hidden[f]
		if !ok {
			continue
		}
		v, _ = scrub(v)
		txt := ledger.Str(v)
		if r := []rune(txt); len(r) > 120 {
			txt = string(r[:120]) + "…"
		}
		out = append(out, SummaryField{Field: f, Value: txt})
	}
	return out
}

// DeletedTimeBudget is how long one call reads history before it ends the chunk.
var DeletedTimeBudget = 700 * time.Millisecond

// extendDeleted reads up to DeletedBudget more commits of the pending walk. When
// the walk ends the events replace or extend the finished ones.
func (s *Store) extendDeleted(ctx context.Context, col *ledger.Collection, st *deletedState) error {
	p := st.Pending
	rd := s.newSnapReader(ctx, col.Name)
	cfg := s.Config()
	n := 0
	start := time.Now()
	timedOut := false
	var inner error
	err := activityLog(ctx, s.repo, p.Tip, ActivityQuery{Skip: p.Skip, Limit: min(DeletedBudget, MaxActivity), Exclude: p.Base},
		[]string{filepath.FromSlash(col.File)}, "", func(c ActivityCommit) bool {
			n++
			if c.Parent != "" && hexRe.MatchString(c.Parent) { // the first commit removed nothing
				if err := s.deletedAt(rd, col, cfg, c, p); err != nil {
					inner = err
					return false
				}
			}
			if time.Since(start) > DeletedTimeBudget {
				timedOut = true
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
	if timedOut || n >= min(DeletedBudget, MaxActivity) {
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

// deletedAt adds to p the events of the records that commit c removed.
func (s *Store) deletedAt(rd *snapReader, col *ledger.Collection, cfg *config.Config, c ActivityCommit, p *deletedPending) error {
	ct, err := rd.tree(c.Hash)
	if err != nil {
		return err
	}
	pt, err := rd.tree(c.Parent)
	if err != nil {
		return err
	}
	if ct.found == pt.found && ct.fileBlob == pt.fileBlob {
		return nil // the same file: nothing was removed
	}
	cur, err := rd.at(c.Hash)
	if err != nil {
		return err
	}
	prev, err := rd.at(c.Parent)
	if err != nil {
		return err
	}
	if cur.unreadable || prev.unreadable || !prev.found {
		return nil // nothing can be said of this commit; the walk goes on past it
	}
	for _, r := range prev.recs {
		if cur.byID[r.ID] != nil || prev.byID[r.ID] != r || renamedTo(prev, cur, r) != nil {
			continue
		}
		p.Events = append(p.Events, DeletedEvent{ID: ledger.SafeID(cfg, col.Name, r.ID), Fields: s.summaryOf(col, prev, r), Commit: c.Hash, Last: c.Parent, Time: c.Time,
			Subject: c.Subject, Author: c.Author, Email: c.Email, EditedBy: c.EditedBy, EditedVia: c.EditedVia})
		if len(p.Events) > maxDeletedEvents {
			break
		}
	}
	return nil
}

// ActivityCommit is the deleting commit as the activity view shows commits.
func (e DeletedEvent) ActivityCommit() ActivityCommit {
	return ActivityCommit{Hash: e.Commit, Short: e.Commit[:7], Author: e.Author, Email: e.Email, Time: e.Time, Subject: e.Subject,
		EditedBy: e.EditedBy, EditedVia: e.EditedVia, State: StateNone}
}

// SummaryField is one field of a summary.
type SummaryField struct {
	Field string `json:"field"`
	Value string `json:"value"`
}
