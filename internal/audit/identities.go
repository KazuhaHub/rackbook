package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// identitiesName is the file in the audit directory that remembers, for each
// person who signed in, the role they had the last time Rackbook looked. It is
// what makes a role_changed event possible: the claims of a sign-in are not
// kept, so the only thing a later look can be compared with is the role itself.
const identitiesName = "identities.json"

// MaxIdentities bounds identities.json. When a new person would go over it, the
// people whose last sign-in is the oldest are dropped. They are then simply new
// at their next sign-in: no role_changed is written for the first time Rackbook
// sees someone. About 150 bytes per entry, so the file stays under 1 MB.
const MaxIdentities = 5000

// IdentityRecord is what identities.json keeps about one person: no groups, no
// claims, nothing the identity provider sent beyond the display name.
type IdentityRecord struct {
	Name       string    `json:"name,omitempty"`
	Role       string    `json:"role"`              // the effective role the last time it was looked at
	Auditor    bool      `json:"auditor,omitempty"` // on auth.auditors then
	LastSignIn time.Time `json:"lastSignIn"`        // UTC
	Method     string    `json:"method"`            // how they signed in then
}

// IdentityEntry is a record with the identity it belongs to.
type IdentityEntry struct {
	Identity string `json:"identity"`
	IdentityRecord
}

type identitiesFile struct {
	Version    int                       `json:"version"`
	Identities map[string]IdentityRecord `json:"identities"`
}

// Role causes of a role_changed event.
const (
	CauseSignIn = "sign_in" // the person signed in and their role differs from the stored one
	CauseConfig = "config"  // rackbook.yml changed, and at their next request their role differs
)

// RoleObservation is one look at a person's effective role.
type RoleObservation struct {
	Identity string
	Name     string
	Method   string
	Role     string // roles.Role.String(): none, viewer, editor, admin
	Auditor  bool
	Addr     string
	Cause    string // CauseSignIn or CauseConfig
	// SignedIn says a session was just issued: the record is created if needed
	// and its last sign-in, name and method are updated. Without it (a refused
	// sign-in, or a request under a new config) only a person already stored is
	// compared, and only role and auditor are updated.
	SignedIn bool
	// Session is when the session in use was issued (a request under a new
	// config). A person who has signed in again since is left to that newer
	// session, so two sessions with different claims cannot write each other's
	// changes back and forth.
	Session time.Time
}

// ObserveRole compares the observed role with the stored one, keeps the new
// one, and writes role_changed to the log when they differ. A person Rackbook
// has not seen before has nothing to be compared with: no event. It reports
// whether an event was written. A nil Log does nothing.
func (l *Log) ObserveRole(o RoleObservation) bool {
	if l == nil || o.Identity == "" {
		return false
	}
	changed, err := l.ids.observe(l, o)
	if err != nil {
		l.log.Error("audit log: could not write identities.json", "err", err)
	}
	return changed
}

// Identities lists what identities.json holds, the most recent sign-in first.
func (l *Log) Identities() []IdentityEntry {
	if l == nil {
		return nil
	}
	return l.ids.list(l)
}

// identityStore is identities.json in memory; the caller of every method passes
// the Log whose lock-free fields (dir, clock) it needs. It has a lock of its
// own and is never used while Log.mu is held.
type identityStore struct {
	mu     sync.Mutex
	loaded bool
	m      map[string]IdentityRecord
	max    int
}

func newIdentityStore() *identityStore { return &identityStore{max: MaxIdentities} }

func (s *identityStore) path(l *Log) string { return filepath.Join(l.dir, identitiesName) }

// load reads the file once. A file that does not parse is set aside (never
// deleted) and the store starts empty: losing the memory of last roles only
// means the next look of each person writes no event.
func (s *identityStore) load(l *Log) {
	if s.loaded {
		return
	}
	s.loaded = true
	s.m = map[string]IdentityRecord{}
	b, err := os.ReadFile(s.path(l))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var f identitiesFile
	if err == nil {
		err = json.Unmarshal(b, &f)
	}
	if err != nil || f.Version != 1 {
		if err == nil {
			err = fmt.Errorf("unknown version %d", f.Version)
		}
		aside := s.path(l) + ".unreadable"
		l.log.Error("audit log: identities.json cannot be read; it is set aside and the store starts empty", "err", err, "aside", filepath.Base(aside))
		_ = os.Rename(s.path(l), aside)
		return
	}
	for id, r := range f.Identities {
		s.m[id] = r
	}
}

// observe is ObserveRole under the store's lock. The event is appended before
// the file is rewritten: after a crash between the two, the next look writes the
// event again, which is better than never.
func (s *identityStore) observe(l *Log, o RoleObservation) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load(l)
	prev, existed := s.m[o.Identity]
	if !o.SignedIn && !existed {
		return false, nil
	}
	if !o.SignedIn && !o.Session.IsZero() && o.Session.Truncate(time.Second).Before(prev.LastSignIn.Truncate(time.Second)) {
		// signed in again since: that sign-in's claims are the newer truth
		return false, nil
	}
	next := prev
	next.Role, next.Auditor = o.Role, o.Auditor
	if o.SignedIn {
		if o.Name != "" {
			next.Name = o.Name
		}
		next.Method = o.Method
		next.LastSignIn = l.opts.Now().UTC().Truncate(time.Second)
	}
	if existed && (prev.Role != o.Role || prev.Auditor != o.Auditor) {
		af, at := prev.Auditor, o.Auditor
		l.Record(Event{Event: "role_changed", Identity: o.Identity, Name: o.Name, Method: o.Method, Addr: o.Addr,
			From: prev.Role, To: o.Role, AuditorFrom: &af, AuditorTo: &at, Cause: o.Cause})
		changed = true
	}
	if existed && !o.SignedIn && !changed {
		return false, nil // nothing to store
	}
	s.m[o.Identity] = next
	s.evict(o.Identity)
	return changed, s.write(l)
}

// evict drops the people with the oldest last sign-in until the store fits max.
// keep is never dropped (it is the one just written).
func (s *identityStore) evict(keep string) {
	for len(s.m) > s.max {
		oldest, found := "", false
		for id, r := range s.m {
			if id == keep {
				continue
			}
			if !found || r.LastSignIn.Before(s.m[oldest].LastSignIn) || (r.LastSignIn.Equal(s.m[oldest].LastSignIn) && id < oldest) {
				oldest, found = id, true
			}
		}
		if !found {
			return
		}
		delete(s.m, oldest)
	}
}

func (s *identityStore) list(l *Log) []IdentityEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load(l)
	out := make([]IdentityEntry, 0, len(s.m))
	for id, r := range s.m {
		out = append(out, IdentityEntry{Identity: id, IdentityRecord: r})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSignIn.Equal(out[j].LastSignIn) {
			return out[i].LastSignIn.After(out[j].LastSignIn)
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

// write replaces identities.json: a temp file of mode 0600, fsync, rename, fsync of
// the directory, so a reader sees the old file or the new one and never half.
func (s *identityStore) write(l *Log) error {
	b, err := json.Marshal(identitiesFile{Version: 1, Identities: s.m})
	if err != nil {
		return err
	}
	tmp := s.path(l) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	if werr == nil {
		werr = f.Chmod(0o600) // a file that already existed keeps its old mode otherwise
	}
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
	if err := os.Rename(tmp, s.path(l)); err != nil {
		return err
	}
	return syncDir(l.dir)
}
