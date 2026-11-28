package accounts

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// Options opens the stores under a state directory.
type Options struct {
	StateDir string
	Key      *statekey.Key
	Log      *audit.Log
	// Pin is the retention pin the audit log was opened with (see NewPin); the store keeps it current.
	Pin    *Pin
	Now    func() time.Time
	Logger *slog.Logger

	hook func(step string) error // tests: crash points
}

// File names under the state directory.
const (
	accountsDir  = "accounts"
	accountsFile = "accounts.enc"
	secretsFile  = "secrets.enc"
	usernamesFil = "usernames"
)

// Store is the account store: encrypted, kept in memory, written by one writer (4.3).
type Store struct {
	o    Options
	eng  *engine[*State]
	used usedSet
	dir  string
}

func newStore(o Options) (*Store, error) {
	if o.Key == nil {
		return nil, errors.New("the account store needs the state key")
	}
	if o.Log == nil {
		return nil, errors.New("the account store needs the audit log")
	}
	dir := filepath.Join(o.StateDir, accountsDir)
	if err := EnsureDir(o.StateDir); err != nil {
		return nil, err
	}
	if err := EnsureDir(dir); err != nil {
		return nil, err
	}
	s := &Store{o: o, dir: dir}
	s.eng = newEngine(engineConfig[*State]{
		Dir: dir, Base: accountsFile, Purpose: statekey.PurposeAccounts, Marker: "change:",
		Key: o.Key, Log: o.Log, Now: o.Now, Logger: o.Logger, Hook: o.hook,
		New: func() *State { return newState() },
		OnSet: func(m Meta) {
			if o.Pin != nil {
				o.Pin.setAccounts(m)
			}
		},
	})
	return s, nil
}

// Open runs the start sequence of 4.3 and returns the store, or a *StartError: the server must
// not start (a wrong key, a gap, a rolled-back log, a bad MAC on the usernames).
func Open(o Options) (*Store, error) {
	s, err := newStore(o)
	if err != nil {
		return nil, err
	}
	if se := s.eng.start(); se != nil {
		return nil, se
	}
	if err := s.loadUsernames(s.eng.cur); err != nil {
		return nil, err
	}
	if o.Pin != nil {
		o.Pin.register(func() {
			if err := s.Checkpoint(); err != nil {
				s.eng.c.Logger.Error("account store: the checkpoint failed; retention stays held back", "err", err)
			}
		})
		if o.Pin.takeHeld() {
			if err := s.Checkpoint(); err != nil {
				return nil, fmt.Errorf("account store: checkpoint: %w", err)
			}
		}
	}
	return s, nil
}

// loadUsernames unions the three records (4.5) and writes the file when it lacks a name.
func (s *Store) loadUsernames(cur *State) error {
	path := filepath.Join(s.dir, usernamesFil)
	if err := promoteUsernamesNext(s.dir, s.o.Key); err != nil {
		return fmt.Errorf("usernames: %w", err)
	}
	fileNames, err := readUsernamesIfAny(path, s.o.Key)
	if err != nil {
		return err
	}
	inv, err := invitedTargets(s.o.Log)
	if err != nil {
		return err
	}
	all := slices.Concat(fileNames, cur.Usernames, cur.Names(), inv)
	s.used.add(all...)
	if got := s.used.list(); !slices.Equal(got, sortedUnique(fileNames)) {
		if err := WriteUsernames(path, s.o.Key, got); err != nil {
			return fmt.Errorf("usernames: %w", err)
		}
	}
	return nil
}

// Snapshot is a deep copy of the committed state. Changing it changes nothing.
func (s *Store) Snapshot() *State { return s.eng.snapshot() }

// UsernameUsed says whether name was ever used (4.5), by any of the three records.
func (s *Store) UsernameUsed(name string) bool { return s.used.has(name) }

// UsedUsernames lists every username ever used.
func (s *Store) UsedUsernames() []string { return s.used.list() }

// Evidence lists the evidence files set aside by the start sequence.
func (s *Store) Evidence() []string { return s.eng.evidence() }

// Recovered says the start recovered a change from its pending file.
func (s *Store) Recovered() bool { return s.eng.recovered }

// Change is a change of the store (4.3): fn edits a copy; the new state is written to .pending,
// ev (which gets "change:<id>") is appended with RecordSync, and only then does the new state
// replace the old one, on disk and in memory. If the audit append fails nothing changes and the
// error satisfies errors.Is(err, ErrAuditUnavailable). It returns the seq of the event.
func (s *Store) Change(ev audit.Event, fn func(*State) error) (int64, error) {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	return s.change(ev, fn)
}

func (s *Store) change(ev audit.Event, fn func(*State) error) (int64, error) {
	var added []string
	seq, err := s.eng.commit(ev, fn, func(cur, next *State) error {
		for n := range cur.Accounts {
			if next.Accounts[n] == nil {
				return ErrAccountDropped
			}
		}
		for n, a := range next.Accounts {
			if a == nil || a.Username != n || !ValidUsername(n) {
				return fmt.Errorf("account %q is malformed", n)
			}
			switch old := cur.Accounts[n]; {
			case old == nil:
				if s.used.has(n) {
					return ErrUsernameUsed
				}
				added = append(added, n)
			case old.ID != a.ID, old.State == StateRemoved && a.State != StateRemoved:
				return ErrAccountReplaced
			}
		}
		next.Usernames = sortedUnique(slices.Concat(s.used.list(), cur.Usernames, next.Names()))
		return nil
	}, func(next *State) error {
		// the event is in the log: the usernames record follows, before the store is renamed
		if len(added) == 0 {
			return nil
		}
		all := sortedUnique(slices.Concat(s.used.list(), added))
		if err := WriteUsernames(filepath.Join(s.dir, usernamesFil), s.o.Key, all); err != nil {
			return err
		}
		s.used.add(added...)
		return nil
	})
	return seq, err
}

// Counter writes a counter change (failure counts, locks, good buckets, last sign-in): the store's
// change id and audit seq stay. ev, when not nil, is appended first with RecordSync. At the first
// write in a month later than the store's audit month, a checkpoint is written first (4.6).
func (s *Store) Counter(ev *audit.Event, fn func(*State) error) error {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	if err := s.checkpointIfNewMonth(); err != nil {
		return err
	}
	return s.eng.counter(ev, fn)
}

func (s *Store) checkpointIfNewMonth() error {
	m := s.eng.cur.meta()
	if m.AuditSeq == 0 || s.eng.c.Now().UTC().Format("2006-01") <= m.AuditMonth {
		return nil
	}
	_, err := s.change(audit.Event{Event: "account_store_checkpoint"}, nil)
	return err
}

// Checkpoint writes the store as a change with an account_store_checkpoint event, which moves
// the retention pin to the current month (4.6). A store with no change yet pins nothing.
func (s *Store) Checkpoint() error {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	if s.eng.cur.meta().AuditSeq == 0 {
		return nil
	}
	_, err := s.change(audit.Event{Event: "account_store_checkpoint"}, nil)
	return err
}

// ---- read-only inspection, for `rackbook accounts list`

// Inspect decrypts the account store without recovering anything or writing a file. It returns
// the state, the evidence files and the names of leftover .pending and .next files.
func Inspect(stateDir string, key *statekey.Key) (*State, []string, []string, error) {
	dir := filepath.Join(stateDir, accountsDir)
	eng := newEngine(engineConfig[*State]{Dir: dir, Base: accountsFile, Purpose: statekey.PurposeAccounts, Key: key, New: func() *State { return newState() }})
	st, err := eng.readDoc(eng.path(""))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, fmt.Errorf("there is no account store in %s", dir)
		}
		return nil, nil, nil, keyErr(err, accountsFile)
	}
	var left []string
	for _, suf := range []string{".pending", ".next"} {
		if _, err := os.Lstat(eng.path(suf)); err == nil {
			left = append(left, accountsFile+suf)
		}
	}
	return st, eng.evidence(), left, nil
}

// UseTOTP checks a code against the account's TOTP and records the step as last_step in one counter
// write, under the single writer: two requests with the same code cannot both pass. A wrong,
// malformed or used code, an account without TOTP and an unknown account all give ErrBadCode. ev, when
// not nil, is appended with RecordSync before the step is stored.
func (s *Store) UseTOTP(username, code string, now time.Time, ev *audit.Event) error {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	a := s.eng.cur.Accounts[username]
	if a == nil || a.TOTP == nil {
		return ErrBadCode
	}
	step, err := VerifyTOTP(a.TOTP.Secret, code, now, a.TOTP.LastStep)
	if err != nil {
		return err
	}
	return s.eng.counter(ev, func(st *State) error {
		st.Accounts[username].TOTP.LastStep = step
		return nil
	})
}
