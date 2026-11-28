package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
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

	revMu  sync.Mutex
	revFor *State
	revSet map[string]struct{}
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
	// a half-written grant file of accept-restore (a .tmp, a symlink included) goes at start
	if err := os.Remove(filepath.Join(o.StateDir, "oauth-grants.json.tmp")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	s := &Store{o: o, dir: dir}
	s.eng = newEngine(engineConfig[*State]{
		Dir: dir, Base: accountsFile, Purpose: statekey.PurposeAccounts, Marker: accountsMarker, Events: accountChangeEvents,
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
		o.Pin.register(whoAccounts, func() {
			if err := s.Checkpoint(); err != nil {
				s.eng.c.Logger.Error("account store: the checkpoint failed; retention stays held back", "err", err)
			}
		})
		if o.Pin.takeHeld(whoAccounts) {
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

// IsRevoked says whether the token (by the SHA-256 of its secret) or the grant (by its id) is on the revocation list. It is cheap
// enough for every request: the set is built once per committed state.
func (s *Store) IsRevoked(kind, id string) bool {
	s.eng.mu.RLock()
	cur := s.eng.cur
	s.eng.mu.RUnlock()
	s.revMu.Lock()
	defer s.revMu.Unlock()
	if s.revFor != cur {
		s.revSet = make(map[string]struct{}, len(cur.Revoked))
		for _, r := range cur.Revoked {
			s.revSet[r.Kind+"\x00"+r.ID] = struct{}{}
		}
		s.revFor = cur
	}
	_, ok := s.revSet[kind+"\x00"+id]
	return ok
}

// RevokedIDs lists the ids of one kind on the revocation list.
func (s *Store) RevokedIDs(kind string) []string {
	var out []string
	s.Peek(func(st *State) {
		for _, r := range st.Revoked {
			if r.Kind == kind {
				out = append(out, r.ID)
			}
		}
	})
	return out
}

// Peek calls fn with the committed state under the read lock, without copying it. fn must not keep the state or
// change anything in it, and must not call the store.
func (s *Store) Peek(fn func(st *State)) {
	s.eng.mu.RLock()
	defer s.eng.mu.RUnlock()
	fn(s.eng.cur)
}

// Lookup returns a copy of one account, or nil.
func (s *Store) Lookup(username string) *Account {
	s.eng.mu.RLock()
	defer s.eng.mu.RUnlock()
	return s.eng.cur.Account(username)
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
	return s.eng.counter(ev, fn, counterFieldsOnly(s.eng))
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
	}, nil)
}

var dummyTOTPSecret = make([]byte, 20)

// ProbeTOTP takes the writer lock and checks a code against the account's secret (a dummy one when there is none), and
// writes nothing: the work UseTOTP does for a code that fails, for the sign-in that must not tell a wrong password from a
// right one by how long it holds the writer (5.6, 8.6).
func (s *Store) ProbeTOTP(username, code string, now time.Time) {
	s.eng.wmu.Lock()
	defer s.eng.wmu.Unlock()
	secret, last := dummyTOTPSecret, int64(0)
	if a := s.eng.cur.Accounts[username]; a != nil && a.TOTP != nil {
		secret, last = a.TOTP.Secret, a.TOTP.LastStep
	}
	_, _ = VerifyTOTP(secret, code, now, last)
}

// ErrNotCounterOnly is returned by Counter when its callback changed anything but counters.
var ErrNotCounterOnly = errors.New("a counter write may change only counter fields; use Change, which is audited")

// counterFieldsOnly is the check of Counter: the new state may differ from the committed one only in the
// counters of 4.2 (failure counts and their windows, locks, good buckets, last sign-in and last
// second-factor failure, TOTP last_step) and in the restriction states that the failure count drives
// (active, restricted, passkey_only). Everything else (credentials, accounts, pending links, usernames) needs a
// Change, which is audited first. Undoing a failure needs proof of a sign-in (counterMovesForward).
func counterFieldsOnly(e *engine[*State]) func(cur, next *State, ev *audit.Event) error {
	return func(cur, next *State, ev *audit.Event) error {
		a, b := maskCounters(e.clone(cur)), maskCounters(e.clone(next))
		ja, err1 := json.Marshal(a)
		jb, err2 := json.Marshal(b)
		if err1 != nil || err2 != nil || string(ja) != string(jb) {
			return ErrNotCounterOnly
		}
		now := e.c.Now()
		for n, old := range cur.Accounts {
			if !counterMovesForward(n, old, next.Accounts[n], now, ev) {
				return ErrNotCounterOnly
			}
		}
		return nil
	}
}

// The windows of the failure counters (8.4): totp_failures count per 24 hours, passkey_path_failures per hour.
const (
	totpFailureWindow    = 24 * time.Hour
	passkeyFailureWindow = time.Hour
)

// signInProof says the counter write carries proof of a sign-in of this account: its event is a login
// event for local:<name> (counter() appends it with RecordSync in the same write), and the new
// last_login moved forward and is not after the store's clock.
func signInProof(name string, old, nw *Account, now time.Time, ev *audit.Event) bool {
	return ev != nil && ev.Event == "login" && ev.Identity == "local:"+name &&
		nw.LastLogin != nil && !nw.LastLogin.Time.After(now) &&
		(old.LastLogin == nil || nw.LastLogin.Time.After(old.LastLogin.Time))
}

// reauthProof says the counter write carries a re-authentication of this account: a reauth event for local:<name>
// (counter() appends it with RecordSync in the same write). A re-authentication verifies the password and the second
// factor again, so it may reset reauth_failures (5.7) and nothing else that a failure raised.
func reauthProof(name string, ev *audit.Event) bool {
	return ev != nil && ev.Event == "reauth" && ev.Identity == "local:"+name
}

// counterMovesForward is the second half of the counter check. What a failed attempt does (a count that grows, a
// lock that is set, an account that becomes restricted) is a counter write. Undoing it is not, unless the write
// proves a sign-in (signInProof) or the thing ran out on its own: leaving restricted or passkey_only, lowering
// consecutive_failures, totp_failures, passkey_path_failures or reauth_failures (or moving their windows) and
// removing a running lock all need the audited path (unlock, a reset) otherwise. An expired lock may be dropped
// and an expired window may start again. TOTP last_step only grows, so a replayed code cannot be made fresh again.
func counterMovesForward(name string, old, nw *Account, now time.Time, ev *audit.Event) bool {
	if old.TOTP != nil && nw.TOTP != nil && nw.TOTP.LastStep < old.TOTP.LastStep {
		return false
	}
	if signInProof(name, old, nw, now, ev) {
		return true
	}
	if (old.State == StateRestricted || old.State == StatePasskeyOnly) && nw.State == StateActive {
		return false
	}
	if old.State == StatePasskeyOnly && nw.State == StateRestricted {
		return false
	}
	if nw.ConsecutiveFailures < old.ConsecutiveFailures {
		return false
	}
	if nw.ReauthFailures < old.ReauthFailures && !(reauthProof(name, ev) && nw.ReauthFailures == 0) {
		return false
	}
	for _, w := range []struct {
		oldN, newN         int
		oldStart, newStart time.Time
		length             time.Duration
	}{
		{old.TOTPFailures, nw.TOTPFailures, old.TOTPWindowStart, nw.TOTPWindowStart, totpFailureWindow},
		{old.PasskeyPathFailures, nw.PasskeyPathFailures, old.PasskeyWindowStart, nw.PasskeyWindowStart, passkeyFailureWindow},
	} {
		expired := w.oldStart.IsZero() || !now.Before(w.oldStart.Add(w.length))
		if !expired && (w.newN < w.oldN || !w.newStart.Equal(w.oldStart)) {
			return false // a running window is not lowered or moved
		}
	}
	for _, l := range old.Locks {
		if l.Until.After(now) && !slices.ContainsFunc(nw.Locks, func(k Lock) bool { return k.Scope == l.Scope && k.Until.Equal(l.Until) }) {
			return false // a lock that is still running was removed
		}
	}
	return true
}

func maskCounters(s *State) *State {
	s.Meta = Meta{}
	for _, a := range s.Accounts {
		a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures, a.ReauthFailures = 0, 0, 0, 0
		a.TOTPWindowStart, a.PasskeyWindowStart = time.Time{}, time.Time{}
		a.Locks, a.GoodBuckets, a.LastLogin, a.LastSecondFactorFailure = nil, nil, nil, nil
		if a.TOTP != nil {
			a.TOTP.LastStep = 0
		}
		switch a.State {
		case StateActive, StateRestricted, StatePasskeyOnly:
			a.State = StateActive
		}
	}
	return s
}

// ---- what sessions, tokens and grants ask of the store (6, 7)

// Live says the account can hold sessions, tokens and grants: it is active, restricted or
// passkey_only. restricted and passkey_only limit new sign-ins only; disabled, removed,
// reset_pending and invited end everything that exists (6).
func (a *Account) Live() bool {
	switch a.State {
	case StateActive, StateRestricted, StatePasskeyOnly:
		return true
	}
	return false
}

// LocalActive says whether username is a live account (see Account.Live). It reads the committed
// state without copying it, so it is cheap enough for every request.
func (s *Store) LocalActive(username string) bool {
	s.eng.mu.RLock()
	defer s.eng.mu.RUnlock()
	a := s.eng.cur.Accounts[username]
	return a != nil && a.Live()
}

// LiveSession returns the session id and the session secret of a live account, for the MAC key of
// its sessions (6). ok is false for an unknown account and for one that is not live. The secret is a
// copy; callers must not keep it beyond the derivation.
func (s *Store) LiveSession(username string) (sid string, secret []byte, ok bool) {
	s.eng.mu.RLock()
	defer s.eng.mu.RUnlock()
	a := s.eng.cur.Accounts[username]
	if a == nil || !a.Live() || a.SID == "" || len(a.SessionSecret) == 0 {
		return "", nil, false
	}
	return a.SID, append([]byte(nil), a.SessionSecret...), true
}

// RosterEntry is one account as the role editor offers it: the username, the display name and the state.
// Nothing of its credentials.
type RosterEntry struct {
	Username string
	Name     string
	State    string
}

// Roster lists the accounts, sorted by username (removed ones too: their names stay used).
func (s *Store) Roster() []RosterEntry {
	s.eng.mu.RLock()
	defer s.eng.mu.RUnlock()
	out := make([]RosterEntry, 0, len(s.eng.cur.Accounts))
	for _, n := range s.eng.cur.Names() {
		a := s.eng.cur.Accounts[n]
		out = append(out, RosterEntry{Username: n, Name: a.Name, State: a.State})
	}
	return out
}
