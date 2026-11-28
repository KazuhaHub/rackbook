package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

func writeGrants(t *testing.T, dir string, ids ...string) {
	t.Helper()
	g := map[string]any{}
	for _, id := range ids {
		g[id] = map[string]string{"id": id}
	}
	b, _ := json.Marshal(map[string]any{"version": 1, "clients": map[string]any{"c1": map[string]string{"id": "c1"}}, "grants": g})
	if err := os.WriteFile(filepath.Join(dir, "oauth-grants.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func grantIDs(t *testing.T, dir string) (grants, clients int) {
	t.Helper()
	var f struct {
		Grants  map[string]json.RawMessage `json:"grants"`
		Clients map[string]json.RawMessage `json:"clients"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "oauth-grants.json")), &f); err != nil {
		t.Fatal(err)
	}
	return len(f.Grants), len(f.Clients)
}

// An earlier global reset between the backup and now must reach every account, named or not (review, medium 1).
func TestAcceptRestoreReappliesAGlobalResetBetweenTheBackupAndNow(t *testing.T) {
	for _, global := range []struct{ name, event, code string }{
		{"a reset after a truncated log", "account_store_problem", "audit_truncated"},
		{"a reset after a pruned month", "account_store_problem", "month_pruned"},
		{"an earlier restore", "account_store_restored", ""},
	} {
		t.Run(global.name, func(t *testing.T) {
			e := newEnv(t)
			s := e.mustOpen()
			for _, n := range []string{"alice", "bob", "carol"} {
				e.mustInvite(s, n)
				e.activate(s, n)
			}
			backup := readFile(t, e.accountsPath("accounts.enc")) // the copy from "seq 40"
			// "seq 50": every account reset by a store-level event; no account-level event names anybody
			if _, err := s.Change(audit.Event{Event: global.event, Code: global.code, Method: "cli", Detail: []string{"operator:ops"}}, func(st *State) error {
				for _, a := range st.Accounts {
					resetAccount(a, "cli")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got := s.Snapshot().Accounts["carol"].State; got != StateResetPending {
				t.Fatalf("setup: carol is %s", got)
			}
			writeGrants(t, e.dir, "g1", "g2")
			os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
			e.restart()
			if _, err := e.open(); startCode(t, err) != CodeGap {
				t.Fatalf("err = %v", err)
			}
			off, out := e.offline()
			off.TokenNames, off.TokensListed = []string{"ci"}, true
			rep, err := AcceptRestore(off, RestoreOptions{})
			if err != nil || rep.Accounts != "gap" {
				t.Fatalf("%+v %v", rep, err)
			}
			if !strings.Contains(out.String(), global.event) {
				t.Fatalf("the global event is not printed:\n%s", out)
			}
			e.restart()
			s2, err := e.open()
			if err != nil {
				t.Fatal(err)
			}
			for n, a := range s2.Snapshot().Accounts {
				if a.State != StateResetPending || a.Password != "" || a.TOTP != nil || a.Pending == nil || a.Pending.Scope != ScopeAll {
					t.Errorf("%s was not reset: %s", n, a.State)
				}
				if len(a.PendingRevocations.Tokens) != 1 || a.PendingRevocations.Tokens[0] != "ci" {
					t.Errorf("%s: tokens = %v", n, a.PendingRevocations.Tokens)
				}
			}
			if g, c := grantIDs(t, e.dir); g != 0 || c != 1 || rep.GrantsRevoked != 2 {
				t.Fatalf("%d grants and %d clients left, %d revoked", g, c, rep.GrantsRevoked)
			}
		})
	}
}

// The attack of the review: an old store, and the log line at its audit_seq edited so that the log "does not hold
// the store's last change". No account may come back active with its old credentials, and no old grant survives.
func TestAcceptRestoreFailsSafeWhenTheLogCannotBeTrusted(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	for _, n := range []string{"alice", "bob"} {
		e.mustInvite(s, n)
		e.activate(s, n)
	}
	old := s.Snapshot()
	backup := readFile(t, e.accountsPath("accounts.enc"))
	// after the backup an administrator disabled bob and revoked what he had
	if _, err := s.Change(audit.Event{Event: "account_disabled", Identity: "local:root", Target: "local:bob", Detail: []string{"tokens:ci", "grants:g1"}}, func(st *State) error {
		st.Accounts["bob"].State = StateDisabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	writeGrants(t, e.dir, "g1", "g2", "g3")
	os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
	// the attacker edits the line at the store's audit_seq
	e.log.Close()
	month := filepath.Join(e.auditDir(), "audit-2026-11.jsonl")
	raw := readFile(t, month)
	edited := bytes.Replace(raw, []byte("change:"+old.Change), []byte("change:aaaaaaaaaaaaaaaaaaaaaaaa"), 1)
	if bytes.Equal(raw, edited) {
		t.Fatal("test setup: the line was not edited")
	}
	os.WriteFile(month, edited, 0o600)
	e.startLog()
	if _, err := e.open(); startCode(t, err) != CodeAuditTruncated {
		t.Fatalf("err = %v", err)
	}

	off, out := e.offline()
	if _, err := AcceptRestore(off, RestoreOptions{AcceptAuditTruncation: true}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"account_disabled", "target=local:bob", "cannot be trusted", "every OAuth grant", "API tokens could not be listed"} {
		if !strings.Contains(text, want) {
			t.Errorf("the operator is not told %q:\n%s", want, text)
		}
	}
	e.restart()
	s2, err := e.open()
	if err != nil {
		t.Fatal(err)
	}
	snap := s2.Snapshot()
	for n, a := range snap.Accounts {
		if a.State == StateActive || a.Password != "" || a.TOTP != nil || a.SID == old.Accounts[n].SID {
			t.Errorf("%s came back with old credentials or sessions: %s", n, a.State)
		}
	}
	if snap.Accounts["bob"].State != StateDisabled {
		t.Fatalf("the restrictive event that is still readable was not re-applied: bob is %s", snap.Accounts["bob"].State)
	}
	if g, _ := grantIDs(t, e.dir); g != 0 {
		t.Fatalf("%d stale OAuth grants survive", g)
	}
}

func TestResetOfADisabledAccountClearsItsPendingLink(t *testing.T) {
	a := &Account{Username: "x", State: StateDisabled, Pending: &Pending{Kind: "invite"}, Password: "p"}
	resetAccount(a, "cli")
	if a.Pending != nil || a.Password != "" || a.State != StateDisabled {
		t.Fatalf("%+v", a)
	}
}

func TestAnOlderAuditedPendingFileIsEvidenceNotDeleted(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	// keep alice's pending file: it is the audited change that created alice
	if _, err := e.invite(e.crashing("rename"), "bob"); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	pend := readFile(t, e.accountsPath("accounts.enc.pending")) // bob's change, audited, and in the store
	e.mustInvite(e.mustOpen(), "carol")                         // the store moves on
	os.WriteFile(e.accountsPath("accounts.enc.pending"), pend, 0o600)
	e.restart()
	s2 := e.mustOpen()
	ev := s2.Evidence()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "accounts.enc.pending.evidence-") {
		t.Fatalf("evidence = %v: an older audited pending file must be kept", ev)
	}
	if exists(e.accountsPath("accounts.enc.pending")) {
		t.Fatal("the pending file was left in place")
	}
}

func TestOnlyTheWritersEventNamesAreChangeEvents(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	if _, err := s.Change(audit.Event{Event: "login"}, nil); err == nil {
		t.Fatal("a change with an event name the writer does not emit was accepted")
	}
	e.mustInvite(s, "alice")
	// a forged line that merely carries a change: detail is not a change event
	e.log.Record(audit.Event{Event: "login", Identity: "x", Detail: []string{"change:ffffffffffffffffffffffff"}})
	e.restart()
	if _, err := e.open(); err != nil {
		t.Fatalf("a login with a change: detail made a gap: %v", err)
	}
	// and a change event of the other document does not count for this one
	e.log.Record(audit.Event{Event: "settings_secret_set", Detail: []string{"change:ffffffffffffffffffffffff"}})
	e.restart()
	if _, err := e.open(); err != nil {
		t.Fatalf("an event of the secrets writer with a change: detail made a gap: %v", err)
	}
}

func TestTmpFilesNeverFollowASymlink(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("do not touch"), 0o600)
	// planted before a write: the writer replaces the link, never writes through it
	for _, f := range []string{"accounts.enc.pending.tmp", "accounts.enc.next.tmp", "usernames.tmp"} {
		if err := os.Symlink(victim, e.accountsPath(f)); err != nil {
			t.Fatal(err)
		}
	}
	e.mustInvite(s, "bob")
	if string(readFile(t, victim)) != "do not touch" {
		t.Fatal("a write followed a planted .tmp symlink")
	}
	if st, err := os.Stat(e.accountsPath("accounts.enc")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("store mode: %v %v", st, err)
	}
	// planted before a start: every kind of leftover .tmp goes, a symlink included, and the target stays
	for _, p := range []string{e.accountsPath("accounts.enc.tmp"), e.accountsPath("usernames.tmp"), e.accountsPath("usernames.next.tmp"), filepath.Join(e.dir, "oauth-grants.json.tmp"), filepath.Join(e.dir, "secrets.enc.tmp")} {
		os.Remove(p)
		if err := os.Symlink(victim, p); err != nil {
			t.Fatal(err)
		}
	}
	e.restart()
	e.mustOpen()
	if _, err := e.openSecrets(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{e.accountsPath("accounts.enc.tmp"), e.accountsPath("usernames.tmp"), e.accountsPath("usernames.next.tmp"), filepath.Join(e.dir, "oauth-grants.json.tmp"), filepath.Join(e.dir, "secrets.enc.tmp")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s survived the start", p)
		}
	}
	if string(readFile(t, victim)) != "do not touch" {
		t.Fatal("the target of a symlink was touched")
	}
}

func TestCounterMayChangeOnlyCounters(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.activate(s, "alice")
	before := s.Snapshot()
	for name, fn := range map[string]func(*State){
		"a password":          func(st *State) { st.Accounts["alice"].Password = "$x" },
		"a factor":            func(st *State) { st.Accounts["alice"].TOTP = nil },
		"a disabled state":    func(st *State) { st.Accounts["alice"].State = StateDisabled },
		"a session secret":    func(st *State) { st.Accounts["alice"].SID = "x" },
		"a pending link":      func(st *State) { st.Accounts["alice"].Pending = &Pending{Kind: "reset"} },
		"a revocation":        func(st *State) { st.Accounts["alice"].PendingRevocations.Tokens = []string{"t"} },
		"a notice":            func(st *State) { st.Accounts["alice"].Notices = []Notice{{Kind: "x"}} },
		"a new account":       func(st *State) { st.Accounts["mallory"] = &Account{Username: "mallory"} },
		"a removed account":   func(st *State) { delete(st.Accounts, "alice") },
		"the TOTP secret":     func(st *State) { st.Accounts["alice"].TOTP.Secret = []byte("zzzzzzzzzzzzzzzzzzzz") },
		"the username record": func(st *State) { st.Usernames = append(st.Usernames, "zed") },
	} {
		err := s.Counter(nil, func(st *State) error { fn(st); return nil })
		if !errors.Is(err, ErrNotCounterOnly) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if got := s.Snapshot(); got.Change != before.Change || got.Accounts["alice"].Password != before.Accounts["alice"].Password || len(got.Accounts) != 1 {
		t.Fatal("a refused counter write changed the state")
	}
	// the counters themselves, and the restriction states they drive, are allowed
	ok := func(st *State) error {
		a := st.Accounts["alice"]
		a.ConsecutiveFailures, a.TOTPFailures, a.PasskeyPathFailures, a.ReauthFailures = 1, 2, 3, 4
		a.Locks = []Lock{{Scope: "account", Until: e.clk.Now().Add(time.Hour)}}
		a.GoodBuckets = []GoodBucket{{Bucket: "b", Last: e.clk.Now()}}
		a.LastLogin = &Seen{Time: e.clk.Now(), Addr: "203.0.113.0"}
		a.LastSecondFactorFailure = &Seen{Time: e.clk.Now()}
		a.TOTP.LastStep = 99
		a.State = StateRestricted
		return nil
	}
	if err := s.Counter(nil, ok); err != nil {
		t.Fatal(err)
	}
	if err := s.Counter(nil, func(st *State) error { st.Accounts["alice"].State = StatePasskeyOnly; return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestDiscardStoreShowsKeyIDsAndNeedsForceForAKnownKey(t *testing.T) {
	e := rekeySetup(t)
	old := e.key
	e.key = mustNewKey(t)
	e.restart()
	off, out := e.offline()
	before := readFile(t, e.accountsPath("accounts.enc"))
	_, err := DiscardStore(off, nil, false)
	if err == nil || !strings.Contains(err.Error(), "--key-is-lost") {
		t.Fatalf("err = %v", err)
	}
	for _, kid := range []string{old.KID(), e.key.KID()} {
		if !strings.Contains(out.String(), kid) {
			t.Errorf("the output does not show key id %s:\n%s", kid, out)
		}
	}
	if !bytes.Equal(before, readFile(t, e.accountsPath("accounts.enc"))) {
		t.Fatal("a refused discard moved the store")
	}
	if _, err := DiscardStore(off, nil, true); err != nil {
		t.Fatalf("with --key-is-lost: %v", err)
	}
	// a file whose header cannot be read has no key id to compare: no force is needed
	e2 := newEnv(t)
	e2.mustInvite(e2.mustOpen(), "alice")
	os.WriteFile(e2.accountsPath("accounts.enc"), []byte("garbage"), 0o600)
	e2.restart()
	off2, _ := e2.offline()
	if _, err := DiscardStore(off2, nil, false); err != nil {
		t.Fatalf("a corrupt store: %v", err)
	}
}

func TestPartialRekeyNamesTheKeyEachFileNeeds(t *testing.T) {
	e := rekeySetup(t)
	newKey := mustNewKey(t)
	e.restart()
	off, _ := e.offline()
	off.hook = func(s string) error {
		if s == "rename1" { // accounts.enc is under the new key, secrets.enc still under the old
			return errCrash
		}
		return nil
	}
	if _, err := Rekey(off, newKey); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	e.restart()
	_, err := e.open() // the old key
	if startCode(t, err) != CodeWrongKey || !strings.Contains(err.Error(), "needs state key "+newKey.KID()) || !strings.Contains(err.Error(), "loaded key is "+e.key.KID()) {
		t.Fatalf("err = %v", err)
	}
	e.key = newKey
	e.restart()
	e.mustOpen()
}
