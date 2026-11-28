package accounts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

func TestChangeIsAuditedFirstAndSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	seq, err := e.invite(s, "alice")
	if err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if snap.AuditSeq != seq || snap.AuditMonth != "2026-11" || snap.Change == "" || snap.Accounts["alice"] == nil {
		t.Fatalf("state = %+v", snap.Meta)
	}
	evs := e.eventsNamed("account_invited")
	if len(evs) != 1 || evs[0].Seq != seq || evs[0].Target != "local:alice" || len(evs[0].Detail) != 1 || evs[0].Detail[0] != "change:"+snap.Change {
		t.Fatalf("event = %+v", evs)
	}
	// nothing is left over after a clean change
	for _, f := range []string{"accounts.enc.pending", "accounts.enc.next", "accounts.enc.tmp"} {
		if exists(e.accountsPath(f)) {
			t.Fatalf("%s is left over", f)
		}
	}
	e.restart()
	s2 := e.mustOpen()
	if s2.Snapshot().Change != snap.Change || s2.Snapshot().Accounts["alice"] == nil {
		t.Fatal("the change did not survive a restart")
	}
	e.verifyChain()
}

func TestFileModes(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	sec, err := e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.Apply(Update{Set: map[string]string{SecretCaptcha: "s3cret-value"}}, audit.Event{Identity: "local:admin"}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		e.dir:                               0o700,
		filepath.Join(e.dir, "accounts"):    0o700,
		e.accountsPath("accounts.enc"):      0o600,
		e.accountsPath("usernames"):         0o600,
		filepath.Join(e.dir, "secrets.enc"): 0o600,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}
	// a loose directory is made private again at start
	if err := os.Chmod(filepath.Join(e.dir, "accounts"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.mustOpen()
	if st, _ := os.Stat(filepath.Join(e.dir, "accounts")); st.Mode().Perm() != 0o700 {
		t.Fatalf("the accounts directory is %v after start", st.Mode().Perm())
	}
}

func TestKeyHandling(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	good := e.opts()

	t.Run("wrong key", func(t *testing.T) {
		other, _ := statekey.GenerateKey()
		o := good
		o.Key = other
		_, err := Open(o)
		if startCode(t, err) != CodeWrongKey {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(err.Error(), "needs state key "+e.key.KID()) || !strings.Contains(err.Error(), "loaded key is "+other.KID()) {
			t.Fatalf("the message should name the key ids: %v", err)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		o := good
		o.Key = nil
		if _, err := Open(o); err == nil || !strings.Contains(err.Error(), "needs the state key") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a key that works after a failed one", func(t *testing.T) {
		if _, err := Open(good); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("plain text in the file", func(t *testing.T) {
		raw := readFile(t, e.accountsPath("accounts.enc"))
		if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), "Alice") {
			t.Fatal("the account store is not encrypted")
		}
		if err := os.WriteFile(e.accountsPath("accounts.enc"), []byte(`{"accounts":{"alice":{}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(good)
		if startCode(t, err) != CodeCorrupt {
			t.Fatalf("err = %v", err)
		}
		os.WriteFile(e.accountsPath("accounts.enc"), raw, 0o600)
		if _, err := Open(good); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a flipped bit", func(t *testing.T) {
		raw := readFile(t, e.accountsPath("accounts.enc"))
		bad := []byte(strings.Replace(string(raw), `"ct":"`, `"ct":"AAAA`, 1))
		os.WriteFile(e.accountsPath("accounts.enc"), bad, 0o600)
		defer os.WriteFile(e.accountsPath("accounts.enc"), raw, 0o600)
		_, err := Open(good)
		if startCode(t, err) != CodeWrongKey {
			t.Fatalf("err = %v", err)
		}
	})
}

// A crash at each step of the single-writer sequence: the start recovers or refuses as 4.3 says.
func TestCrashAtEachStepOfTheWriter(t *testing.T) {
	type want struct {
		bob       bool
		recovered bool
	}
	for step, w := range map[string]want{
		"pending": {bob: false},                 // never audited: dropped silently
		"event":   {bob: true, recovered: true}, // audited, store not written: finished from .pending
		"next":    {bob: true},                  // .next is E's: renamed into place
		"rename":  {bob: true},                  // the store has E; .pending is deleted silently
	} {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			s := e.mustOpen()
			e.mustInvite(s, "alice")
			crash := e.crashing(step)
			if _, err := e.invite(crash, "bob"); !errors.Is(err, errCrash) {
				t.Fatalf("the writer should have stopped at %s: %v", step, err)
			}
			// the process is gone; a failed writer refuses everything until restart
			if _, err := e.invite(crash, "carol"); err == nil {
				t.Fatal("a writer that failed after its audit event must refuse further changes")
			}
			e.restart()
			s2, err := e.open()
			if err != nil {
				t.Fatalf("start after a crash at %s: %v", step, err)
			}
			snap := s2.Snapshot()
			if (snap.Accounts["bob"] != nil) != w.bob || snap.Accounts["alice"] == nil {
				t.Fatalf("accounts = %v", snap.Names())
			}
			if s2.Recovered() != w.recovered {
				t.Fatalf("recovered = %v", s2.Recovered())
			}
			if got := len(e.eventsNamed("account_store_problem")); (got == 1) != w.recovered {
				t.Fatalf("%d account_store_problem events", got)
			}
			for _, f := range []string{"accounts.enc.pending", "accounts.enc.next"} {
				if exists(e.accountsPath(f)) {
					t.Fatalf("%s is left after start", f)
				}
			}
			if len(s2.Evidence()) != 0 {
				t.Fatalf("a crash is not tampering: %v", s2.Evidence())
			}
			if w.bob && (snap.AuditSeq == 0 || snap.Change == "") {
				t.Fatalf("meta = %+v", snap.Meta)
			}
			// the store is writable again, and consistent with the log after another restart
			e.mustInvite(s2, "dave")
			e.restart()
			if got := e.mustOpen().Snapshot(); got.Accounts["dave"] == nil {
				t.Fatal("dave is missing")
			}
			e.verifyChain()
		})
	}
}

func TestCrashLeavesTmpFilesWhichStartDeletes(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	for _, f := range []string{"accounts.enc.tmp", "accounts.enc.pending.tmp", "accounts.enc.next.tmp", "usernames.tmp"} {
		os.WriteFile(e.accountsPath(f), []byte("torn"), 0o600)
	}
	e.restart()
	s2 := e.mustOpen()
	if s2.Snapshot().Accounts["alice"] == nil {
		t.Fatal("alice is gone")
	}
	for _, f := range []string{"accounts.enc.tmp", "accounts.enc.pending.tmp", "accounts.enc.next.tmp"} {
		if exists(e.accountsPath(f)) {
			t.Fatalf("%s survived the start", f)
		}
	}
}

func TestPlantedFilesStopOrAreSetAside(t *testing.T) {
	t.Run("garbage .pending beside a store that lacks E stops the server", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		if _, err := e.invite(e.crashing("event"), "bob"); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		os.WriteFile(e.accountsPath("accounts.enc.pending"), []byte("garbage"), 0o600)
		e.restart()
		_, err := e.open()
		if startCode(t, err) != CodeGap {
			t.Fatalf("err = %v", err)
		}
		// the garbage is evidence, not deleted
		var ev bool
		ents, _ := os.ReadDir(filepath.Join(e.dir, "accounts"))
		for _, f := range ents {
			ev = ev || strings.HasPrefix(f.Name(), "accounts.enc.pending.evidence-")
		}
		if !ev {
			t.Fatal("the planted file should be kept as evidence")
		}
	})
	t.Run("a missing .pending beside a store that lacks E stops the server", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		if _, err := e.invite(e.crashing("event"), "bob"); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		os.Remove(e.accountsPath("accounts.enc.pending"))
		e.restart()
		if _, err := e.open(); startCode(t, err) != CodeGap {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("garbage .next is set aside and the start goes on", func(t *testing.T) {
		e := newEnv(t)
		e.mustInvite(e.mustOpen(), "alice")
		os.WriteFile(e.accountsPath("accounts.enc.next"), []byte("garbage"), 0o600)
		os.WriteFile(e.accountsPath("accounts.enc.pending"), []byte("garbage"), 0o600)
		e.restart()
		s := e.mustOpen()
		if len(s.Evidence()) != 2 {
			t.Fatalf("evidence = %v", s.Evidence())
		}
		if s.Snapshot().Accounts["alice"] == nil {
			t.Fatal("alice is gone")
		}
	})
	t.Run("an undecryptable store stops the server and a keyless attacker cannot roll back", func(t *testing.T) {
		e := newEnv(t)
		e.mustInvite(e.mustOpen(), "alice")
		os.WriteFile(e.accountsPath("accounts.enc"), []byte("garbage"), 0o600)
		e.restart()
		if _, err := e.open(); startCode(t, err) != CodeCorrupt {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a missing store while the log has changes stops the server", func(t *testing.T) {
		e := newEnv(t)
		e.mustInvite(e.mustOpen(), "alice")
		os.Remove(e.accountsPath("accounts.enc"))
		e.restart()
		if _, err := e.open(); startCode(t, err) != CodeMissing {
			t.Fatalf("err = %v", err)
		}
		if exists(e.accountsPath("accounts.enc")) {
			t.Fatal("a store must not be created over a log that has changes")
		}
	})
	t.Run("a pending file that names no event is never audited and goes silently", func(t *testing.T) {
		e := newEnv(t)
		e.mustInvite(e.mustOpen(), "alice")
		if _, err := e.invite(e.crashing("pending"), "bob"); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		e.restart()
		s := e.mustOpen()
		if len(s.Evidence()) != 0 || s.Snapshot().Accounts["bob"] != nil {
			t.Fatalf("evidence %v, names %v", s.Evidence(), s.Snapshot().Names())
		}
	})
}

func TestAuditFailureChangesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not stop root")
	}
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	before := s.Snapshot()
	month := filepath.Join(e.auditDir(), "audit-2026-11.jsonl")
	if err := os.Chmod(month, 0o400); err != nil {
		t.Fatal(err)
	}
	_, err := e.invite(s, "bob")
	os.Chmod(month, 0o600)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v, want audit_unavailable", err)
	}
	if got := s.Snapshot(); got.Change != before.Change || got.Accounts["bob"] != nil {
		t.Fatal("a change whose audit event failed must change nothing")
	}
	if exists(e.accountsPath("accounts.enc.pending")) || exists(e.accountsPath("accounts.enc.next")) {
		t.Fatal("the pending file must be deleted")
	}
	if e.UsernameUsedAfterFailed(s, "bob") {
		t.Fatal("a refused invite must not consume the username")
	}
	// and the writer works again
	e.mustInvite(s, "bob")
}

func (e *env) UsernameUsedAfterFailed(s *Store, n string) bool { return s.UsernameUsed(n) }

func TestRollbackOfTheStoreIsAGap(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	backup := readFile(t, e.accountsPath("accounts.enc"))
	e.mustInvite(s, "bob")
	if err := os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	e.restart()
	_, err := e.open()
	var se *StartError
	if !errors.As(err, &se) || se.Code != CodeGap || se.Gap == nil {
		t.Fatalf("err = %v", err)
	}
	if len(se.Gap.Events) != 1 || se.Gap.Events[0].Target != "local:bob" {
		t.Fatalf("the gap should name bob's invite: %+v", se.Gap.Events)
	}
	if !strings.Contains(se.Error(), "accept-restore") {
		t.Fatalf("message: %v", se)
	}
	// the refusal is stable: it does not repair itself on the next try
	if _, err := e.open(); startCode(t, err) != CodeGap {
		t.Fatalf("second try: %v", err)
	}
}

func TestAuditLogRolledBackOrTruncated(t *testing.T) {
	t.Run("log shorter than the store", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		e.mustInvite(s, "bob")
		e.log.Close()
		os.RemoveAll(e.auditDir())
		e.startLog()
		_, err := e.open()
		var se *StartError
		if !errors.As(err, &se) || se.Code != CodeAuditTruncated {
			t.Fatalf("err = %v", err)
		}
		if len(se.Detail) != 2 || !strings.HasPrefix(se.Detail[0], "store_seq:") || se.Detail[1] != "log_end:0" {
			t.Fatalf("detail = %v", se.Detail)
		}
	})
	t.Run("the log was replaced by one that has other lines at the same seqs", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		e.log.Close()
		os.RemoveAll(e.auditDir())
		e.startLog()
		for range 3 {
			e.log.Record(audit.Event{Event: "login", Identity: "x"})
		}
		if _, err := e.open(); startCode(t, err) != CodeAuditTruncated {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the store's month file is gone and retention does not explain it", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice") // November
		e.clk.Set(time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC))
		e.log.Record(audit.Event{Event: "login", Identity: "x"}) // December
		e.log.Close()
		os.Remove(filepath.Join(e.auditDir(), "audit-2026-11.jsonl"))
		e.startLog()
		// December is now the first month: the store's month was deleted out from under it
		if _, err := e.open(); startCode(t, err) != CodeMonthPruned {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestUsernamesAreNeverReused(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	if _, err := e.invite(s, "alice"); !errors.Is(err, ErrAccountReplaced) {
		t.Fatalf("a second invite of an existing name: %v", err)
	}
	// remove leaves a tombstone: the name stays used
	if _, err := s.Change(audit.Event{Event: "account_removed", Target: "local:alice"}, func(st *State) error {
		a := st.Accounts["alice"]
		a.State, a.Password, a.TOTP = StateRemoved, "", nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.invite(s, "alice"); !errors.Is(err, ErrAccountReplaced) {
		t.Fatalf("a removed account's name must not be reusable: %v", err)
	}
	// nor can the tombstone be edited back into a live account
	if _, err := s.Change(audit.Event{Event: "account_enabled"}, func(st *State) error { st.Accounts["alice"].State = StateActive; return nil }); !errors.Is(err, ErrAccountReplaced) {
		t.Fatalf("a tombstone came back: %v", err)
	}
	// the account cannot be deleted from the map to make the name free
	_, err := s.Change(audit.Event{Event: "account_removed", Target: "local:alice"}, func(st *State) error {
		delete(st.Accounts, "alice")
		return nil
	})
	if !errors.Is(err, ErrAccountDropped) {
		t.Fatalf("err = %v", err)
	}
	// even after a restart, with the file and the store's list both gone: the audit log still names it
	e.restart()
	os.Remove(e.accountsPath("usernames"))
	s2 := e.mustOpen()
	if !s2.UsernameUsed("alice") {
		t.Fatal("alice is forgotten after the usernames file was removed")
	}
	if !exists(e.accountsPath("usernames")) {
		t.Fatal("the file should be written again")
	}
}

func TestUsernamesUnionAgainstOlderCopiesAndLostStores(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	old := readFile(t, e.accountsPath("usernames")) // validly MACed, but older than what follows
	e.mustInvite(s, "bob")
	e.restart()
	if err := os.WriteFile(e.accountsPath("usernames"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := e.mustOpen()
	if !s2.UsernameUsed("bob") || !s2.UsernameUsed("alice") {
		t.Fatal("an older, validly MACed copy brought a name back")
	}
	names, err := ReadUsernames(e.accountsPath("usernames"), e.key)
	if err != nil || len(names) != 2 {
		t.Fatalf("the file should be rewritten with the union: %v %v", names, err)
	}
	// a name only the audit log knows (the store and the file never held it)
	e.log.Record(audit.Event{Event: "account_invited", Target: "local:carol"})
	e.restart()
	s3 := e.mustOpen()
	if !s3.UsernameUsed("carol") {
		t.Fatal("the target of an account_invited event must count")
	}
	// an account of that name is refused although neither the store nor the file ever held it
	if _, err := e.invite(s3, "carol"); !errors.Is(err, ErrUsernameUsed) {
		t.Fatalf("err = %v", err)
	}
}

func TestUsernamesBadMACStopsTheServer(t *testing.T) {
	e := newEnv(t)
	e.mustInvite(e.mustOpen(), "alice")
	raw := readFile(t, e.accountsPath("usernames"))
	edited := strings.Replace(string(raw), "alice\n", "alice\nbob\n", 1)
	os.WriteFile(e.accountsPath("usernames"), []byte(edited), 0o600)
	e.restart()
	if _, err := e.open(); startCode(t, err) != CodeUsernamesMAC {
		t.Fatalf("err = %v", err)
	}
	// MACed under another key
	other, _ := statekey.GenerateKey()
	WriteUsernames(e.accountsPath("usernames"), other, []string{"alice"})
	if _, err := e.open(); startCode(t, err) != CodeUsernamesMAC {
		t.Fatalf("other key: %v", err)
	}
	// no mac line
	os.WriteFile(e.accountsPath("usernames"), []byte("alice\n"), 0o600)
	if _, err := e.open(); startCode(t, err) != CodeUsernamesMAC {
		t.Fatalf("no mac: %v", err)
	}
}

func TestCountersKeepTheChangeAndTheAuditPosition(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	before := s.Snapshot()
	n := len(e.events())
	ev := audit.Event{Event: "login_refused", Reason: "bad_credentials"}
	if err := s.Counter(&ev, func(st *State) error { st.Accounts["alice"].ConsecutiveFailures++; return nil }); err != nil {
		t.Fatal(err)
	}
	after := s.Snapshot()
	if after.Change != before.Change || after.AuditSeq != before.AuditSeq || after.Accounts["alice"].ConsecutiveFailures != 1 {
		t.Fatalf("counter moved the position: %+v", after.Meta)
	}
	evs := e.events()
	if len(evs) != n+1 || hasChange(evs[n]) {
		t.Fatalf("a counter's audit line carries no change id: %+v", evs[n:])
	}
	// and the next start is clean: the counter is not a gap
	e.restart()
	if got := e.mustOpen().Snapshot().Accounts["alice"].ConsecutiveFailures; got != 1 {
		t.Fatalf("counter lost: %d", got)
	}
	// a crash during a counter write leaves a .tmp that start deletes and the old counters
	os.WriteFile(e.accountsPath("accounts.enc.tmp"), []byte("half a write"), 0o600)
	e.restart()
	if got := e.mustOpen().Snapshot().Accounts["alice"].ConsecutiveFailures; got != 1 {
		t.Fatalf("counter = %d", got)
	}
}

func TestCounterWithFailedAuditWritesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not stop root")
	}
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	month := filepath.Join(e.auditDir(), "audit-2026-11.jsonl")
	os.Chmod(month, 0o400)
	defer os.Chmod(month, 0o600)
	err := s.Counter(&audit.Event{Event: "login_refused"}, func(st *State) error { st.Accounts["alice"].ConsecutiveFailures++; return nil })
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if s.Snapshot().Accounts["alice"].ConsecutiveFailures != 0 {
		t.Fatal("the in-memory counter moved although nothing was audited")
	}
}

func TestInMemoryStateIsReplacedOnlyAfterTheWriteLanded(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	crash := e.crashing("next")
	if _, err := e.invite(crash, "bob"); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	if crash.Snapshot().Accounts["bob"] != nil {
		t.Fatal("the in-memory state moved before the new store was in place")
	}
	// a counter write encrypts the last committed state: it can never persist an unaudited change
	if err := crash.Counter(nil, func(*State) error { return nil }); err == nil {
		t.Fatal("a failed writer must refuse counters too")
	}
}

func TestSingleWriterSerialisesChanges(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.invite(s, fmt.Sprintf("user%02d", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := len(s.Snapshot().Accounts); got != 12 {
		t.Fatalf("%d accounts, want 12: a change was lost", got)
	}
	e.restart()
	if got := len(e.mustOpen().Snapshot().Accounts); got != 12 {
		t.Fatalf("%d accounts after restart", got)
	}
	e.verifyChain()
}

func TestSnapshotIsACopy(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	snap := s.Snapshot()
	snap.Accounts["alice"].State = StateDisabled
	delete(snap.Accounts, "alice")
	if a := s.Snapshot().Accounts["alice"]; a == nil || a.State != StateInvited {
		t.Fatal("a snapshot shares memory with the store")
	}
}
