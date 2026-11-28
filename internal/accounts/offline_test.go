package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

func (e *env) offline() (Offline, *bytes.Buffer) {
	var out bytes.Buffer
	return Offline{StateDir: e.dir, Key: e.key, Log: e.log, Operator: "tester", Out: &out, Now: e.clk.Now}, &out
}

// activate makes an account active with a password and TOTP, as a finished setup would.
func (e *env) activate(s *Store, name string) {
	e.t.Helper()
	secret, _ := NewTOTPSecret()
	if _, err := s.Change(audit.Event{Event: "account_setup_completed", Identity: "local:" + name}, func(st *State) error {
		a := st.Accounts[name]
		a.State = StateActive
		a.Password = "$argon2id$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"
		a.TOTP = &TOTP{Secret: secret, Added: e.clk.Now()}
		a.GoodBuckets = []GoodBucket{{Bucket: "203.0.113.7", Last: e.clk.Now()}}
		return a.RenewSessions()
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestAcceptRestoreOfAGap(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	for _, n := range []string{"alice", "bob", "dave"} {
		e.mustInvite(s, n)
		e.activate(s, n)
	}
	backup := readFile(t, e.accountsPath("accounts.enc"))
	oldSID := s.Snapshot().Accounts["dave"].SID
	// after the backup: bob disabled with revocations, alice changed her password, carol invited
	if _, err := s.Change(audit.Event{Event: "account_disabled", Identity: "local:root", Target: "local:bob", Detail: []string{"tokens:ci,deploy", "grants:g1,g2"}}, func(st *State) error {
		st.Accounts["bob"].State = StateDisabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.Change(audit.Event{Event: "password_changed", Identity: "local:alice"}, func(st *State) error { st.Accounts["alice"].Password = "$new"; return nil })
	e.mustInvite(s, "carol")
	grants := `{"version":1,"clients":{},"grants":{"g1":{"id":"g1"},"g2":{"id":"g2"},"keep":{"id":"keep"}}}`
	os.WriteFile(filepath.Join(e.dir, "oauth-grants.json"), []byte(grants), 0o600)

	os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
	e.restart()
	if _, err := e.open(); startCode(t, err) != CodeGap {
		t.Fatalf("err = %v", err)
	}
	before := readFile(t, e.accountsPath("accounts.enc"))

	off, out := e.offline()
	// a refusal at the prompt changes nothing
	if _, err := AcceptRestore(off, RestoreOptions{Confirm: func() (bool, error) { return false, nil }}); err == nil {
		t.Fatal("not confirmed must be an error")
	}
	if !bytes.Equal(before, readFile(t, e.accountsPath("accounts.enc"))) || len(e.eventsNamed("account_store_restored")) != 0 {
		t.Fatal("a refused restore changed something")
	}
	out.Reset()
	rep, err := AcceptRestore(off, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Accounts != "gap" || rep.Nothing {
		t.Fatalf("report = %+v", rep)
	}
	text := out.String()
	for _, want := range []string{"account_disabled", "target=local:bob", "password_changed", "account_invited", "target=local:carol"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan does not print %q:\n%s", want, text)
		}
	}

	e.restart()
	s2, err := e.open()
	if err != nil {
		t.Fatalf("start after accept-restore: %v", err)
	}
	snap := s2.Snapshot()
	// the restrictive change is back: bob stays disabled although the backup had him active
	if snap.Accounts["bob"].State != StateDisabled {
		t.Fatalf("bob = %s", snap.Accounts["bob"].State)
	}
	for _, n := range []string{"alice", "bob"} { // named by a change event after the backup
		a := snap.Accounts[n]
		if a.Password != "" || a.TOTP != nil || len(a.Passkeys) != 0 {
			t.Errorf("%s keeps credentials", n)
		}
	}
	al := snap.Accounts["alice"]
	if al.State != StateResetPending || al.Pending == nil || al.Pending.Kind != "reset" || al.Pending.Scope != ScopeAll {
		t.Fatalf("alice = %+v %+v", al.State, al.Pending)
	}
	// every account, named or not, has new session ids and no good buckets
	for n, a := range snap.Accounts {
		if len(a.GoodBuckets) != 0 {
			t.Errorf("%s keeps good buckets", n)
		}
	}
	if snap.Accounts["dave"].SID == oldSID {
		t.Fatal("an account that no event named kept its session id")
	}
	if d := snap.Accounts["dave"]; d.State != StateActive || d.Password == "" {
		t.Fatal("an account that no event named was reset")
	}
	// carol was invited after the backup: not in the store, but her name stays used
	if snap.Accounts["carol"] != nil || !s2.UsernameUsed("carol") {
		t.Fatal("carol's name must stay used")
	}
	if _, err := e.invite(s2, "carol"); !errors.Is(err, ErrUsernameUsed) {
		t.Fatalf("err = %v", err)
	}
	// revocations: the grants were revoked in oauth-grants.json, the tokens wait for the commit path
	if got := snap.Accounts["bob"].PendingRevocations; len(got.Tokens) != 2 || len(got.Grants) != 0 {
		t.Fatalf("pending revocations = %+v", got)
	}
	var f struct {
		Grants map[string]json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(e.dir, "oauth-grants.json")), &f); err != nil || len(f.Grants) != 1 || f.Grants["keep"] == nil {
		t.Fatalf("oauth-grants.json = %v %v", f.Grants, err)
	}
	// the event
	ev := e.eventsNamed("account_store_restored")
	if len(ev) != 1 || ev[0].Method != "cli" || !hasChange(ev[0]) || !containsStr(ev[0].Detail, "operator:tester") || len(detailValues(ev[0], "from:")) != 1 || len(detailValues(ev[0], "to:")) != 1 {
		t.Fatalf("event = %+v", ev)
	}
	if snap.AuditSeq != ev[0].Seq {
		t.Fatalf("store seq %d, event seq %d", snap.AuditSeq, ev[0].Seq)
	}
	e.verifyChain()
	// it is stable, and a second accept-restore has nothing to do
	e.restart()
	off, _ = e.offline()
	if rep, err := AcceptRestore(off, RestoreOptions{}); err != nil || !rep.Nothing {
		t.Fatalf("second run: %+v %v", rep, err)
	}
}

func containsStr(in []string, s string) bool {
	for _, v := range in {
		if v == s {
			return true
		}
	}
	return false
}

func TestAcceptRestoreNothingToDo(t *testing.T) {
	e := newEnv(t)
	e.mustInvite(e.mustOpen(), "alice")
	off, _ := e.offline()
	n := len(e.events())
	rep, err := AcceptRestore(off, RestoreOptions{})
	if err != nil || !rep.Nothing || len(e.events()) != n {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestAcceptRestoreOfATruncatedOrRolledBackLog(t *testing.T) {
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		e.activate(s, "alice")
		e.mustInvite(s, "bob")
		e.log.Close()
		os.RemoveAll(e.auditDir())
		e.startLog()
		return e
	}
	t.Run("refused without the flag, and nothing is changed", func(t *testing.T) {
		e := setup(t)
		before := readFile(t, e.accountsPath("accounts.enc"))
		off, _ := e.offline()
		_, err := AcceptRestore(off, RestoreOptions{})
		if err == nil || !strings.Contains(err.Error(), "--accept-audit-truncation") {
			t.Fatalf("err = %v", err)
		}
		if !bytes.Equal(before, readFile(t, e.accountsPath("accounts.enc"))) || len(e.events()) != 0 {
			t.Fatal("a refused accept-restore changed something")
		}
		if _, err := AcceptRestore(off, RestoreOptions{ResetAllAccounts: true}); err == nil {
			t.Fatal("the other flag must not accept a truncated log")
		}
	})
	t.Run("with the flag every account is reset", func(t *testing.T) {
		e := setup(t)
		off, _ := e.offline()
		rep, err := AcceptRestore(off, RestoreOptions{AcceptAuditTruncation: true})
		if err != nil || rep.Accounts != "audit_truncated" {
			t.Fatalf("%+v %v", rep, err)
		}
		e.restart()
		s, err := e.open()
		if err != nil {
			t.Fatalf("start after: %v", err)
		}
		for n, a := range s.Snapshot().Accounts {
			if a.State != StateResetPending || a.Pending.Scope != ScopeAll || a.Password != "" || a.TOTP != nil {
				t.Errorf("%s = %s", n, a.State)
			}
		}
		ev := e.eventsNamed("account_store_problem")
		if len(ev) != 1 || ev[0].Code != "audit_truncated" || !hasChange(ev[0]) || len(detailValues(ev[0], "store_seq:")) != 1 || len(detailValues(ev[0], "log_end:")) != 1 {
			t.Fatalf("event = %+v", ev)
		}
		if s.Snapshot().AuditSeq != ev[0].Seq {
			t.Fatal("the store does not point at the new event")
		}
	})
}

func TestAcceptRestoreOfAPrunedMonth(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.activate(s, "alice")
	e.clk.Set(time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC))
	e.log.Record(audit.Event{Event: "login", Identity: "x"})
	e.log.Close()
	os.Remove(filepath.Join(e.auditDir(), "audit-2026-11.jsonl"))
	e.startLog()
	off, _ := e.offline()
	if _, err := AcceptRestore(off, RestoreOptions{AcceptAuditTruncation: true}); err == nil || !strings.Contains(err.Error(), "--reset-all-accounts") {
		t.Fatalf("err = %v", err)
	}
	if _, err := AcceptRestore(off, RestoreOptions{ResetAllAccounts: true}); err != nil {
		t.Fatal(err)
	}
	e.restart()
	s2, err := e.open()
	if err != nil {
		t.Fatal(err)
	}
	if a := s2.Snapshot().Accounts["alice"]; a.State != StateResetPending || a.Password != "" {
		t.Fatalf("alice = %+v", a.State)
	}
	if ev := e.eventsNamed("account_store_problem"); len(ev) != 1 || ev[0].Code != "month_pruned" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestAcceptRestoreCrashIsRecovered(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.activate(s, "alice")
	backup := readFile(t, e.accountsPath("accounts.enc"))
	oldSID := s.Snapshot().Accounts["alice"].SID
	e.mustInvite(s, "bob")
	os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
	e.restart()
	off, _ := e.offline()
	off.hook = func(step string) error {
		if step == "event" {
			return errCrash
		}
		return nil
	}
	if _, err := AcceptRestore(off, RestoreOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("err = %v", err)
	}
	e.restart()
	s2, err := e.open()
	if err != nil {
		t.Fatalf("start after a crashed accept-restore: %v", err)
	}
	if a := s2.Snapshot().Accounts["alice"]; !s2.Recovered() || a.SID == oldSID || len(a.GoodBuckets) != 0 {
		t.Fatal("the restore was not finished from its pending file")
	}
	if !s2.UsernameUsed("bob") {
		t.Fatal("bob's name must stay used")
	}
}

func TestAcceptRestoreOfSecretsDoesNotUndoAClear(t *testing.T) {
	e := newEnv(t)
	sec, _ := e.openSecrets()
	mustApply(t, sec, Update{Set: map[string]string{SecretCaptcha: "captcha-v", SecretOIDCClient: "oidc-v"}, Issuer: "https://i.example", ClientID: "c"})
	old := readFile(t, SecretsPath(e.dir))
	mustApply(t, sec, Update{Clear: []string{SecretCaptcha}}) // cleared on purpose after the backup
	os.WriteFile(SecretsPath(e.dir), old, 0o600)
	e.restart()
	if _, err := e.openSecrets(); startCode(t, err) != CodeGap {
		t.Fatalf("err = %v", err)
	}
	off, out := e.offline()
	rep, err := AcceptRestore(off, RestoreOptions{})
	if err != nil || rep.Secrets != "gap" {
		t.Fatalf("%+v %v", rep, err)
	}
	if !strings.Contains(out.String(), "captcha_secret") {
		t.Fatalf("the operator is told which secrets to enter again:\n%s", out)
	}
	e.restart()
	sec2, err := e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if sec2.Status().HasCaptchaSecret {
		t.Fatal("the restore brought back a secret that was cleared")
	}
	if _, ok := sec2.OIDCClientSecret("https://i.example", "c"); !ok {
		t.Fatal("a secret no event named was lost")
	}
	if ev := e.eventsNamed("account_store_restored"); len(ev) != 1 || !containsStr(ev[0].Detail, "store:secrets") {
		t.Fatalf("events = %+v", ev)
	}
	// and when the log cannot be trusted, no secret stays
	e.log.Close()
	os.RemoveAll(e.auditDir())
	e.startLog()
	off, _ = e.offline()
	if _, err := AcceptRestore(off, RestoreOptions{AcceptAuditTruncation: true}); err != nil {
		t.Fatal(err)
	}
	e.restart()
	sec3, err := e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if sec3.Status().HasOIDCClientSecret {
		t.Fatal("a truncated log must clear every secret")
	}
}

func TestEvidenceIsArchivedByAcceptRestore(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	backup := readFile(t, e.accountsPath("accounts.enc"))
	e.mustInvite(s, "bob")
	os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
	os.WriteFile(e.accountsPath("accounts.enc.pending"), []byte("planted"), 0o600)
	e.restart()
	off, out := e.offline()
	if _, err := AcceptRestore(off, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "evidence file") {
		t.Fatalf("output:\n%s", out)
	}
	e.restart()
	s2 := e.mustOpen()
	if len(s2.Evidence()) != 0 {
		t.Fatalf("evidence is still in the Users view: %v", s2.Evidence())
	}
	var kept int
	filepath.WalkDir(filepath.Join(e.dir, "accounts"), func(p string, d fs.DirEntry, err error) error {
		if strings.Contains(p, ".evidence-") && strings.Contains(filepath.Base(filepath.Dir(p)), "evidence-") {
			kept++
		}
		return nil
	})
	if kept != 1 {
		t.Fatalf("%d evidence files are kept in the archive, want 1", kept)
	}
}

// ---- rekey

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rekeySetup(t *testing.T) *env {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.activate(s, "alice")
	sec, _ := e.openSecrets()
	mustApply(t, sec, Update{Set: map[string]string{SecretCaptcha: "captcha-value"}})
	return e
}

func TestRekeyRoundTrip(t *testing.T) {
	e := rekeySetup(t)
	oldKey, newKey := e.key, mustNewKey(t)
	before := e.mustOpen().Snapshot()
	e.restart()
	off, _ := e.offline()
	rep, err := Rekey(off, newKey)
	if err != nil || rep.OldKID != oldKey.KID() || rep.NewKID != newKey.KID() {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, f := range []string{"accounts.enc.pending", "accounts.enc.next", "usernames.next"} {
		if exists(e.accountsPath(f)) {
			t.Fatalf("%s is left over", f)
		}
	}
	for _, f := range []string{filepath.Join(e.dir, "secrets.enc.pending"), filepath.Join(e.dir, "secrets.enc.next")} {
		if exists(f) {
			t.Fatalf("%s is left over", f)
		}
	}
	e.restart()
	// the old key opens nothing
	o := e.opts()
	if _, err := Open(o); startCode(t, err) != CodeWrongKey {
		t.Fatalf("old key, accounts: %v", err)
	}
	if _, err := OpenSecrets(o); startCode(t, err) != CodeWrongKey {
		t.Fatalf("old key, secrets: %v", err)
	}
	if _, err := ReadUsernames(e.accountsPath("usernames"), oldKey); startCode(t, err) != CodeUsernamesMAC {
		t.Fatalf("old key, usernames: %v", err)
	}
	// the new key opens everything, with the same content
	e.key = newKey
	e.restart()
	s, err := e.open()
	if err != nil {
		t.Fatal(err)
	}
	after := s.Snapshot()
	if after.Accounts["alice"].SID != before.Accounts["alice"].SID || after.Accounts["alice"].TOTP == nil || after.Change == before.Change {
		t.Fatal("the content changed, or the change id did not move")
	}
	sec, err := e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := sec.CaptchaSecret(); v != "captcha-value" {
		t.Fatal("the secret did not survive the rekey")
	}
	if names, err := ReadUsernames(e.accountsPath("usernames"), newKey); err != nil || len(names) != 1 {
		t.Fatalf("usernames under the new key: %v %v", names, err)
	}
	// the event names the key ids and never key material
	ev := e.eventsNamed("account_store_rekeyed")
	if len(ev) != 1 || ev[0].Method != "cli" || !hasChange(ev[0]) || !containsStr(ev[0].Detail, "from_kid:"+oldKey.KID()) || !containsStr(ev[0].Detail, "to_kid:"+newKey.KID()) {
		t.Fatalf("event = %+v", ev)
	}
	raw, _ := json.Marshal(e.events())
	for _, k := range []*statekey.Key{oldKey, newKey} {
		if bytes.Contains(raw, []byte(k.Base64())) {
			t.Fatal("key material in the audit log")
		}
	}
	// the stores are writable under the new key
	e.mustInvite(s, "bob")
	e.verifyChain()
	for _, p := range []string{e.accountsPath("accounts.enc"), SecretsPath(e.dir), e.accountsPath("usernames")} {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", p, st.Mode().Perm())
		}
	}
}

func TestRekeyRefusals(t *testing.T) {
	e := rekeySetup(t)
	e.restart()
	off, _ := e.offline()
	if _, err := Rekey(off, e.key); err == nil || !strings.Contains(err.Error(), "same as the old key") {
		t.Fatalf("same key: %v", err)
	}
	if _, err := Rekey(off, nil); err == nil {
		t.Fatal("no new key")
	}
	wrong := off
	wrong.Key = mustNewKey(t)
	if _, err := Rekey(wrong, mustNewKey(t)); startCode(t, errors.Unwrap(err)) != CodeWrongKey {
		t.Fatalf("wrong old key: %v", err)
	}
	// a stopped writer left nothing behind
	if exists(e.accountsPath("accounts.enc.pending")) || len(e.eventsNamed("account_store_rekeyed")) != 0 {
		t.Fatal("a refused rekey left traces")
	}
	off.Operator = ""
	if _, err := Rekey(off, mustNewKey(t)); err == nil {
		t.Fatal("an operator name is required")
	}
}

func TestRekeyCrashAtEachStep(t *testing.T) {
	type works struct{ old, new bool }
	for step, w := range map[string]works{
		"pending": {true, false}, // nothing was audited: the old key undoes it
		"event":   {true, false}, // audited, no new file yet: the old key recovers from .pending
		"next":    {true, true},  // the new files are complete: either key can go on
		"rename1": {false, true},
		"rename2": {false, true},
		"rename3": {false, true},
	} {
		t.Run(step, func(t *testing.T) {
			e := rekeySetup(t)
			newKey := mustNewKey(t)
			e.restart()
			off, _ := e.offline()
			off.hook = func(s string) error {
				if s == step {
					return errCrash
				}
				return nil
			}
			if _, err := Rekey(off, newKey); !errors.Is(err, errCrash) {
				t.Fatalf("err = %v", err)
			}
			e.log.Close()
			try := func(key *statekey.Key) (*env, error) {
				c := &env{t: t, dir: t.TempDir(), key: key, clk: e.clk}
				copyTree(t, e.dir, c.dir)
				c.startLog()
				t.Cleanup(c.log.Close)
				if _, err := c.open(); err != nil {
					return c, err
				}
				if _, err := c.openSecrets(); err != nil {
					return c, err
				}
				return c, nil
			}
			c, err := try(e.key)
			if (err == nil) != w.old {
				t.Fatalf("old key: works=%v err=%v", err == nil, err)
			}
			if err == nil {
				if _, err := c.open(); err != nil {
					t.Fatal(err)
				}
				// whichever way, accounts and secrets agree and the chain verifies
				c.verifyChain()
			}
			c, err = try(newKey)
			if (err == nil) != w.new {
				t.Fatalf("new key: works=%v err=%v", err == nil, err)
			}
			if err == nil {
				s, _ := c.open()
				if s.Snapshot().Accounts["alice"] == nil {
					t.Fatal("alice is gone")
				}
				sec, _ := c.openSecrets()
				if v, _ := sec.CaptchaSecret(); v != "captcha-value" {
					t.Fatal("the secret is gone")
				}
				if _, err := ReadUsernames(c.accountsPath("usernames"), newKey); err != nil {
					t.Fatalf("usernames under the new key: %v", err)
				}
				c.verifyChain()
			}
			if !w.old && !w.new {
				t.Fatal("a crash must leave a key that works")
			}
		})
	}
}

// ---- discard-store

func TestDiscardStoreAfterALostKey(t *testing.T) {
	e := rekeySetup(t)
	s := e.mustOpen()
	e.mustInvite(s, "bob")
	e.log.Record(audit.Event{Event: "account_invited", Target: "local:carol"})
	oldKey := e.key
	e.key = mustNewKey(t) // the old key is lost
	e.restart()
	if _, err := e.open(); startCode(t, err) != CodeWrongKey {
		t.Fatalf("err = %v", err)
	}
	oldBytes := readFile(t, e.accountsPath("accounts.enc"))

	off, out := e.offline()
	var asked []string
	rep, err := DiscardStore(off, func(names []string) (bool, error) { asked = names; return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != "alice,bob,carol" || rep.Usernames != 3 || !strings.Contains(out.String(), "carol") {
		t.Fatalf("names shown to the operator: %v\n%s", asked, out)
	}
	// the stores are moved, not deleted
	moved, err := os.ReadFile(filepath.Join(rep.Dir, "accounts.enc"))
	if err != nil || !bytes.Equal(moved, oldBytes) {
		t.Fatalf("the old store was not kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rep.Dir, "secrets.enc")); err != nil {
		t.Fatal("the old secrets were not kept")
	}
	e.restart()
	s2, err := e.open()
	if err != nil {
		t.Fatalf("start after discard: %v", err)
	}
	if len(s2.Snapshot().Accounts) != 0 {
		t.Fatal("the new store is not empty")
	}
	sec, err := e.openSecrets()
	if err != nil || sec.Status().HasCaptchaSecret {
		t.Fatalf("secrets: %v", err)
	}
	// usernames are MACed under the new key, and every name stays used
	names, err := ReadUsernames(e.accountsPath("usernames"), e.key)
	if err != nil || strings.Join(names, ",") != "alice,bob,carol" {
		t.Fatalf("usernames = %v %v", names, err)
	}
	if _, err := ReadUsernames(e.accountsPath("usernames"), oldKey); err == nil {
		t.Fatal("usernames still verifies under the lost key")
	}
	for _, n := range []string{"alice", "bob", "carol"} {
		if _, err := e.invite(s2, n); !errors.Is(err, ErrUsernameUsed) {
			t.Fatalf("%s: %v", n, err)
		}
	}
	e.mustInvite(s2, "erin")
	ev := e.eventsNamed("account_store_problem")
	if len(ev) != 1 || ev[0].Code != "discarded" || ev[0].Method != "cli" || !hasChange(ev[0]) || !containsStr(ev[0].Detail, "operator:tester") {
		t.Fatalf("event = %+v", ev)
	}
	e.verifyChain()
}

func TestDiscardStoreRefusals(t *testing.T) {
	t.Run("a store that opens is not discarded", func(t *testing.T) {
		e := rekeySetup(t)
		e.restart()
		off, _ := e.offline()
		before := readFile(t, e.accountsPath("accounts.enc"))
		if _, err := DiscardStore(off, nil); err == nil || !strings.Contains(err.Error(), "nothing to discard") {
			t.Fatalf("err = %v", err)
		}
		if !bytes.Equal(before, readFile(t, e.accountsPath("accounts.enc"))) {
			t.Fatal("a readable store was touched")
		}
	})
	t.Run("a gap is for accept-restore", func(t *testing.T) {
		e := newEnv(t)
		s := e.mustOpen()
		e.mustInvite(s, "alice")
		backup := readFile(t, e.accountsPath("accounts.enc"))
		e.mustInvite(s, "bob")
		os.WriteFile(e.accountsPath("accounts.enc"), backup, 0o600)
		e.restart()
		off, _ := e.offline()
		if _, err := DiscardStore(off, nil); err == nil || !strings.Contains(err.Error(), "another problem") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("not confirmed changes nothing", func(t *testing.T) {
		e := rekeySetup(t)
		e.key = mustNewKey(t)
		e.restart()
		before := readFile(t, e.accountsPath("accounts.enc"))
		off, _ := e.offline()
		if _, err := DiscardStore(off, func([]string) (bool, error) { return false, nil }); err == nil {
			t.Fatal("not confirmed must be an error")
		}
		if !bytes.Equal(before, readFile(t, e.accountsPath("accounts.enc"))) || len(e.eventsNamed("account_store_problem")) != 0 {
			t.Fatal("a declined discard changed something")
		}
	})
}

func TestDiscardStoreCrashCanBeRerun(t *testing.T) {
	for _, step := range []string{"moved", "usernames", "event"} {
		t.Run(step, func(t *testing.T) {
			e := rekeySetup(t)
			e.mustInvite(e.mustOpen(), "bob")
			e.key = mustNewKey(t)
			e.restart()
			off, _ := e.offline()
			off.hook = func(s string) error {
				if s == step {
					return errCrash
				}
				return nil
			}
			if _, err := DiscardStore(off, nil); !errors.Is(err, errCrash) {
				t.Fatalf("err = %v", err)
			}
			e.restart()
			// the half-done discard is not a store: start stops, and a rerun finishes it
			if _, err := e.open(); err == nil {
				if step != "event" {
					t.Fatal("a half-discarded store started")
				}
			}
			off, _ = e.offline()
			if _, err := DiscardStore(off, nil); err != nil {
				t.Fatalf("rerun: %v", err)
			}
			e.restart()
			s, err := e.open()
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"alice", "bob"} {
				if !s.UsernameUsed(n) {
					t.Fatalf("%s is free again", n)
				}
			}
			e.verifyChain()
		})
	}
}

// ---- list

func TestListShowsStateAndNeverSecrets(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.mustInvite(s, "alice")
	e.activate(s, "alice")
	e.mustInvite(s, "bob")
	secret := s.Snapshot().Accounts["alice"].TOTP.Secret
	s.Counter(nil, func(st *State) error {
		a := st.Accounts["alice"]
		a.ConsecutiveFailures = 4
		a.Locks = []Lock{{Scope: "account", Until: e.clk.Now().Add(time.Hour)}}
		a.PendingRevocations = Revocations{Tokens: []string{"ci"}, Grants: []string{"g9"}}
		return nil
	})
	sec, _ := e.openSecrets()
	mustApply(t, sec, Update{Set: map[string]string{SecretCaptcha: "hidden-captcha"}})
	os.WriteFile(e.accountsPath("accounts.enc.next.evidence-20261122T100000Z"), []byte("x"), 0o600)

	var out bytes.Buffer
	if err := List(&out, e.dir, e.key, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"alice", "bob", "active", "invited", "4/0/0/0", "account until", "revocations pending", "ci", "g9", "has_captcha_secret=true", "has_oidc_client_secret=false", "evidence files", "accounts.enc.next.evidence-"} {
		if !strings.Contains(text, want) {
			t.Errorf("list lacks %q:\n%s", want, text)
		}
	}
	for _, leak := range []string{"$argon2", "hidden-captcha", TOTPBase32(secret), string(secret), e.key.Base64()} {
		if strings.Contains(text, leak) {
			t.Fatalf("list leaks %q", leak)
		}
	}
	// a wrong key is an error, not an empty list
	if err := List(&out, e.dir, mustNewKey(t), e.clk.Now()); startCode(t, err) != CodeWrongKey {
		t.Fatalf("err = %v", err)
	}
	// list changes nothing: no file is written
	if exists(e.accountsPath("accounts.enc.tmp")) {
		t.Fatal("list wrote a file")
	}
}
