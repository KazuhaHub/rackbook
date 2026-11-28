package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/fsutil"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

func runWithStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := newRoot()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

// accountsFixture makes a state dir with a store that holds alice and bob, and a key file outside it.
type accountsFixture struct {
	state, keyFile string
	key            *statekey.Key
}

func newAccountsFixture(t *testing.T) *accountsFixture {
	t.Helper()
	t.Setenv("RACKBOOK_STATE_KEY", "")
	t.Setenv("RACKBOOK_SESSION_KEY", "")
	f := &accountsFixture{state: filepath.Join(t.TempDir(), "state")}
	if err := os.Mkdir(f.state, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.key, err = statekey.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	f.keyFile = filepath.Join(t.TempDir(), "state.key")
	if err := os.WriteFile(f.keyFile, []byte(f.key.Base64()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.populate(t)
	return f
}

func (f *accountsFixture) open(t *testing.T) (*audit.Log, *accounts.Store) {
	t.Helper()
	l, err := audit.Open(filepath.Join(f.state, "audit"), audit.Options{Now: func() time.Time { return time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	s, err := accounts.Open(accounts.Options{StateDir: f.state, Key: f.key, Log: l})
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	return l, s
}

func (f *accountsFixture) populate(t *testing.T) {
	t.Helper()
	l, s := f.open(t)
	defer l.Close()
	for _, n := range []string{"alice", "bob"} {
		if _, err := s.Change(audit.Event{Event: "account_invited", Identity: "local:root", Target: "local:" + n}, func(st *accounts.State) error {
			a, err := accounts.NewAccount(n, n, "local:root", time.Now())
			st.Accounts[n] = a
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *accountsFixture) args(more ...string) []string {
	return append(more, "--state-dir", f.state, "--state-key-file", f.keyFile)
}

func TestAccountsListNeedsTheKeyAndPrintsNoSecret(t *testing.T) {
	f := newAccountsFixture(t)
	out, err := run(t, f.args("accounts", "list")...)
	if err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "bob") || !strings.Contains(out, "invited") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, f.key.Base64()) {
		t.Fatal("list printed the key")
	}

	for name, c := range map[string]struct {
		args []string
		env  string
		want string
	}{
		"no state dir":     {[]string{"accounts", "list", "--state-key-file", f.keyFile}, "", "--state-dir is required"},
		"state dir typo":   {[]string{"accounts", "list", "--state-dir", f.state + "-typo", "--state-key-file", f.keyFile}, "", "is not a directory"},
		"no key":           {[]string{"accounts", "list", "--state-dir", f.state}, "", "need the state key: set RACKBOOK_STATE_KEY"},
		"both key sources": {f.args("accounts", "list"), f.key.Base64(), "set only one of RACKBOOK_STATE_KEY and --state-key-file"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("RACKBOOK_STATE_KEY", c.env)
			if _, err := run(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		k, _ := statekey.GenerateKey()
		bad := filepath.Join(t.TempDir(), "bad")
		os.WriteFile(bad, []byte(k.Base64()), 0o600)
		if _, err := run(t, "accounts", "list", "--state-dir", f.state, "--state-key-file", bad); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the key must differ from the session key", func(t *testing.T) {
		t.Setenv("RACKBOOK_SESSION_KEY", f.key.Base64())
		if _, err := run(t, f.args("accounts", "list")...); err == nil || !strings.Contains(err.Error(), "must differ from the session key") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the key file must be outside the state dir", func(t *testing.T) {
		inside := filepath.Join(f.state, "key")
		os.WriteFile(inside, []byte(f.key.Base64()), 0o600)
		if _, err := run(t, "accounts", "list", "--state-dir", f.state, "--state-key-file", inside); err == nil || !strings.Contains(err.Error(), "inside --state-dir") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the key from the environment", func(t *testing.T) {
		t.Setenv("RACKBOOK_STATE_KEY", f.key.Base64())
		if _, err := run(t, "accounts", "list", "--state-dir", f.state); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAccountsOfflineCommandsNeedTheServerStopped(t *testing.T) {
	f := newAccountsFixture(t)
	unlock, err := fsutil.Lock(filepath.Join(f.state, "rackbook.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for _, sub := range [][]string{{"accept-restore", "--yes"}, {"discard-store", "--yes"}, {"rekey", "--generate", "--new-key-file", filepath.Join(t.TempDir(), "n")}} {
		if _, err := run(t, f.args(append([]string{"accounts"}, sub...)...)...); err == nil || !strings.Contains(err.Error(), "stop it first") {
			t.Errorf("%v: err = %v", sub, err)
		}
	}
	// list reads only and works beside a running server
	if _, err := run(t, f.args("accounts", "list")...); err != nil {
		t.Fatal(err)
	}
}

func TestAccountsRekeyGenerate(t *testing.T) {
	f := newAccountsFixture(t)
	newFile := filepath.Join(t.TempDir(), "new.key")
	out, err := run(t, f.args("accounts", "rekey", "--generate", "--new-key-file", newFile, "--operator", "ops")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := os.Stat(newFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("new key file: %v %v", st, err)
	}
	raw, _ := os.ReadFile(newFile)
	if strings.Contains(out, strings.TrimSpace(string(raw))) {
		t.Fatal("the new key was printed")
	}
	if _, err := run(t, f.args("accounts", "list")...); err == nil {
		t.Fatal("the old key still opens the store")
	}
	if out, err := run(t, "accounts", "list", "--state-dir", f.state, "--state-key-file", newFile); err != nil || !strings.Contains(out, "alice") {
		t.Fatalf("%v\n%s", err, out)
	}
	// the event names the operator
	l, err := audit.Open(filepath.Join(f.state, "audit"), audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var found bool
	l.EachEvent("", func(e audit.Event, _ string) bool {
		if e.Event == "account_store_rekeyed" && e.Method == "cli" {
			for _, d := range e.Detail {
				found = found || d == "operator:ops"
			}
		}
		return true
	})
	if !found {
		t.Fatal("no account_store_rekeyed event with the operator")
	}
	// --generate never overwrites a file, and the key file must be outside the state dir
	if _, err := run(t, "accounts", "rekey", "--generate", "--new-key-file", newFile, "--state-dir", f.state, "--state-key-file", newFile); err == nil {
		t.Fatal("an existing file was overwritten")
	}
	if _, err := run(t, f.args("accounts", "rekey", "--generate", "--new-key-file", filepath.Join(f.state, "n.key"))...); err == nil || !strings.Contains(err.Error(), "inside --state-dir") {
		t.Fatalf("err = %v", err)
	}
	if _, err := run(t, f.args("accounts", "rekey")...); err == nil || !strings.Contains(err.Error(), "--new-key-file is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestAccountsRekeyRefusesTheSessionKeyAndTheSameKey(t *testing.T) {
	f := newAccountsFixture(t)
	sess := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	newFile := filepath.Join(t.TempDir(), "n")
	os.WriteFile(newFile, []byte(sess), 0o600)
	t.Setenv("RACKBOOK_SESSION_KEY", sess)
	if _, err := run(t, f.args("accounts", "rekey", "--new-key-file", newFile)...); err == nil || !strings.Contains(err.Error(), "must differ from the session key") {
		t.Fatalf("err = %v", err)
	}
	t.Setenv("RACKBOOK_SESSION_KEY", "")
	if _, err := run(t, f.args("accounts", "rekey", "--new-key-file", f.keyFile)...); err == nil || !strings.Contains(err.Error(), "same as the old key") {
		t.Fatalf("err = %v", err)
	}
}

func TestAccountsAcceptRestorePromptsAndRestores(t *testing.T) {
	f := newAccountsFixture(t)
	acc := filepath.Join(f.state, "accounts", "accounts.enc")
	backup, _ := os.ReadFile(acc)
	l, s := f.open(t)
	if _, err := s.Change(audit.Event{Event: "account_disabled", Identity: "local:root", Target: "local:bob"}, func(st *accounts.State) error {
		st.Accounts["bob"].State = accounts.StateDisabled
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	os.WriteFile(acc, backup, 0o600)

	out, err := run(t, f.args("accounts", "accept-restore", "--yes")...)
	_ = out
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// run the gap again and decline at the prompt
	f2 := newAccountsFixture(t)
	acc2 := filepath.Join(f2.state, "accounts", "accounts.enc")
	backup2, _ := os.ReadFile(acc2)
	l, s = f2.open(t)
	s.Change(audit.Event{Event: "account_disabled", Identity: "local:root", Target: "local:bob"}, func(st *accounts.State) error { st.Accounts["bob"].State = accounts.StateDisabled; return nil })
	l.Close()
	os.WriteFile(acc2, backup2, 0o600)
	out, err = runWithStdin(t, "no\n", f2.args("accounts", "accept-restore")...)
	if err == nil || !strings.Contains(out, "account_disabled") || !strings.Contains(out, "Type yes") {
		t.Fatalf("%v\n%s", err, out)
	}
	if after, _ := os.ReadFile(acc2); !bytes.Equal(after, backup2) {
		t.Fatal("a declined restore changed the store")
	}
	out, err = runWithStdin(t, "yes\n", f2.args("accounts", "accept-restore")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = run(t, f2.args("accounts", "list")...)
	if err != nil || !strings.Contains(out, "disabled") {
		t.Fatalf("%v\n%s", err, out)
	}
	// nothing is left to accept
	if out, err := run(t, f2.args("accounts", "accept-restore", "--yes")...); err != nil || !strings.Contains(out, "Nothing to accept") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestAccountsDiscardStore(t *testing.T) {
	f := newAccountsFixture(t)
	k, _ := statekey.GenerateKey()
	newFile := filepath.Join(t.TempDir(), "new.key")
	os.WriteFile(newFile, []byte(k.Base64()), 0o600)
	args := []string{"accounts", "discard-store", "--state-dir", f.state, "--state-key-file", newFile}
	out, err := runWithStdin(t, "no\n", args...)
	if err == nil || !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(f.state, "accounts", "accounts.enc")); err != nil {
		t.Fatal("a declined discard moved the store")
	}
	if out, err := runWithStdin(t, "yes\n", args...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(t, "accounts", "list", "--state-dir", f.state, "--state-key-file", newFile); err != nil || !strings.Contains(out, "no accounts") {
		t.Fatalf("%v\n%s", err, out)
	}
	// the old key opens nothing of the new store, and the names stay used
	if _, err := accounts.ReadUsernames(filepath.Join(f.state, "accounts", "usernames"), k); err != nil {
		t.Fatal(err)
	}
	// a store that opens is not discarded
	if _, err := run(t, "accounts", "discard-store", "--yes", "--state-dir", f.state, "--state-key-file", newFile); err == nil || !strings.Contains(err.Error(), "nothing to discard") {
		t.Fatalf("err = %v", err)
	}
}

func TestServeDoesNotReadTheStateKeyYet(t *testing.T) {
	// Nothing is reachable from HTTP in this piece: serve has no state-key flag and no account code.
	for _, name := range []string{"state-key-file", "state-key"} {
		if newServe().Flags().Lookup(name) != nil {
			t.Fatalf("serve has --%s", name)
		}
	}
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"internal/accounts", "STATE_KEY", "statekey"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("serve.go mentions %q", banned)
		}
	}
}
