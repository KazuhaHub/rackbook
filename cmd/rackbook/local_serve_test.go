package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/statekey"
	"github.com/kazuhahub/rackbook/internal/testutil"
)

// serveArgs is a serve command line for --auth login that stops at a refusal: it never gets to listen.
func serveArgs(t *testing.T, state string, more ...string) []string {
	t.Helper()
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	return append([]string{"serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git", "--auth", "login", "--base-url", "https://ledger.example.com", "--state-dir", state}, more...)
}

func writeKey(t *testing.T, k *statekey.Key) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(k.Base64()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServeLoginFlagsAreChecked(t *testing.T) {
	// --auth login is the built-in login, and oidc its alias
	if f := newServe().Flags().Lookup("state-key-file"); f == nil {
		t.Fatal("serve has no --state-key-file")
	}
	fx := newAccountsFixture(t) // a state dir with alice and bob, the key, and a key file outside the dir
	other, _ := statekey.GenerateKey()
	otherFile := writeKey(t, other)
	session := writeKey(t, fx.key) // a session key file that holds the state key
	sessionOther := writeKey(t, other)

	for name, c := range map[string]struct {
		state string
		args  []string
		want  string
	}{
		"a wrong state key": {fx.state, []string{"--state-key-file", otherFile},
			"refused to start (wrong_key)"},
		"accounts on disk and no key": {fx.state, nil,
			"encrypted under the state key"},
		"a key and no state dir": {"", []string{"--state-key-file", fx.keyFile},
			"need --state-dir"},
		"a key kept inside the state dir": {fx.state, []string{"--state-key-file", filepath.Join(fx.state, "k")},
			"inside --state-dir"},
		"the state key is the session key": {fx.state, []string{"--state-key-file", fx.keyFile, "--session-key-file", session},
			"must differ from the session key"},
		"a state key with another auth mode": {fx.state, nil, "are for local accounts"},
	} {
		args := serveArgs(t, c.state, c.args...)
		if c.state == "" {
			args = serveArgsWithout(t, c.args...)
		}
		if name == "a state key with another auth mode" {
			args = []string{"serve", "--listen", "127.0.0.1:0", "--config", filepath.Join(testutil.CopyExample(t), "rackbook.yml"), "--no-git", "--auth", "none", "--state-key-file", fx.keyFile}
		}
		t.Setenv("RACKBOOK_STATE_KEY", "")
		t.Setenv("RACKBOOK_SESSION_KEY", "")
		out, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v %s (want %q)", name, err, out, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), fx.key.Base64()) || strings.Contains(err.Error(), other.Base64())) {
			t.Errorf("%s: the error prints key material", name)
		}
	}

	// the start sequence refuses: a missing store while the log has its changes
	if err := os.Remove(filepath.Join(fx.state, "accounts", "accounts.enc")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RACKBOOK_STATE_KEY", "")
	if _, err := run(t, serveArgs(t, fx.state, "--state-key-file", fx.keyFile, "--session-key-file", sessionOther)...); err == nil || !strings.Contains(err.Error(), "refused to start (missing)") {
		t.Fatalf("a store that is gone: %v", err)
	}

	// neither single sign-on nor local accounts: nothing to sign in with
	empty := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, serveArgs(t, empty, "--session-key-file", sessionOther)...); err == nil || !strings.Contains(err.Error(), "neither is available") {
		t.Fatalf("no SSO and no state key: %v", err)
	}
}

// serveArgsWithout is serveArgs with no --state-dir.
func serveArgsWithout(t *testing.T, more ...string) []string {
	t.Helper()
	cfg := filepath.Join(testutil.CopyExample(t), "rackbook.yml")
	return append([]string{"serve", "--listen", "127.0.0.1:0", "--config", cfg, "--no-git", "--auth", "login", "--base-url", "https://ledger.example.com"}, more...)
}

// With the right key the start sequence passes, and the store answers what sessions, tokens and grants ask.
func TestServeOpensTheAccountStoreWithTheRightKey(t *testing.T) {
	fx := newAccountsFixture(t)
	f := newServe().Flags()
	if err := f.Set("state-key-file", fx.keyFile); err != nil {
		t.Fatal(err)
	}
	key, err := loadStateKey(f, fx.state)
	if err != nil || key == nil || !key.Equal(fx.key) {
		t.Fatalf("%v", err)
	}
	pin := accounts.NewPin(fx.state, key)
	l, err := audit.Open(filepath.Join(fx.state, "audit"), audit.Options{Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, err := openAccounts(fx.state, key, l, pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	// alice and bob were invited: they exist, and an invited account holds no session or role
	if names := st.Snapshot().Names(); len(names) != 2 || st.LocalActive("alice") || st.LocalActive("nobody") {
		t.Fatalf("%v", names)
	}
	if _, _, ok := st.LiveSession("alice"); ok {
		t.Fatal("an invited account has a live session")
	}
	// no key given: nothing, and nothing is refused when there are no account files
	empty := t.TempDir()
	t.Setenv("RACKBOOK_STATE_KEY", "")
	if k, err := loadStateKey(newServe().Flags(), empty); k != nil || err != nil {
		t.Fatalf("%v %v", k, err)
	}
	// a nil audit log is refused: the changes of the store are audited before they are made
	if _, err := openAccounts(fx.state, key, nil, pin, nil); err == nil {
		t.Fatal("opened without an audit log")
	}
}

// The state key in the environment is for --auth login alone, and is removed from the process environment once
// it is read, so that git and anything else the server starts does not inherit it.
func TestStateKeyEnvironmentVariableIsRefusedElsewhereAndUnsetOnceRead(t *testing.T) {
	fx := newAccountsFixture(t)
	t.Setenv("RACKBOOK_STATE_KEY", fx.key.Base64())
	args := []string{"serve", "--listen", "127.0.0.1:0", "--config", filepath.Join(testutil.CopyExample(t), "rackbook.yml"), "--no-git", "--auth", "none"}
	if _, err := run(t, args...); err == nil || !strings.Contains(err.Error(), "RACKBOOK_STATE_KEY are for local accounts") {
		t.Fatalf("%v", err)
	}
	if os.Getenv("RACKBOOK_STATE_KEY") == "" {
		t.Fatal("a refused start must not have read the key")
	}
	key, err := loadStateKey(newServe().Flags(), fx.state)
	if err != nil || key == nil || !key.Equal(fx.key) {
		t.Fatalf("%v", err)
	}
	if v, ok := os.LookupEnv("RACKBOOK_STATE_KEY"); ok {
		t.Fatalf("the state key is still in the environment (%d bytes)", len(v))
	}
}
