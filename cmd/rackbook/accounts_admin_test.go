package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/localauth"
)

func linkOf(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.Contains(l, "/auth/local/setup#") {
			return l
		}
	}
	t.Fatalf("no link in\n%s", out)
	return ""
}

func TestOfflineCommandsInviteResetRecoverWithoutAPasswordOnTheCommandLine(t *testing.T) {
	f := newAccountsFixture(t)
	out, err := run(t, f.args("accounts", "invite", "carol", "--name", "Carol", "--base-url", "https://ledger.example.com", "--operator", "ops")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "https://ledger.example.com/auth/local/setup#") || !strings.Contains(out, "invite link for carol") || !strings.Contains(out, "working on the files") {
		t.Fatal(out)
	}
	// no command takes a password
	for _, name := range []string{"invite", "reset", "unlock", "disable", "enable", "remove", "end-sessions", "recover"} {
		c, _, err := newRoot().Find([]string{"accounts", name})
		if err != nil {
			t.Fatal(err)
		}
		c.Flags().VisitAll(func(fl *pflag.Flag) {
			if strings.Contains(strings.ToLower(fl.Name), "password") {
				t.Errorf("%s has a flag %s", name, fl.Name)
			}
		})
	}
	// the account is invited and the audit event is the CLI's, without the link
	l, s := f.open(t)
	defer l.Close()
	if a := s.Snapshot().Accounts["carol"]; a == nil || a.State != accounts.StateInvited || a.Pending == nil {
		t.Fatalf("%+v", a)
	}
	tok := strings.SplitN(linkOf(t, out), "#", 2)[1]
	var seen bool
	_ = l.EachEvent("", func(ev audit.Event, _ string) bool {
		if ev.Event == "account_invited" && ev.Target == "local:carol" {
			seen = ev.Method == "cli" && len(ev.Detail) > 0 && ev.Detail[0] == "operator:ops"
		}
		if strings.Contains(strings.Join(ev.Detail, " "), tok) {
			t.Error("the link is in the audit log")
		}
		return true
	})
	if !seen {
		t.Fatal("no CLI invite event")
	}
	l.Close()
	// recover: an existing account gets a full reset, an unknown name an invite; --grant-admin offline says what to add
	out, err = run(t, f.args("accounts", "recover", "alice")...)
	if err != nil || !strings.Contains(out, "reset link (scope all) for alice") || !strings.Contains(out, "takes over the account") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = run(t, f.args("accounts", "recover", "dave", "--grant-admin")...)
	if err != nil || !strings.Contains(out, "invite link for dave") || !strings.Contains(out, `"local:dave"`) || !strings.Contains(out, "nothing was committed") {
		t.Fatalf("%v\n%s", err, out)
	}
	// errors: a used name, a bad scope
	if _, err := run(t, f.args("accounts", "invite", "carol")...); err == nil || !strings.Contains(err.Error(), "used before") {
		t.Fatalf("%v", err)
	}
	if _, err := run(t, f.args("accounts", "reset", "bob", "--scope", "nonsense")...); err == nil {
		t.Fatal("a bad scope was accepted")
	}
	// disable, enable, remove, end-sessions, unlock
	for _, c := range [][]string{{"unlock", "bob"}, {"end-sessions", "bob"}, {"end-sessions", "--all"}, {"disable", "bob", "--yes"}} {
		if out, err := run(t, f.args(append([]string{"accounts"}, c...)...)...); err != nil {
			t.Fatalf("%v: %v\n%s", c, err, out)
		}
	}
	// the tokens and grants of a disabled account are recorded to be revoked by the server at its next start: until then it stays
	// disabled (an enable is refused), and a removal goes on
	if out, err := run(t, f.args("accounts", "enable", "bob")...); err == nil || !strings.Contains(err.Error(), "still to be revoked") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(t, f.args("accounts", "remove", "bob", "--yes")...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// without --yes the commands that are hard to undo ask, and a no changes nothing
	if _, err := run(t, f.args("accounts", "remove", "alice")...); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("remove without a yes: %v", err)
	}
	if _, err := runWithStdin(t, "yes\n", append([]string{"accounts", "disable", "alice"}, f.args()...)...); err != nil {
		t.Fatalf("disable after a yes: %v", err)
	}
	if _, err := run(t, f.args("accounts", "reset", "--all")...); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("reset --all without a yes: %v", err)
	}
	if out, err := run(t, f.args("accounts", "list")...); err != nil || !strings.Contains(out, "removed") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestOnlineCommandsGoOverTheAdminChannelWhenAServerRuns(t *testing.T) {
	f := newAccountsFixture(t)
	l, s := f.open(t)
	defer l.Close()
	srv, err := localauth.ServeAdminWith(f.state, f.key, func() localauth.AdminEnv {
		return localauth.AdminEnv{Store: s, BaseURL: "https://ledger.example.com", InviteTTL: func() time.Duration { return 72 * time.Hour }, ResetTTL: func() time.Duration { return 24 * time.Hour }}
	}, nil)
	if err != nil {
		t.Skip(err)
	}
	defer srv.Close()
	// the offline path would fail: the running "server" holds the account store open, and the lock is not ours to take
	out, err := run(t, f.args("accounts", "invite", "erin", "--operator", "ops")...)
	if err != nil || strings.Contains(out, "working on the files") || !strings.Contains(out, "https://ledger.example.com/auth/local/setup#") {
		t.Fatalf("%v\n%s", err, out)
	}
	if a := s.Snapshot().Accounts["erin"]; a == nil || a.State != accounts.StateInvited {
		t.Fatalf("the running server's store did not get the account: %+v", a)
	}
	// a wrong key is refused before anything is sent
	other := newAccountsFixture(t)
	if _, err := run(t, "accounts", "invite", "mallory", "--state-dir", f.state, "--state-key-file", other.keyFile); err == nil {
		t.Fatal("a wrong key must not run a command")
	}
	if s.Snapshot().Accounts["mallory"] != nil {
		t.Fatal("mallory was invited")
	}
	// errors of the server come back as errors of the command
	if _, err := run(t, f.args("accounts", "disable", "nobody-here", "--yes")...); err == nil || !strings.Contains(err.Error(), "no such account") {
		t.Fatalf("%v", err)
	}
}

// Without a server the last-administrator guard of 5.9 is applied when rackbook.yml is given: sso_only is on, boss is the only
// local administrator, so boss cannot be disabled or removed; a second administrator lifts it.
func TestOfflineDisableAppliesTheLastAdminGuardUnderSSOOnly(t *testing.T) {
	f := newAccountsFixture(t)
	l, s := f.open(t)
	hasher := accounts.NewHasherCost(accounts.NewSlots(3, 5*time.Second), 64, 1, 1)
	mkActive := func(name string) {
		tok, err := s.Invite(accounts.CLI("t"), name, name, 72*time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		_, hold, _ := accounts.NewHold()
		if _, _, err := s.OpenLink(tok, hold, "", time.Now()); err != nil {
			t.Fatal(err)
		}
		sec, _ := accounts.NewTOTPSecret()
		fac, err := accounts.NewTOTPFactor(sec, accounts.TOTPCode(sec, accounts.TOTPStep(time.Now())), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		pw, _ := hasher.Hash(t.Context(), accounts.ClassNormal, "correct horse battery staple")
		if _, err := s.CompleteSetup(accounts.Setup{Token: tok, Holder: hold, Password: pw, TOTP: fac, Factor: "totp"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	mkActive("boss")
	mkActive("deputy")
	l.Close()
	cfg := filepath.Join(t.TempDir(), "rackbook.yml")
	yml := "collections:\n  a: {file: a.yml, schema: s.json}\nauth:\n  mode: oidc\n  oidc: {issuer: 'https://idp.example', client_id: x}\n  login: {sso_only: true}\n  roles:\n    admin: ['local:boss']\n"
	if err := os.WriteFile(cfg, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, f.args("accounts", "disable", "boss", "--yes", "--config", cfg)...); err == nil || !strings.Contains(err.Error(), "last active local administrator") {
		t.Fatalf("the only local administrator was disabled: %v", err)
	}
	if _, err := run(t, f.args("accounts", "remove", "boss", "--yes", "--config", cfg)...); err == nil {
		t.Fatal("the only local administrator was removed")
	}
	// a non-admin is not protected, and with a second administrator the first can go
	if out, err := run(t, f.args("accounts", "disable", "deputy", "--yes", "--config", cfg)...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// without --config the guard cannot be checked, and the command says so
	out, err := run(t, f.args("accounts", "remove", "bob", "--yes")...)
	if err != nil || !strings.Contains(out, "sso_only guard") {
		t.Fatalf("%v\n%s", err, out)
	}
}
