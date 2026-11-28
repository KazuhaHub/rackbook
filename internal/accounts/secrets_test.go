package accounts

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kazuhahub/rackbook/internal/audit"
)

var admin = audit.Event{Identity: "local:admin", Name: "Admin", Method: "local", Addr: "203.0.113.7"}

func mustApply(t *testing.T, s *Secrets, u Update) {
	t.Helper()
	if err := s.Apply(u, admin); err != nil {
		t.Fatal(err)
	}
}

func TestSecretsAreWriteOnly(t *testing.T) {
	e := newEnv(t)
	s, err := e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.HasCaptchaSecret || st.HasOIDCClientSecret {
		t.Fatalf("a new store has secrets: %+v", st)
	}
	const value = "captcha-secret-value-7f3a"
	mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: value}})
	if st := s.Status(); !st.HasCaptchaSecret || st.HasOIDCClientSecret {
		t.Fatalf("status = %+v", st)
	}
	// the only thing the API can say is has_*
	if got := fmt.Sprintf("%+v", s.Status()); strings.Contains(got, value) {
		t.Fatal("status shows the value")
	}
	// the value is nowhere on disk in the clear, and nowhere in the audit log
	if strings.Contains(string(readFile(t, SecretsPath(e.dir))), value) {
		t.Fatal("secrets.enc holds the value in the clear")
	}
	for _, ev := range e.events() {
		b := fmt.Sprintf("%+v", ev)
		if strings.Contains(b, value) {
			t.Fatalf("the audit log holds the secret: %s", b)
		}
	}
	set := e.eventsNamed("settings_secret_set")
	if len(set) != 1 || set[0].Identity != "local:admin" || len(set[0].Detail) != 2 || set[0].Detail[0] != "name:captcha_secret" || !strings.HasPrefix(set[0].Detail[1], "secrets_change:") {
		t.Fatalf("event = %+v", set)
	}
	// an error or a log line never prints it
	entry := &SecretEntry{Value: value}
	if got := fmt.Sprintf("%v %+v %#v %s", entry, *entry, *entry, entry.Value); strings.Contains(got, value) {
		t.Fatalf("a secret printed itself: %s", got)
	}
	// the server can still use it, and it survives a restart
	e.restart()
	s, err = e.openSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.CaptchaSecret(); !ok || v != value {
		t.Fatal("the stored secret is gone after a restart")
	}
}

func TestEmptyMeansKeepAndClearIsExplicit(t *testing.T) {
	e := newEnv(t)
	s, _ := e.openSecrets()
	mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: "one"}})
	n := len(e.events())

	// a form that sends every field with a blank secret keeps it, and writes nothing
	mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: ""}})
	if v, _ := s.CaptchaSecret(); v != "one" || len(e.events()) != n {
		t.Fatal("a blank secret must keep the stored value and write no event")
	}
	// clearing a secret that is not set is a no-op, too
	mustApply(t, s, Update{Clear: []string{SecretOIDCClient}})
	if len(e.events()) != n {
		t.Fatal("clearing nothing wrote an event")
	}
	mustApply(t, s, Update{Clear: []string{SecretCaptcha}})
	if s.Status().HasCaptchaSecret {
		t.Fatal("Clear did not clear")
	}
	cl := e.eventsNamed("settings_secret_cleared")
	if len(cl) != 1 || cl[0].Detail[0] != "name:captcha_secret" || cl[0].Cause != "" {
		t.Fatalf("clear event = %+v", cl)
	}
	// refusals change nothing
	mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: "two"}})
	n = len(e.events())
	for name, u := range map[string]Update{
		"set and clear": {Set: map[string]string{SecretCaptcha: "x"}, Clear: []string{SecretCaptcha}},
		"unknown":       {Set: map[string]string{"nope": "x"}},
		"unknown clear": {Clear: []string{"nope"}},
		"too long":      {Set: map[string]string{SecretCaptcha: strings.Repeat("x", MaxSecretLen+1)}},
		"oidc unbound":  {Set: map[string]string{SecretOIDCClient: "x"}},
	} {
		if err := s.Apply(u, admin); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if v, _ := s.CaptchaSecret(); v != "two" || len(e.events()) != n {
		t.Fatal("a refused update changed something")
	}
}

func TestOIDCSecretIsBoundToIssuerAndClient(t *testing.T) {
	e := newEnv(t)
	s, _ := e.openSecrets()
	const iss, cli = "https://login.example.com/tenant/v2.0", "client-1"
	mustApply(t, s, Update{Set: map[string]string{SecretOIDCClient: "oidc-secret"}, Issuer: iss, ClientID: cli})

	if v, ok := s.OIDCClientSecret(iss, cli); !ok || v != "oidc-secret" {
		t.Fatal("the secret is not available to its own issuer and client")
	}
	for _, c := range [][2]string{{"https://evil.example.net", cli}, {iss, "client-2"}, {"", ""}, {iss, ""}} {
		if v, ok := s.OIDCClientSecret(c[0], c[1]); ok || v != "" {
			t.Fatalf("the secret was handed out for %v", c)
		}
	}
	if i, c, ok := s.OIDCBinding(); !ok || i != iss || c != cli {
		t.Fatalf("binding = %q %q %v", i, c, ok)
	}

	// changing the issuer or client in the console, without a new secret in the same save: refused
	for _, u := range []Update{{Issuer: "https://other.example.com", ClientID: cli}, {Issuer: iss, ClientID: "client-2"}} {
		if err := s.Apply(u, admin); !errors.Is(err, ErrOIDCSecretRequired) {
			t.Fatalf("err = %v", err)
		}
	}
	if _, ok := s.OIDCClientSecret(iss, cli); !ok {
		t.Fatal("a refused save cleared the secret")
	}
	// the same save with a new secret rebinds
	mustApply(t, s, Update{Set: map[string]string{SecretOIDCClient: "new-secret"}, Issuer: "https://other.example.com", ClientID: cli})
	if _, ok := s.OIDCClientSecret(iss, cli); ok {
		t.Fatal("the old binding still works")
	}
	if v, ok := s.OIDCClientSecret("https://other.example.com", cli); !ok || v != "new-secret" {
		t.Fatal("the new binding does not work")
	}
	// a push that changed rackbook.yml: the binding no longer matches, the secret is cleared and says why
	cleared, err := s.ClearForBinding("https://third.example.com", cli, admin)
	if err != nil || !cleared || s.Status().HasOIDCClientSecret {
		t.Fatalf("cleared=%v err=%v", cleared, err)
	}
	cl := e.eventsNamed("settings_secret_cleared")
	if len(cl) != 1 || cl[0].Cause != "binding" || cl[0].Detail[0] != "name:oidc_client_secret" {
		t.Fatalf("event = %+v", cl)
	}
	if c, _ := s.ClearForBinding("x", "y", admin); c {
		t.Fatal("nothing to clear")
	}
}

func TestSecretsCrashAndRollback(t *testing.T) {
	t.Run("crash after the audit event is recovered", func(t *testing.T) {
		e := newEnv(t)
		o := e.opts()
		o.hook = func(step string) error {
			if step == "event" {
				return errCrash
			}
			return nil
		}
		s, err := OpenSecrets(o)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(Update{Set: map[string]string{SecretCaptcha: "v"}}, admin); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		e.restart()
		s2, err := e.openSecrets()
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := s2.CaptchaSecret(); !ok || v != "v" {
			t.Fatal("the audited secret change was not recovered")
		}
		if got := e.eventsNamed("account_store_problem"); len(got) != 1 || got[0].Code != "recovered" {
			t.Fatalf("events = %+v", got)
		}
	})
	t.Run("an older secrets.enc is a gap", func(t *testing.T) {
		e := newEnv(t)
		s, _ := e.openSecrets()
		mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: "one"}})
		old := readFile(t, SecretsPath(e.dir))
		mustApply(t, s, Update{Clear: []string{SecretCaptcha}}) // the clear must not be undone by a restore
		os.WriteFile(SecretsPath(e.dir), old, 0o600)
		e.restart()
		_, err := e.openSecrets()
		var se *StartError
		if !errors.As(err, &se) || se.Code != CodeGap || se.Gap == nil || len(se.Gap.Events) != 1 || se.Gap.Events[0].Event != "settings_secret_cleared" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		e := newEnv(t)
		s, _ := e.openSecrets()
		mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: "one"}})
		o := e.opts()
		o.Key = mustNewKey(t)
		if _, err := OpenSecrets(o); startCode(t, err) != CodeWrongKey {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the account store's events do not confuse the secrets' start", func(t *testing.T) {
		e := newEnv(t)
		st := e.mustOpen()
		s, _ := e.openSecrets()
		mustApply(t, s, Update{Set: map[string]string{SecretCaptcha: "one"}})
		e.mustInvite(st, "alice")
		e.restart()
		e.mustOpen()
		if _, err := e.openSecrets(); err != nil {
			t.Fatal(err)
		}
	})
}
