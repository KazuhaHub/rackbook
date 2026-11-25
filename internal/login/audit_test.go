package login

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kazuhahub/rackbook/internal/audit"

	"encoding/json"
)

// events reads the audit log of the env, oldest first.
func (e *env) events() []audit.Event {
	e.t.Helper()
	files, _ := filepath.Glob(filepath.Join(e.audit, "audit-*.jsonl"))
	var out []audit.Event
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			e.t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var ev audit.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				e.t.Fatal(err)
			}
			out = append(out, ev)
		}
	}
	return out
}

// last is the newest event.
func (e *env) last() audit.Event {
	e.t.Helper()
	evs := e.events()
	if len(evs) == 0 {
		e.t.Fatal("nothing was recorded")
	}
	return evs[len(evs)-1]
}

func TestAuditLoginAndLogout(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{})
	b := e.browser()
	b.login("admin", "")
	ev := e.last()
	if ev.Event != "login" || ev.Identity != "kazuha@kazuha.org" || ev.Name != "Kazuha M" || ev.Method != "oidc" || ev.Role != "admin" || ev.Addr != "127.0.0.0" {
		t.Fatalf("login: %+v", ev)
	}
	b.do("POST", "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin", "Accept": "application/json"}, nil)
	ev = e.last()
	if ev.Event != "logout" || ev.Identity != "kazuha@kazuha.org" || ev.Method != "oidc" || ev.Role != "admin" {
		t.Fatalf("logout: %+v", ev)
	}
	// A logout without a session records nothing.
	n := len(e.events())
	e.browser().do("POST", "/auth/logout", map[string]string{"Sec-Fetch-Site": "same-origin"}, nil)
	if len(e.events()) != n {
		t.Fatal("a logout without a session must not be recorded")
	}
	if rep, err := audit.Verify(e.audit); err != nil || !rep.OK {
		t.Fatalf("%v %+v", err, rep)
	}
}

func TestAuditLoginRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{})
	tests := []struct {
		name   string
		user   string
		mutate func(map[string]any)
		reason string
		ident  string
	}{
		{"no role", "nobody", nil, "no_role", "nobody@elsewhere.net"},
		{"tenant", "foreign", nil, "tenant", "ed@kazuha.org"},
		{"claims", "admin", func(c map[string]any) { delete(c, "preferred_username") }, "claims", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e.idp.Mutate = tc.mutate
			defer func() { e.idp.Mutate = nil }()
			e.t = t
			e.browser().login(tc.user, "")
			ev := e.last()
			if ev.Event != "login_refused" || ev.Reason != tc.reason || ev.Identity != tc.ident || ev.Method != "oidc" || ev.Role != "" {
				t.Fatalf("%+v", ev)
			}
		})
	}
	for _, ev := range e.events() {
		if ev.Event == "login" {
			t.Fatalf("a refused login must not be recorded as a login: %+v", ev)
		}
	}
}

func TestAuditPasskey(t *testing.T) {
	t.Parallel()
	e := newEnv(t, options{passkeys: true, nogit: true})
	stranger := e.newDevice()
	stranger.auth.Options.UserHandle = []byte("whoever")
	stranger.auth.AddCredential(stranger.cred)
	stranger.login(e.browser(), "")
	if ev := e.last(); ev.Event != "login_refused" || ev.Reason != "passkey_failed" || ev.Method != "passkey" {
		t.Fatalf("unknown credential: %+v", ev)
	}
	owner := e.browser()
	owner.login("editor", "")
	dev := e.newDevice()
	if fin := dev.enrol(owner, "key"); fin.StatusCode != 201 {
		t.Fatalf("enrol: %d %s", fin.StatusCode, fin.Body)
	}
	dev.login(e.browser(), "")
	if ev := e.last(); ev.Event != "login" || ev.Method != "passkey" || ev.Role != "editor" || ev.Identity != "ed@kazuha.org" {
		t.Fatalf("login: %+v", ev)
	}
	e.rewriteRoles("  roles:\n    admin: [kazuha@kazuha.org]\n")
	dev.login(e.browser(), "")
	if ev := e.last(); ev.Event != "login_refused" || ev.Reason != "no_role" || ev.Identity != "ed@kazuha.org" || ev.Method != "passkey" {
		t.Fatalf("no role: %+v", ev)
	}
}
