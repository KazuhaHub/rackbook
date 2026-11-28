package login

import (
	"net/http/httptest"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/api"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

// localRoles are roles for a deployment with local accounts beside single sign-on.
const localRoles = `  roles:
    admin: [kazuha@kazuha.org, "local:alice"]
    editor: ["*@kazuha.org", "local:bob"]
    viewer: [guest@example.com, "local:*"]
  auditors: ["local:carol"]
`

// openLocal makes a state directory with a state key and opens the account store on the env's audit log.
func (e *env) openLocal(al *audit.Log) {
	e.t.Helper()
	k, err := statekey.GenerateKey()
	if err != nil {
		e.t.Fatal(err)
	}
	e.stateKey, e.stateDir = k, e.t.TempDir()
	e.local, err = accounts.Open(accounts.Options{StateDir: e.stateDir, Key: k, Log: al, Now: e.clk.Now})
	if err != nil {
		e.t.Fatal(err)
	}
}

// addLocal makes an account in the state given (accounts.StateActive and so on).
func (e *env) addLocal(name, state string) {
	e.t.Helper()
	_, err := e.local.Change(audit.Event{Event: "account_invited", Target: "local:" + name}, func(st *accounts.State) error {
		a, err := accounts.NewAccount(name, "Name of "+name, "local:root", e.clk.Now())
		if err != nil {
			return err
		}
		a.State = state
		st.Accounts[name] = a
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// changeLocal changes an account the way the writer's callers do: with its audited event.
func (e *env) changeLocal(name, event string, fn func(a *accounts.Account)) {
	e.t.Helper()
	_, err := e.local.Change(audit.Event{Event: event, Target: "local:" + name}, func(st *accounts.State) error {
		fn(st.Accounts[name])
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) disableLocal(name string) {
	e.t.Helper()
	e.changeLocal(name, "account_disabled", func(a *accounts.Account) { a.State = accounts.StateDisabled; _ = a.RenewSessions() })
}

func (e *env) enableLocal(name string) {
	e.t.Helper()
	e.changeLocal(name, "account_enabled", func(a *accounts.Account) { a.State = accounts.StateActive })
}

func (e *env) removeLocal(name string) {
	e.t.Helper()
	e.changeLocal(name, "account_removed", func(a *accounts.Account) { a.State = accounts.StateRemoved; _ = a.RenewSessions() })
}

// renewLocal ends every session of the account without changing its state (sessions_ended, a rekey of the
// account's session id and secret).
func (e *env) renewLocal(name string) {
	e.t.Helper()
	e.changeLocal(name, "sessions_ended", func(a *accounts.Account) { _ = a.RenewSessions() })
}

// localCookie is a session cookie of a local account, made by the test helper that stands in for the sign-in of
// a later piece: no route of the server makes one.
func (e *env) localCookie(name string) string {
	e.t.Helper()
	sid, secret, ok := e.local.LiveSession(name)
	clear(secret)
	if !ok {
		e.t.Fatalf("account %s cannot hold a session", name)
	}
	now := e.clk.Now().Unix()
	sess := session{ID: "local:" + name, Name: "Name of " + name, Method: auth.MethodLocal, Issued: now, Seen: now, Sid: sid, AuthAt: now, Factor: "totp"}
	w := httptest.NewRecorder()
	if _, _, _, err := e.svc.setSession(w, sess); err != nil {
		e.t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	e.t.Fatal("no session cookie")
	return ""
}

// localBrowser is a browser holding a local session of the account.
func (e *env) localBrowser(name string) *browser {
	e.t.Helper()
	b := e.browser()
	b.setCookie(SessionCookie, e.localCookie(name))
	return b
}

// testRoster is what cmd/rackbook's adapter is: the account store as the role editor sees it.
type testRoster struct{ s *accounts.Store }

func (r testRoster) Roster() []api.LocalAccount {
	var out []api.LocalAccount
	for _, e := range r.s.Roster() {
		out = append(out, api.LocalAccount{Username: e.Username, Name: e.Name, State: e.State})
	}
	return out
}
