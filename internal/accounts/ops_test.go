package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/audit"
)

var rootActor = Actor{Identity: "local:root", Name: "Root", Method: "local", Addr: "203.0.113.1"}

func (e *env) setupActive(s *Store, name string) {
	e.t.Helper()
	tok, err := s.Invite(rootActor, name, "Test", 72*time.Hour, e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	e.finish(s, tok)
}

// finish opens the link and completes setup with a password and a TOTP.
func (e *env) finish(s *Store, tok string) string {
	e.t.Helper()
	hold, hh, _ := NewHold()
	_ = hold
	if _, _, err := s.OpenLink(tok, hh, "203.0.113.2", e.clk.Now()); err != nil {
		e.t.Fatal(err)
	}
	sec, _ := NewTOTPSecret()
	f, err := NewTOTPFactor(sec, TOTPCode(sec, TOTPStep(e.clk.Now())), e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	pw, _ := hashPassword("correct horse battery staple")
	u, err := s.CompleteSetup(Setup{Token: tok, Holder: hh, Password: pw, TOTP: f, Factor: "totp", Addr: "203.0.113.2"}, e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func TestInviteOpenSetupIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	tok, err := s.Invite(rootActor, "alice", "Alice", 72*time.Hour, e.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := s.Snapshot()
	a := st.Accounts["alice"]
	if a.State != StateInvited || a.Pending == nil || a.Pending.Kind != LinkInvite || bytes.Contains(a.Pending.TokenHash, []byte(tok)) {
		t.Fatalf("%+v", a)
	}
	// a wrong token
	if _, _, err := s.OpenLink("nope", "h", "", e.clk.Now()); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("wrong token: %v", err)
	}
	// setup before the link was opened is refused
	if _, err := s.CompleteSetup(Setup{Token: tok, Holder: "x", Password: "p", Factor: "totp"}, e.clk.Now()); err == nil {
		t.Fatal("setup without an opened link")
	}
	e.finish(s, tok)
	st = s.Snapshot()
	if got := st.Accounts["alice"]; got.State != StateActive || got.Pending != nil || got.Password == "" || got.TOTP == nil {
		t.Fatalf("%+v", got)
	}
	// single use: the token no longer opens anything
	if _, _, err := s.OpenLink(tok, "h", "", e.clk.Now()); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("a used token opened again: %v", err)
	}
	// an expired invite
	tok2, _ := s.Invite(rootActor, "bob", "Bob", time.Hour, e.clk.Now())
	e.clk.Set(e.clk.Now().Add(61 * time.Minute))
	if _, _, err := s.OpenLink(tok2, "h", "", e.clk.Now()); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestOpenLinkHoldsTheLinkForOneBrowser(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	tok, _ := s.Invite(rootActor, "alice", "Alice", 72*time.Hour, e.clk.Now())
	_, h1, _ := NewHold()
	_, h2, _ := NewHold()
	if _, _, err := s.OpenLink(tok, h1, "", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenLink(tok, h2, "", e.clk.Now().Add(time.Minute)); !errors.Is(err, ErrLinkClaimed) {
		t.Fatalf("another browser during the hold: %v", err)
	}
	if _, err := s.CompleteSetup(Setup{Token: tok, Holder: h2, Password: "x", Factor: "totp"}, e.clk.Now().Add(time.Minute)); !errors.Is(err, ErrLinkClaimed) {
		t.Fatalf("setup from the other browser: %v", err)
	}
	if _, _, err := s.OpenLink(tok, h1, "", e.clk.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("the same browser may open again: %v", err)
	}
	// the hold ends: the link is dead for everybody, the holder included
	e.clk.Set(e.clk.Now().Add(HoldTime + 3*time.Minute))
	if _, _, err := s.OpenLink(tok, h1, "", e.clk.Now()); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("after the hold: %v", err)
	}
	if _, _, err := s.OpenLink(tok, h2, "", e.clk.Now()); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("after the hold, other browser: %v", err)
	}
}

func TestSetupNeedsPasswordAndSecondFactor(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	tok, _ := s.Invite(rootActor, "alice", "Alice", 72*time.Hour, e.clk.Now())
	_, h, _ := NewHold()
	if _, _, err := s.OpenLink(tok, h, "", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	pw, _ := hashPassword("correct horse battery staple")
	if _, err := s.CompleteSetup(Setup{Token: tok, Holder: h, Password: pw, Factor: "totp"}, e.clk.Now()); !errors.Is(err, ErrNeedsFactor) {
		t.Fatalf("no second factor: %v", err)
	}
	if got := s.Snapshot().Accounts["alice"]; got.State != StateInvited || got.Password != "" {
		t.Fatalf("a refused setup changed the account: %+v", got)
	}
}

func TestResetScopesDeleteWhatTheyNameAndRenewSessions(t *testing.T) {
	for _, scope := range []string{ScopePassword, ScopeSecondFactor, ScopeAll} {
		t.Run(scope, func(t *testing.T) {
			e := newEnv(t)
			s := e.mustOpen()
			e.setupActive(s, "alice")
			before := s.Snapshot().Accounts["alice"]
			tok, err := s.Reset(rootActor, "alice", ResetOptions{Scope: scope, TTL: 24 * time.Hour}, e.clk.Now())
			if err != nil {
				t.Fatal(err)
			}
			a := s.Snapshot().Accounts["alice"]
			if a.State != StateResetPending || a.Pending == nil || a.Pending.Scope != scope || a.SID == before.SID || bytes.Equal(a.SessionSecret, before.SessionSecret) {
				t.Fatalf("%+v", a)
			}
			if s.LocalActive("alice") {
				t.Fatal("a reset account must have no live session")
			}
			wantPW, wantFactor := scope == ScopeSecondFactor, scope == ScopePassword
			if (a.Password != "") != wantPW || (a.TOTP != nil) != wantFactor {
				t.Fatalf("scope %s kept password=%v factor=%v", scope, a.Password != "", a.TOTP != nil)
			}
			if tok == "" || len(a.Notices) == 0 {
				t.Fatal("no link or no notice")
			}
		})
	}
}

func TestResetOnAnInvitedAccountIsANewInvite(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	old, _ := s.Invite(rootActor, "alice", "Alice", time.Hour, e.clk.Now())
	nu, err := s.Reset(rootActor, "alice", ResetOptions{Scope: ScopeAll, TTL: 24 * time.Hour}, e.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a := s.Snapshot().Accounts["alice"]; a.State != StateInvited || a.Pending.Kind != LinkInvite {
		t.Fatalf("%+v", a)
	}
	if _, _, err := s.OpenLink(old, "h", "", e.clk.Now()); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("the old invite still opens: %v", err)
	}
	if _, _, err := s.OpenLink(nu, "h", "", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestDisableEnableRemoveAndEndSessions(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.setupActive(s, "alice")
	sid0 := s.Snapshot().Accounts["alice"].SID
	if err := s.EndSessions(CLI("op"), "alice", "cli", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	sid1 := s.Snapshot().Accounts["alice"].SID
	if sid1 == sid0 {
		t.Fatal("end-sessions must renew the session id")
	}
	if err := s.Disable(CLI("op"), "alice", nil, Revocations{}, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	a := s.Snapshot().Accounts["alice"]
	if a.State != StateDisabled || a.SID == sid1 || s.LocalActive("alice") {
		t.Fatalf("disable must end sessions and renew sid and secret: %+v", a)
	}
	if err := s.Disable(CLI("op"), "alice", nil, Revocations{}, e.clk.Now()); !errors.Is(err, ErrBadState) {
		t.Fatalf("disable twice: %v", err)
	}
	sid2 := a.SID
	if err := s.Enable(CLI("op"), "alice", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if a = s.Snapshot().Accounts["alice"]; a.State != StateActive || a.SID == sid2 {
		t.Fatalf("enable must bring back an active account under new session credentials: %+v", a)
	}
	if err := s.Remove(CLI("op"), "alice", nil, Revocations{}, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	a = s.Snapshot().Accounts["alice"]
	if a.State != StateRemoved || a.Password != "" || a.TOTP != nil || len(a.Passkeys) != 0 || !s.UsernameUsed("alice") {
		t.Fatalf("%+v", a)
	}
	if _, err := s.Invite(rootActor, "alice", "Again", time.Hour*72, e.clk.Now()); !errors.Is(err, ErrUsernameUsed) {
		t.Fatalf("a removed name came back: %v", err)
	}
}

func TestEnableIsRefusedWhileRevocationsArePending(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.setupActive(s, "alice")
	if err := s.Disable(CLI("op"), "alice", nil, Revocations{}, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Change(CLI("op").ev("account_unlocked", "alice", ""), func(st *State) error {
		st.Accounts["alice"].PendingRevocations = Revocations{Tokens: []string{"ci"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(CLI("op"), "alice", e.clk.Now()); !errors.Is(err, ErrRevocations) {
		t.Fatalf("enable with revocations pending: %v", err)
	}
}

func TestUnlockClearsLocksAndRestrictions(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.setupActive(s, "alice")
	if err := s.Counter(nil, func(st *State) error {
		a := st.Accounts["alice"]
		a.ConsecutiveFailures, a.State = 99, StatePasskeyOnly
		a.Locks = []Lock{{Scope: "account", Until: e.clk.Now().Add(time.Hour)}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock(rootActor, "alice", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if a := s.Snapshot().Accounts["alice"]; a.State != StateActive || a.ConsecutiveFailures != 0 || len(a.Locks) != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestRecoverCreatesOrFullyResets(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	tok, created, err := s.Recover(CLI("op"), "carol", "Carol", 72*time.Hour, 24*time.Hour, Revocations{}, e.clk.Now())
	if err != nil || !created || tok == "" {
		t.Fatalf("%v %v", created, err)
	}
	e.finish(s, tok)
	_, created, err = s.Recover(CLI("op"), "carol", "", 72*time.Hour, 24*time.Hour, Revocations{}, e.clk.Now())
	if err != nil || created {
		t.Fatalf("%v %v", created, err)
	}
	if a := s.Snapshot().Accounts["carol"]; a.State != StateResetPending || a.Pending.Scope != ScopeAll || a.Password != "" || a.TOTP != nil {
		t.Fatalf("%+v", a)
	}
}

func TestChangesCarryTheirEventsAndNeverATokenOrHash(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	tok, _ := s.Invite(rootActor, "alice", "Alice", 72*time.Hour, e.clk.Now())
	e.finish(s, tok)
	rt, _ := s.Reset(CLI("op"), "alice", ResetOptions{Scope: ScopeAll, TTL: time.Hour * 24}, e.clk.Now())
	var all bytes.Buffer
	for _, ev := range e.events() {
		b, _ := json.Marshal(ev)
		all.Write(b)
	}
	for _, secret := range []string{tok, rt, "correct horse battery staple", "$argon2id"} {
		if strings.Contains(all.String(), secret) {
			t.Fatalf("the audit log holds %q", secret[:min(len(secret), 8)])
		}
	}
	for _, name := range []string{"account_invited", "account_link_opened", "account_setup_completed", "account_reset_issued"} {
		if len(e.eventsNamed(name)) == 0 {
			t.Errorf("no %s event", name)
		}
	}
	if ev := e.eventsNamed("account_reset_issued")[0]; ev.Method != "cli" || ev.Target != "local:alice" || ev.Code != ScopeAll || !hasChange(ev) || !contains(ev.Detail, "operator:op") {
		t.Fatalf("%+v", ev)
	}
	e.verifyChain()
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// A re-authentication proves the password and the second factor again, so it may reset reauth_failures (5.7), and nothing
// else that a failure raised.
func TestReauthEventMayResetOnlyReauthFailures(t *testing.T) {
	e := newEnv(t)
	s := e.mustOpen()
	e.setupActive(s, "alice")
	raise := func(st *State) error {
		a := st.Accounts["alice"]
		a.ReauthFailures, a.ConsecutiveFailures = 2, 3
		return nil
	}
	if err := s.Counter(nil, raise); err != nil {
		t.Fatal(err)
	}
	reset := func(st *State) error { st.Accounts["alice"].ReauthFailures = 0; return nil }
	if err := s.Counter(nil, reset); !errors.Is(err, ErrNotCounterOnly) {
		t.Fatalf("without an event: %v", err)
	}
	other := audit.Event{Event: "reauth", Identity: "local:bob"}
	if err := s.Counter(&other, reset); !errors.Is(err, ErrNotCounterOnly) {
		t.Fatalf("a re-authentication of another account: %v", err)
	}
	both := func(st *State) error {
		a := st.Accounts["alice"]
		a.ReauthFailures, a.ConsecutiveFailures = 0, 0
		return nil
	}
	ev := audit.Event{Event: "reauth", Identity: "local:alice"}
	if err := s.Counter(&ev, both); !errors.Is(err, ErrNotCounterOnly) {
		t.Fatalf("a re-authentication must not clear consecutive_failures: %v", err)
	}
	ev = audit.Event{Event: "reauth", Identity: "local:alice"}
	if err := s.Counter(&ev, reset); err != nil {
		t.Fatalf("%v", err)
	}
	if a := s.Snapshot().Accounts["alice"]; a.ReauthFailures != 0 || a.ConsecutiveFailures != 3 {
		t.Fatalf("%+v", a)
	}
}
