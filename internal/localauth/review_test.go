package localauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/login"
)

// parallel runs n requests at once and returns their answers in order.
func parallel(n int, f func(i int) resp) []resp {
	out := make([]resp, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = f(i)
		}()
	}
	close(start)
	wg.Wait()
	return out
}

func count(rs []resp, status int) int {
	n := 0
	for _, r := range rs {
		if r.Status == status {
			n++
		}
	}
	return n
}

// ---- finding 1: reserve before work

// Sixty guesses at once, each from another network, must not get past the cap: the checks and the counts are one step, so the
// account stops being tried at cap-1 and never reaches passkey_only from networks it does not know.
func TestParallelWrongPasswordsNeverPassTheCap(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	rs := parallel(60, func(i int) resp {
		return e.login1(e.browser(fmt.Sprintf("192.0.%d.%d", i/200+2, i%200+1)), alice, "wrong wrong wrong", "")
	})
	if count(rs, 401) != 60 {
		t.Fatalf("every attempt gets the one answer: %d of 401", count(rs, 401))
	}
	got := e.account("alice")
	if got.ConsecutiveFailures != 9 || got.State != accounts.StateRestricted {
		t.Fatalf("after 60 parallel guesses from unknown networks: %d failures, %s (the design allows restricted at cap-1 and nothing beyond)", got.ConsecutiveFailures, got.State)
	}
	if n := len(e.events("account_restricted")); n != 1 {
		t.Fatalf("%d account_restricted events", n)
	}
}

// The same from the account's known network: the cap-th failure is the last that can be made, and only from there.
func TestParallelGuessesFromAKnownNetworkEndAtPasskeyOnly(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	e.login1(e.browser(addrA), alice, goodPassword, e.code(alice))
	rs := parallel(40, func(i int) resp { return e.login1(e.browser(addrA), alice, "wrong wrong wrong", "") })
	_ = rs
	got := e.account("alice")
	if got.ConsecutiveFailures != 10 || got.State != accounts.StatePasskeyOnly {
		t.Fatalf("%d failures, %s", got.ConsecutiveFailures, got.State)
	}
}

// Sixty parallel code guesses behind the right password: no more than the limit of a day are ever checked.
func TestParallelCodeGuessesNeverPassTheDailyLimit(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  twofa_limits: {totp_per_day: 3}\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	rs := parallel(60, func(i int) resp {
		return e.login1(e.browser(fmt.Sprintf("192.0.%d.%d", i/200+2, i%200+1)), alice, goodPassword, fmt.Sprintf("%06d", 100000+i))
	})
	if count(rs, 401) != 60 {
		t.Fatalf("%d", count(rs, 401))
	}
	if got := e.account("alice"); got.TOTPFailures != 3 {
		t.Fatalf("the stored count is %d, the limit is 3", got.TOTPFailures)
	}
	// and with the limit spent the right code is refused too
	if r := e.login1(e.browser(addrB), alice, goodPassword, e.code(alice)); r.Status != 401 {
		t.Fatalf("%d", r.Status)
	}
}

// The throttle counts an attempt before it does any work: with a limit of 5 from one network, exactly 5 of 60 parallel attempts
// are tried and the rest are refused.
func TestThrottleHoldsUnderParallelism(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 5, window: 10m}\n"})
	alice := e.addAccount("alice")
	before := e.svc.sample.seq()
	rs := parallel(60, func(i int) resp { return e.login1(e.browser(addrA), alice, "wrong wrong wrong", "") })
	if count(rs, 401) != 5 || count(rs, 429) != 55 {
		t.Fatalf("%d tried and %d refused", count(rs, 401), count(rs, 429))
	}
	if n := e.svc.sample.seq() - before; n != 5 {
		t.Fatalf("%d hashes", n)
	}
	// a success under the limit gives its place back: five right sign-ins never use it up
	e2 := newEnv(t, envOpts{auth: "  throttle: {max: 2, window: 10m}\n"})
	b2 := e2.addAccount("bob")
	for i := 0; i < 4; i++ {
		if r := e2.login1(e2.browser(addrA), b2, goodPassword, e2.code(b2)); r.Status != 200 {
			t.Fatalf("sign-in %d: %d", i, r.Status)
		}
	}
}

// An account lock set by the attempt that reached the limit holds for the attempts that follow at once.
func TestParallelAttemptsAreStoppedByTheAccountLock(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 4, window: 10m}\n  lock: {enabled: true, duration: 30m, scope: account}\n"})
	alice := e.addAccount("alice")
	rs := parallel(40, func(i int) resp {
		return e.login1(e.browser(fmt.Sprintf("192.0.%d.%d", i/200+2, i%200+1)), alice, "wrong wrong wrong", "")
	})
	if count(rs, 401) != 4 || count(rs, 429) != 36 {
		t.Fatalf("%d tried and %d refused", count(rs, 401), count(rs, 429))
	}
	if l := e.account("alice").Locks; len(l) != 1 || l[0].Scope != "account" {
		t.Fatalf("%+v", l)
	}
}

// The state is decided again inside the write of a success: an account that became passkey-only while a right password
// was being checked does not sign in.
func TestAnAccountThatBecameRestrictedIsNotSignedInByAnOlderCheck(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	if err := e.store.Counter(nil, func(st *accounts.State) error {
		a := st.Accounts["alice"]
		a.ConsecutiveFailures, a.State = 10, accounts.StatePasskeyOnly
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	set := e.svc.settings()
	a := e.account("alice")
	if e.svc.mayCommit(a, false, addrA, set, e.clk.Now(), "totp") {
		t.Fatal("a password and a code must not sign in a passkey-only account")
	}
	if !e.svc.mayCommit(a, true, addrA, set, e.clk.Now(), "passkey") {
		t.Fatal("the passkey path stays open")
	}
	_ = alice
}

// ---- finding 4

func TestRestrictedAdminStillCountsForTheSSOOnlyGuard(t *testing.T) {
	e := newEnv(t, envOpts{sso: true, auth: "  nist_cap: 10\n  login: {sso_only: true}\n  throttle: {max: 1000}\n"})
	alice, bob := e.addAccount("alice"), e.addAccount("bob")
	for i := 1; i <= 9; i++ { // cap-1 failures on the only local admin, from unknown networks
		e.login1(e.browser(fmt.Sprintf("192.0.2.%d", i)), alice, "wrong wrong wrong", "")
	}
	if got := e.account("alice"); got.State != accounts.StateRestricted {
		t.Fatalf("%+v", got)
	}
	if !e.svc.LocalAdminExists() {
		t.Fatal("a restricted administrator is still a local administrator")
	}
	// sso_only is still in force: a non-admin with the right credentials is told to use the organisation's sign-in
	if r := e.login1(e.browser(addrA), bob, goodPassword, e.code(bob)); r.Status != 403 || r.code() != "sso_required" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if n := len(e.events("settings_problem")); n != 0 {
		t.Fatalf("%d settings_problem events: sso_only was switched off", n)
	}
	// and a passkey_only administrator counts too
	if err := e.store.Counter(nil, func(st *accounts.State) error { st.Accounts["alice"].State = accounts.StatePasskeyOnly; return nil }); err != nil {
		t.Fatal(err)
	}
	if !e.svc.LocalAdminExists() {
		t.Fatal("a passkey-only administrator is still a local administrator")
	}
	// the guard that keeps the last local administrator counts them as well
	env := e.svc.AdminEnv()
	if r := env.Do(AdminRequest{Cmd: "disable", Username: "alice", Operator: "t"}); r.OK || r.Code != "last_local_admin" {
		t.Fatalf("%+v", r)
	}
}

// ---- finding 5

func TestPasswordResetIsProvableWithAPasskey(t *testing.T) {
	e := newEnv(t, envOpts{})
	d := newDevice()
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	pk := d.attest(t, b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "passkey": pk}); f.Status != 200 {
		t.Fatalf("%d %s", f.Status, f.Body)
	}
	d.auth.AddCredential(d.cred)
	rt, err := e.store.Reset(accounts.CLI("t"), "dana", accounts.ResetOptions{Scope: accounts.ScopePassword, TTL: 24 * time.Hour}, e.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	b2 := e.browser(addrB)
	if o := e.open(b2, rt); o.Status != 200 || o.json()["proveFactor"] != true {
		t.Fatalf("%d %s", o.Status, o.Body)
	}
	// a wrong passkey of someone else does not pass; the person's own does
	other := newDevice()
	attempt, assertion := other.assert(t, b2)
	if r := b2.post("/auth/local/setup/finish", map[string]any{"token": rt, "password": goodPassword, "proof": map[string]any{"attempt": attempt, "passkey": assertion}}); r.Status != 401 {
		t.Fatalf("a passkey that is not hers: %d", r.Status)
	}
	attempt, assertion = d.assert(t, b2)
	r := b2.post("/auth/local/setup/finish", map[string]any{"token": rt, "password": goodPassword, "proof": map[string]any{"attempt": attempt, "passkey": assertion}})
	if r.Status != 200 || r.json()["signedIn"] != true {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if a := e.account("dana"); a.State != accounts.StateActive || len(a.Passkeys) != 1 {
		t.Fatalf("%+v", a)
	}
	if ev := e.events("account_setup_completed"); ev[len(ev)-1].Detail[0] != "factor:passkey" {
		t.Fatalf("%+v", ev)
	}
	// the exception is for the reset proof only: a passkey of a reset_pending account does not sign in
	rt2, _ := e.store.Reset(accounts.CLI("t"), "dana", accounts.ResetOptions{Scope: accounts.ScopePassword, TTL: time.Hour * 24}, e.clk.Now())
	_ = rt2
	attempt, assertion = d.assert(t, e.browser(addrB))
	if r := e.browser(addrB).post("/auth/local/login", map[string]any{"username": "dana", "password": goodPassword, "attempt": attempt, "passkey": assertion}); r.Status == 200 {
		t.Fatal("a reset_pending account signed in")
	}
}

// ---- finding 6

func TestParallelProofsOnAResetLinkCountAgainstTheAccountLimit(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  twofa_limits: {totp_per_day: 3}\n  throttle: {max: 1000}\n"})
	bob := e.addAccount("bob")
	tok, _ := e.store.Reset(accounts.CLI("t"), "bob", accounts.ResetOptions{Scope: accounts.ScopePassword, TTL: 24 * time.Hour}, e.clk.Now())
	b := e.browser(addrA)
	e.open(b, tok)
	// the browser holds the link; sixty guesses at once from it
	rs := parallel(60, func(i int) resp {
		bb := e.browser(addrA)
		bb.cookies = map[string]string{HoldCookie: b.cookies[HoldCookie]}
		return bb.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": map[string]any{"code": fmt.Sprintf("%06d", 100000+i)}})
	})
	if count(rs, 200) != 0 {
		t.Fatal("a guess passed")
	}
	if got := e.account("bob"); got.TOTPFailures != 3 {
		t.Fatalf("the account's own counter is %d, the limit is 3", got.TOTPFailures)
	}
	// the right code is refused as well once the account's limit is spent, link or not
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": map[string]any{"code": e.code(bob)}}); r.Status == 200 {
		t.Fatal("the account's limit did not hold")
	}
	// the per-link cap is an extra cap: another link of an account with room is still ended by ten wrong proofs
	e2 := newEnv(t, envOpts{auth: "  twofa_limits: {totp_per_day: 20}\n  throttle: {max: 1000}\n"})
	e2.addAccount("bob")
	tok2, _ := e2.store.Reset(accounts.CLI("t"), "bob", accounts.ResetOptions{Scope: accounts.ScopePassword, TTL: 24 * time.Hour}, e2.clk.Now())
	b2 := e2.browser(addrA)
	e2.open(b2, tok2)
	for i := 0; i < maxSetupFails+2; i++ {
		b2.post("/auth/local/setup/finish", map[string]any{"token": tok2, "password": newPassword, "proof": map[string]any{"code": "000000"}})
	}
	if r := b2.post("/auth/local/setup/finish", map[string]any{"token": tok2, "password": newPassword, "proof": map[string]any{"code": "000000"}}); r.Status != 404 {
		t.Fatalf("%d", r.Status)
	}
}

// ---- finding 7

func TestAFailedCounterWriteLatchesEveryAttemptUntilAWriteWorks(t *testing.T) {
	logs := &syncBuf{}
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n", mutate: func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(logs, nil)) }})
	alice := e.addAccount("alice")
	dir := e.dir + "/accounts"
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	// a wrong password: its answer is the usual one, and the counter write after it fails
	if r := e.login1(e.browser(addrA), alice, "wrong wrong wrong", ""); r.Status != 401 {
		t.Fatalf("%d", r.Status)
	}
	if !e.svc.degraded.Load() {
		t.Fatal("a failed counter write must latch the service")
	}
	// now right and wrong credentials alike get the same 503, and the right ones get no session
	b := e.browser(addrB)
	right := e.login1(b, alice, goodPassword, e.code(alice))
	wrong := e.login1(e.browser(addrB), alice, "wrong wrong wrong", "")
	ghost := e.login1(e.browser(addrB), &person{name: "ghost"}, "wrong wrong wrong", "")
	if right.Status != 503 || right.Body != wrong.Body || right.Body != ghost.Body || wrong.Status != 503 || b.cookies[login.SessionCookie] != "" {
		t.Fatalf("right: %d %s\nwrong: %d %s\nghost: %d %s", right.Status, right.Body, wrong.Status, wrong.Body, ghost.Status, ghost.Body)
	}
	if ev := e.events("sign_in_degraded"); len(ev) != 1 || ev[0].Code != "start" {
		t.Fatalf("%+v", ev)
	}
	// the store works again, but the next probe is a backoff away
	os.Chmod(dir, 0o700)
	if r := e.login1(e.browser(addrB), alice, "wrong wrong wrong", ""); r.Status != 503 {
		t.Fatalf("inside the backoff: %d", r.Status)
	}
	e.clk.Advance(probeBackoff + time.Second)
	if r := e.login1(e.browser(addrB), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("after the backoff: %d %s", r.Status, r.Body)
	}
	if ev := e.events("sign_in_degraded"); len(ev) != 2 || ev[1].Code != "end" {
		t.Fatalf("%+v", ev)
	}
}

// ---- low findings

func TestRepeatedOpenDoesNotExtendTheHold(t *testing.T) {
	e := newEnv(t, envOpts{})
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	first := e.account("dana").Pending.HeldUntil
	e.clk.Advance(20 * time.Minute)
	if r := e.open(b, tok); r.Status != 200 {
		t.Fatalf("%d", r.Status)
	}
	if got := e.account("dana").Pending.HeldUntil; !got.Equal(first) {
		t.Fatalf("the hold moved from %s to %s", first, got)
	}
	e.clk.Advance(11 * time.Minute) // past the first 30 minutes
	if r := e.open(b, tok); r.Status != 410 {
		t.Fatalf("%d", r.Status)
	}
}

func TestFloodIsCheckedBeforeTheBodyOfSetupAndReauth(t *testing.T) {
	e := newEnv(t, envOpts{})
	b := e.browser(addrA)
	for i := 0; i < floodPerMinute; i++ {
		e.svc.tables.Flood(testBucket(addrA))
	}
	for _, p := range []string{"/auth/local/setup/open", "/auth/local/setup/totp", "/auth/local/setup/passkey", "/auth/local/setup/finish", "/auth/local/reauth", "/auth/local/login"} {
		if r := b.post(p, "{not json at all"); r.Status != 429 {
			t.Errorf("%s: %d: the ceiling must answer before the body is read", p, r.Status)
		}
	}
}

func testBucket(addr string) string { return addr }

func TestReauthFailuresAreClearedWhenSessionsEndAndOnFullSignIn(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	e.login1(b, alice, goodPassword, e.code(alice))
	for i := 0; i < 3; i++ {
		b.post("/auth/local/reauth", map[string]string{"password": "wrong wrong wrong"})
	}
	if a := e.account("alice"); a.ReauthFailures != 0 {
		t.Fatalf("the sessions ended and the count starts again: %d", a.ReauthFailures)
	}
	// two more failures, then a full sign-in clears them
	b2 := e.browser(addrB)
	e.login1(b2, alice, goodPassword, e.code(alice))
	b2.post("/auth/local/reauth", map[string]string{"password": "wrong wrong wrong"})
	b2.post("/auth/local/reauth", map[string]string{"password": "wrong wrong wrong"})
	if a := e.account("alice"); a.ReauthFailures != 2 {
		t.Fatalf("%d", a.ReauthFailures)
	}
	e.clk.Advance(time.Second)
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatal(r.Status)
	}
	if a := e.account("alice"); a.ReauthFailures != 0 {
		t.Fatalf("a full sign-in clears reauth_failures: %d", a.ReauthFailures)
	}
}

func TestProbeTOTPTakesTheWriterAndWritesNothing(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	before := e.account("alice")
	e.store.ProbeTOTP("alice", e.code(alice), e.clk.Now())
	e.store.ProbeTOTP("nobody", "123456", e.clk.Now())
	after := e.account("alice")
	if after.TOTP.LastStep != before.TOTP.LastStep {
		t.Fatal("a probe must not use up a code")
	}
}

// ---- the TOTP seed is never logged

func TestTheTOTPSeedIsNeverLoggedOrAudited(t *testing.T) {
	logs := &syncBuf{}
	e := newEnv(t, envOpts{mutate: func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}})
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	r := b.post("/auth/local/setup/totp", map[string]string{"token": tok})
	j := r.json()
	secret, uri := j["secret"].(string), j["uri"].(string)
	sec, _ := decodeBase32(secret)
	totp := map[string]any{"enrol": j["enrol"], "code": accounts.TOTPCode(sec, accounts.TOTPStep(e.clk.Now()))}
	b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp})
	e.login1(e.browser(addrB), &person{name: "dana"}, newPassword, "000000")
	var all strings.Builder
	all.WriteString(logs.String())
	for _, ev := range e.events("") {
		ev.Prev = "" // a hash chain is random hex: a six-digit code can sit in it by chance
		raw, _ := json.Marshal(ev)
		all.Write(raw)
	}
	e.svc.refused.Flush(e.clk.Now(), true)
	for _, ev := range e.events("") {
		ev.Prev = "" // a hash chain is random hex: a six-digit code can sit in it by chance
		raw, _ := json.Marshal(ev)
		all.Write(raw)
	}
	hex := fmt.Sprintf("%x", sec)
	for _, s := range []string{secret, uri, strings.ToLower(secret), hex, j["enrol"].(string), newPassword, tok} {
		if strings.Contains(all.String(), s) {
			t.Fatalf("%q is in a log or an audit event", s[:min(len(s), 8)])
		}
	}
}

// ---- revocation (5.11)

func (e *env) revokedNow(kind, id string) bool { return e.store.IsRevoked(kind, id) }

func TestResetRevokesWhatTheAccountOwnsAndTheOldCredentialsAreRefusedAfterSetup(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.addAccount("bob")
	e.rev.own("bob", []string{"ci-token"}, []string{"grant-1"})
	env := e.svc.AdminEnv()
	r := env.Do(AdminRequest{Cmd: "reset", Username: "bob", Scope: "all", Operator: "ops"})
	if !r.OK || len(r.Links) != 1 {
		t.Fatalf("%+v", r)
	}
	// the local list is written in the same audited change that clears the pending entries: refused from this moment
	if !e.revokedNow(accounts.KindToken, "id-ci-token") || !e.revokedNow(accounts.KindGrant, "grant-1") {
		t.Fatal("the token and the grant must be on the revocation list")
	}
	if a := e.account("bob"); !a.PendingRevocations.Empty() {
		t.Fatalf("applied revocations are cleared: %+v", a.PendingRevocations)
	}
	// the event lists what was revoked, by name and id, and nothing secret
	var issued, applied string
	for _, ev := range e.events("") {
		switch ev.Event {
		case "account_reset_issued":
			issued = strings.Join(ev.Detail, " ")
		case "account_revocations_applied":
			applied = strings.Join(ev.Detail, " ")
		}
	}
	if !strings.Contains(issued, "tokens:*,ci-token") || !strings.Contains(issued, "grants:*,grant-1") || !strings.Contains(applied, "ci-token") || !strings.Contains(applied, "grant-1") {
		t.Fatalf("issued %q applied %q", issued, applied)
	}
	// the record layer follows
	if err := e.svc.RecordRevoked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if did := strings.Join(e.rev.did(), " "); !strings.Contains(did, "token:ci-token") || !strings.Contains(did, "grant:grant-1") {
		t.Fatalf("%s", did)
	}
	// set up again: the setup goes through, and the old token and grant are still on the list
	tok := strings.TrimPrefix(r.Links[0].URL, testBase+"/auth/local/setup#")
	b := e.browser(addrA)
	e.open(b, tok)
	totp, _ := e.enrolTOTP(b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp}); f.Status != 200 {
		t.Fatalf("%d %s", f.Status, f.Body)
	}
	if !e.revokedNow(accounts.KindToken, "id-ci-token") || !e.revokedNow(accounts.KindGrant, "grant-1") {
		t.Fatal("the old token or grant came back with the account")
	}
	// a new token of the same name is another token, and is not on the list
	if e.revokedNow(accounts.KindToken, "id-another-secret") {
		t.Fatal("the list is by the token's own id, not by its name")
	}
}

func TestDisableRemoveAndRecoverRevokeToo(t *testing.T) {
	for _, cmd := range []string{"disable", "remove", "recover"} {
		t.Run(cmd, func(t *testing.T) {
			e := newEnv(t, envOpts{})
			e.addAccount("bob")
			e.rev.own("bob", []string{"t1", "t2"}, []string{"g1"})
			r := e.svc.AdminEnv().Do(AdminRequest{Cmd: cmd, Username: "bob", Operator: "ops"})
			if !r.OK {
				t.Fatalf("%+v", r)
			}
			for _, id := range []string{"id-t1", "id-t2"} {
				if !e.revokedNow(accounts.KindToken, id) {
					t.Fatalf("%s: %s is not refused", cmd, id)
				}
			}
			if !e.revokedNow(accounts.KindGrant, "g1") || !e.account("bob").PendingRevocations.Empty() {
				t.Fatalf("%s: the grant is not refused or the revocation is still pending", cmd)
			}
		})
	}
}

// What cannot be listed leaves the revocations pending and the account unable to come back; a retry finishes them.
func TestPendingRevocationsBlockEnableAndSetupUntilTheyAreApplied(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.addAccount("bob")
	e.rev.own("bob", []string{"ci"}, nil)
	failing := &failingRevoker{fakeRevoker: e.rev, fail: true}
	e.svc.SetRevoker(failing)
	r := e.svc.AdminEnv().Do(AdminRequest{Cmd: "reset", Username: "bob", Scope: "all", Operator: "ops"})
	if !r.OK || !strings.Contains(strings.Join(r.Lines, " "), "pending") {
		t.Fatalf("%+v", r)
	}
	if e.account("bob").PendingRevocations.Empty() {
		t.Fatal("a revocation that could not be resolved must stay pending")
	}
	tok := strings.TrimPrefix(r.Links[0].URL, testBase+"/auth/local/setup#")
	b := e.browser(addrA)
	e.open(b, tok)
	totp, _ := e.enrolTOTP(b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp}); f.Status != 409 || f.code() != "revocations_pending" {
		t.Fatalf("setup while revocations are pending: %d %s", f.Status, f.Body)
	}
	failing.fail = false
	if err := e.svc.ApplyAllRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.account("bob").PendingRevocations.Empty() || !e.revokedNow(accounts.KindToken, "id-ci") {
		t.Fatal("the retry did not finish")
	}
	totp, _ = e.enrolTOTP(b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp}); f.Status != 200 {
		t.Fatalf("after the retry: %d %s", f.Status, f.Body)
	}
}

// Git is the record, not the block: a pull request instead of a commit, or a refused push, leaves the token refused all the same,
// and neither setup, enable nor recover waits for it.
func TestRevocationDoesNotDependOnGit(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.addAccount("bob")
	e.rev.own("bob", []string{"ci"}, []string{"g"})
	e.rev.setGitFails(true)
	r := e.svc.AdminEnv().Do(AdminRequest{Cmd: "recover", Username: "bob", Operator: "ops"})
	if !r.OK || len(r.Links) != 1 {
		t.Fatalf("recover with git down: %+v", r)
	}
	if !e.revokedNow(accounts.KindToken, "id-ci") || !e.revokedNow(accounts.KindGrant, "g") || !e.account("bob").PendingRevocations.Empty() {
		t.Fatal("the local list must block the token and the grant whatever git says")
	}
	if err := e.svc.RecordRevoked(context.Background()); err == nil {
		t.Fatal("the record layer should have failed")
	}
	tok := strings.TrimPrefix(r.Links[0].URL, testBase+"/auth/local/setup#")
	b := e.browser(addrA)
	e.open(b, tok)
	totp, _ := e.enrolTOTP(b, tok)
	if f := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp}); f.Status != 200 {
		t.Fatalf("setup with git down: %d %s", f.Status, f.Body)
	}
	if r := e.svc.AdminEnv().Do(AdminRequest{Cmd: "disable", Username: "bob", Operator: "ops"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if r := e.svc.AdminEnv().Do(AdminRequest{Cmd: "enable", Username: "bob", Operator: "ops"}); !r.OK {
		t.Fatalf("enable with git down: %+v", r)
	}
	// git comes back: the record is retried and made
	e.rev.setGitFails(false)
	if err := e.svc.RecordRevoked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(e.rev.did(), " "), "token:ci") {
		t.Fatal("the retry did not record the token")
	}
}

type failingRevoker struct {
	*fakeRevoker
	fail bool
}

func (f *failingRevoker) Owned(user string) ([]string, []string, error) {
	if f.fail {
		return nil, nil, errors.New("tokens.yml cannot be read")
	}
	return f.fakeRevoker.Owned(user)
}

func TestOfflineRevocationsAreRecordedAndAppliedAtStart(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.addAccount("bob")
	e.rev.own("bob", []string{"ci"}, []string{"g"})
	e.svc.SetRevoker(nil) // the command line with the server stopped
	env := e.svc.AdminEnv()
	env.Revoker = nil
	if r := env.Do(AdminRequest{Cmd: "disable", Username: "bob", Operator: "ops"}); !r.OK || !strings.Contains(strings.Join(r.Lines, " "), "when it starts") {
		t.Fatalf("%+v", r)
	}
	if p := e.account("bob").PendingRevocations; len(p.Tokens) != 1 || p.Tokens[0] != accounts.AllOwned {
		t.Fatalf("%+v", p)
	}
	if r := env.Do(AdminRequest{Cmd: "enable", Username: "bob", Operator: "ops"}); r.OK {
		t.Fatal("an account with revocations pending was enabled")
	}
	// the server starts: before it serves, every pending revocation is carried out
	e.svc.SetRevoker(e.rev)
	if err := e.svc.ApplyAllRevocations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !e.revokedNow(accounts.KindToken, "id-ci") || !e.revokedNow(accounts.KindGrant, "g") {
		t.Fatal("not on the list")
	}
	if r := env.Do(AdminRequest{Cmd: "enable", Username: "bob", Operator: "ops"}); !r.OK {
		t.Fatalf("%+v", r)
	}
}

var _ = http.StatusOK

// ---- round 2

// Under sso_only every refusal waits for about the time an administrator's success spends writing before its answer, and writes
// nothing itself: the timing class is the same, and no refusal makes a store write or an audit line of its own.
func TestUnderSSOOnlyEveryRefusalWaitsForTheTimeOfASuccessWrite(t *testing.T) {
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n  throttle: {max: 1000}\n"})
	alice, bob := e.addAccount("alice"), e.addAccount("bob")
	est := 40 * time.Millisecond
	e.svc.estMu.Lock()
	e.svc.writeEst = est
	e.svc.estMu.Unlock()
	stateFile := e.dir + "/accounts/accounts.enc"
	type seen struct {
		lines int64
		wrote bool
		slept []time.Duration
	}
	probe := func(i int, do func(b *browser) resp) seen {
		e.resetSleeps()
		seq0, _ := e.log.Head()
		st0, _ := os.Stat(stateFile)
		b := e.browser(fmt.Sprintf("203.0.113.%d", 30+i))
		var s seen
		b.onAnswer = func() {
			seq1, _ := e.log.Head()
			st1, _ := os.Stat(stateFile)
			s.lines, s.wrote = seq1-seq0, !st1.ModTime().Equal(st0.ModTime()) || st1.Size() != st0.Size()
		}
		do(b)
		s.slept = e.slept()
		e.clk.Advance(time.Second)
		return s
	}
	refusals := map[string]func(b *browser) resp{
		"unknown name":          func(b *browser) resp { return e.login1(b, &person{name: "ghost"}, goodPassword, "123456") },
		"wrong password":        func(b *browser) resp { return e.login1(b, bob, "wrong wrong wrong", e.code(bob)) },
		"wrong code":            func(b *browser) resp { return e.login1(b, bob, goodPassword, "000000") },
		"non-admin, right":      func(b *browser) resp { return e.login1(b, bob, goodPassword, e.code(bob)) },
		"admin, wrong password": func(b *browser) resp { return e.login1(b, alice, "wrong wrong wrong", e.code(alice)) },
	}
	i := 0
	for name, do := range refusals {
		i++
		got := probe(i, do)
		if len(got.slept) != 1 || got.slept[0] < est*3/4 || got.slept[0] > est*5/4 {
			t.Errorf("%s: slept %v, want one wait around %v", name, got.slept, est)
		}
		if got.lines != 0 || got.wrote {
			t.Errorf("%s: a refusal wrote %d audit lines and the store (%v) before its answer", name, got.lines, got.wrote)
		}
	}
	// an administrator's success is the write itself, and waits for nothing
	got := probe(99, func(b *browser) resp { return e.login1(b, alice, goodPassword, e.code(alice)) })
	if got.lines != 1 || !got.wrote || len(got.slept) != 0 {
		t.Errorf("an administrator's success: %+v", got)
	}
	// the estimate follows the real writes
	e.svc.noteWrite(5 * time.Second)
	if e.svc.writeEstimate() <= est {
		t.Error("the estimate must follow what a success's write really takes")
	}
}

// A burst of refusals from many networks does not grow the store or the audit log per attempt: the audit log gets the aggregated
// events (the first of each account per network and minute, a summary after, at most 100 networks a minute), and the store is rewritten
// at its own size.
func TestABurstOfRefusalsDoesNotGrowTheStoreOrTheAuditLogPerAttempt(t *testing.T) {
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n  throttle: {max: 1000}\n"})
	e.addAccount("alice")
	bob := e.addAccount("bob")
	stateFile := e.dir + "/accounts/accounts.enc"
	size0 := func() int64 { st, _ := os.Stat(stateFile); return st.Size() }()
	seq0, _ := e.log.Head()
	const attempts = 400
	parallel(attempts, func(i int) resp {
		return e.login1(e.browser(fmt.Sprintf("198.51.%d.%d", i/200+1, i%200+1)), bob, "wrong wrong wrong", "")
	})
	e.clk.Advance(2 * time.Minute)
	e.svc.refused.Flush(e.clk.Now(), false)
	seq1, _ := e.log.Head()
	if lines := seq1 - seq0; lines > 2*maxAggBuckets+2 {
		t.Fatalf("%d audit lines for %d refusals", lines, attempts)
	}
	if size := func() int64 { st, _ := os.Stat(stateFile); return st.Size() }(); size > size0+size0/4 {
		t.Fatalf("the store grew from %d to %d bytes", size0, size)
	}
	// one network, many attempts: the first in full, the rest in one summary
	seq0, _ = e.log.Head()
	for i := 0; i < 150; i++ {
		e.login1(e.browser("203.0.113.9"), bob, "wrong wrong wrong", "")
	}
	e.clk.Advance(2 * time.Minute)
	e.svc.refused.Flush(e.clk.Now(), false)
	seq1, _ = e.log.Head()
	if seq1-seq0 > 3 {
		t.Fatalf("%d audit lines for 150 refusals from one network", seq1-seq0)
	}
}

// Past the bound on the refusals that wait at once, the answer is the 503 busy of the hashing slots.
func TestSSOOnlyWaitersAreBoundedAndPastTheBoundTheAnswerIsBusy(t *testing.T) {
	gate := make(chan struct{})
	var started sync.WaitGroup
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n  throttle: {max: 1000}\n", mutate: func(o *Options) {
		o.Sleep = func(time.Duration) { started.Done(); <-gate }
	}})
	e.addAccount("alice")
	e.svc.sleepers = make(chan struct{}, 2)
	started.Add(2)
	var rs []resp
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.login1(e.browser(fmt.Sprintf("203.0.113.%d", 50+i)), &person{name: "ghost"}, "x", "")
			mu.Lock()
			rs = append(rs, r)
			mu.Unlock()
		}()
	}
	started.Wait() // both waiters are sleeping
	over := e.login1(e.browser("203.0.113.99"), &person{name: "ghost"}, "x", "")
	if over.Status != 503 || over.code() != "busy" {
		t.Fatalf("past the bound: %d %s", over.Status, over.Body)
	}
	close(gate)
	wg.Wait()
	for _, r := range rs {
		if r.Status != 403 || r.code() != "sso_required" {
			t.Fatalf("a waiter: %d %s", r.Status, r.Body)
		}
	}
}

// The current password that proves a second-factor reset is reserved against the account's persistent counter before it is checked.
func TestParallelCurrentPasswordProofsAreBoundByTheAccountCounter(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	e.addAccount("bob")
	tok, _ := e.store.Reset(accounts.CLI("t"), "bob", accounts.ResetOptions{Scope: accounts.ScopeSecondFactor, TTL: 24 * time.Hour}, e.clk.Now())
	b := e.browser(addrA)
	e.open(b, tok)
	before := e.svc.sample.seq()
	rs := parallel(60, func(i int) resp {
		bb := e.browser(addrA)
		bb.cookies = map[string]string{HoldCookie: b.cookies[HoldCookie]}
		return bb.post("/auth/local/setup/finish", map[string]any{"token": tok, "current_password": fmt.Sprintf("not the password %d", i)})
	})
	if count(rs, 200) != 0 {
		t.Fatal("a wrong password passed")
	}
	// the runs counted are the checks (at most 10) and the dummy hashes of the refusals the budget allows (2 for this network)
	if n := e.svc.sample.seq() - before; n > 10+dummyPerBucketMinute {
		t.Fatalf("%d hashes: more passwords were checked than the cap allows", n)
	}
	if got := e.account("bob"); got.ConsecutiveFailures != 10 || got.State != accounts.StateResetPending {
		t.Fatalf("%+v", got)
	}
	// with the cap spent the right password is refused too, link or not
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "current_password": goodPassword}); r.Status == 200 {
		t.Fatal("the account's counter did not hold")
	}
}

// A ticket gives back only into the window it was counted in.
func TestRefundDoesNothingOnceTheWindowHasRolledOver(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tb := newTables(func() time.Time { return now })
	lock := lockSetting{}
	old, _ := tb.Begin("b", "alice", 5, 10*time.Minute, lock, true)
	now = now.Add(11 * time.Minute) // the window ended
	fresh, _ := tb.Begin("b", "alice", 5, 10*time.Minute, lock, true)
	_ = fresh
	tb.Refund(old) // the old attempt's success must not forgive a failure of the new window
	if c := tb.Pre("b", "alice", 1, 10*time.Minute); !c.Throttled {
		t.Fatal("the failure of the new window was given back by a ticket of the old one")
	}
	// the same window: a success gives its place back
	tb2 := newTables(func() time.Time { return now })
	tk, _ := tb2.Begin("b", "alice", 1, 10*time.Minute, lock, true)
	tb2.Refund(tk)
	if c := tb2.Pre("b", "alice", 1, 10*time.Minute); c.Throttled {
		t.Fatal("a success must give its place back inside its window")
	}
}
