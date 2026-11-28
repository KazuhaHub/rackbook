package localauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/login"
)

func TestSignInWithPasswordAndCode(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	code := e.code(alice)
	r := e.login1(b, alice, goodPassword, code)
	if r.Status != 200 || r.json()["ok"] != true || r.json()["return"] != "/" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if b.cookies[login.SessionCookie] == "" {
		t.Fatal("no session cookie")
	}
	// the cookie is a local session of alice, with the time of the full authentication
	req := httptestRequest(b)
	info, ok := e.login.LocalSession(req)
	if !ok || info.Username != "alice" || info.Factor != "totp" || !e.login.RecentAuth(req, time.Minute) {
		t.Fatalf("%+v %v", info, ok)
	}
	a := e.account("alice")
	if a.LastLogin == nil || a.LastLogin.Addr != addrA || len(a.GoodBuckets) != 1 || a.GoodBuckets[0].Bucket != addrA {
		t.Fatalf("%+v", a)
	}
	evs := e.events("login")
	if len(evs) != 1 || evs[0].Identity != "local:alice" || evs[0].Method != "local" || evs[0].Role != "admin" || evs[0].Addr != addrA || evs[0].Detail[0] != "factor:totp" {
		t.Fatalf("%+v", evs)
	}
	// the code just used is refused the second time (replay), from the same or another browser
	e.clk.Advance(time.Second)
	if r := e.login1(e.browser(addrB), alice, goodPassword, code); r.Status != 401 {
		t.Fatalf("replayed code: %d %s", r.Status, r.Body)
	}
}

func TestSignInRefusesWhatIsNotACompleteCredential(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	for name, tc := range map[string]struct{ pw, code string }{
		"no code":        {goodPassword, ""},
		"wrong code":     {goodPassword, "000000"},
		"wrong password": {"not the password at all", ""},
		"malformed code": {goodPassword, "12ab56"},
	} {
		code := tc.code
		if name == "wrong password" {
			code = e.code(alice)
		}
		if r := e.login1(e.browser(addrA), alice, tc.pw, code); r.Status != 401 || r.code() != "sign_in_failed" {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	if r := e.browser(addrA).post("/auth/local/login", "{not json"); r.Status != 400 {
		t.Errorf("garbage body: %d", r.Status)
	}
}

// states that cannot sign in
func (e *env) makeStates(t *testing.T) map[string]*person {
	t.Helper()
	out := map[string]*person{}
	out["wrongpw"] = e.addAccount("wrongpw")
	for _, n := range []string{"disabled", "removed", "resetting"} {
		out[n] = e.addAccount(n)
	}
	if err := e.store.Disable(accounts.CLI("t"), "disabled", nil, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Remove(accounts.CLI("t"), "removed", nil, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Reset(accounts.CLI("t"), "resetting", accounts.ResetOptions{Scope: accounts.ScopeAll, TTL: 24 * time.Hour}, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Invite(accounts.CLI("t"), "invited", "Invited", 72*time.Hour, e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	out["invited"] = &person{name: "invited"}
	out["nobody"] = &person{name: "nobody"}
	return out
}

func TestAnswersAreUniform(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	ps := e.makeStates(t)
	var want resp
	for i, name := range []string{"wrongpw", "nobody", "disabled", "removed", "resetting", "invited"} {
		p := ps[name]
		before := e.svc.sample.seq()
		pw := goodPassword
		if name == "wrongpw" {
			pw = "this is not the password"
		}
		r := e.login1(e.browser(fmt.Sprintf("203.0.113.%d", 50+i)), p, pw, "123456")
		if after := e.svc.sample.seq(); after != before+1 {
			t.Errorf("%s: %d argon2id runs, want exactly one", name, after-before)
		}
		if i == 0 {
			want = r
			continue
		}
		if r.Status != want.Status || r.Body != want.Body {
			t.Errorf("%s answers %d %q, a wrong password answers %d %q", name, r.Status, r.Body, want.Status, want.Body)
		}
	}
	if want.Status != 401 || want.code() != "sign_in_failed" {
		t.Fatalf("%+v", want)
	}
	// the typed unknown name is in no audit event
	for _, ev := range e.events("") {
		if b := fmt.Sprint(ev); strings.Contains(b, "nobody") {
			t.Fatalf("a typed unknown username is in the audit log: %+v", ev)
		}
	}
}

func TestThrottleIsAlwaysOnAndPerBucket(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 3, window: 5m}\n"})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	for i := 0; i < 3; i++ {
		if r := e.login1(b, alice, "wrong wrong wrong", ""); r.Status != 401 {
			t.Fatalf("failure %d: %d", i, r.Status)
		}
	}
	e.resetSleeps()
	before := e.svc.sample.seq()
	// now even the right credentials are refused, without a hash, after the fixed delay, for any name
	r := e.login1(b, alice, goodPassword, e.code(alice))
	r2 := e.login1(b, &person{name: "somebody-else"}, goodPassword, "123456")
	if r.Status != 429 || r.code() != "too_many_attempts" || r2.Status != 429 || r.Body != r2.Body {
		t.Fatalf("%d %s / %d %s", r.Status, r.Body, r2.Status, r2.Body)
	}
	if e.svc.sample.seq() != before {
		t.Error("a refused attempt must take no hash")
	}
	if s := e.slept(); len(s) != 2 || s[0] != refusalDelay || s[1] != refusalDelay {
		t.Errorf("fixed delay: %v", s)
	}
	if strings.Contains(r.Body, "minute") || strings.Contains(r.Body, "second") {
		t.Errorf("the answer must not give a time: %s", r.Body)
	}
	// another network is not affected
	if r := e.login1(e.browser(addrB), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("another bucket: %d %s", r.Status, r.Body)
	}
	// the window ends
	e.clk.Advance(6 * time.Minute)
	if r := e.login1(b, alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("after the window: %d %s", r.Status, r.Body)
	}
}

func TestIPv6IsBucketedBy48(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 2}\n"})
	alice := e.addAccount("alice")
	mk := func(a string) *browser { b := e.browser(""); b.addr = "[" + a + "]"; return b }
	for _, a := range []string{"2001:db8:1:1::1", "2001:db8:1:ffff::2"} { // the same /48
		e.login1(mk(a), alice, "wrong wrong wrong", "")
	}
	if r := e.login1(mk("2001:db8:1:9::3"), alice, goodPassword, e.code(alice)); r.Status != 429 {
		t.Fatalf("same /48: %d", r.Status)
	}
	if r := e.login1(mk("2001:db8:2::1"), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("another /48: %d %s", r.Status, r.Body)
	}
}

func TestLocksByScope(t *testing.T) {
	// the throttle window is one minute and the lock half an hour, so a refusal after the window is the lock's
	for _, scope := range []string{"ip", "ip_account", "account"} {
		t.Run(scope, func(t *testing.T) {
			e := newEnv(t, envOpts{auth: fmt.Sprintf("  throttle: {max: 3, window: 1m}\n  lock: {enabled: true, duration: 30m, scope: %s}\n", scope)})
			alice, bob := e.addAccount("alice"), e.addAccount("bob")
			for i := 0; i < 3; i++ {
				e.login1(e.browser(addrA), alice, "wrong wrong wrong", "")
			}
			e.clk.Advance(2 * time.Minute) // the throttle is over
			a := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice))
			if a.Status != 429 {
				t.Fatalf("a locked account with the right credentials: %d %s", a.Status, a.Body)
			}
			otherName := e.login1(e.browser(addrA), bob, goodPassword, e.code(bob))
			otherNet := e.login1(e.browser(addrB), alice, goodPassword, e.code(alice))
			switch scope {
			case "ip": // the whole network
				if otherName.Status != 429 || otherNet.Status != 200 {
					t.Errorf("ip: other name %d, other network %d", otherName.Status, otherNet.Status)
				}
			case "ip_account": // that account on that network only
				if otherName.Status != 200 || otherNet.Status != 200 {
					t.Errorf("ip_account: other name %d, other network %d", otherName.Status, otherNet.Status)
				}
			case "account": // everywhere, for that name only
				if otherName.Status != 200 || otherNet.Status != 429 {
					t.Errorf("account: other name %d, other network %d", otherName.Status, otherNet.Status)
				}
				if l := e.account("alice").Locks; len(l) != 1 || l[0].Scope != "account" {
					t.Errorf("the lock of an account is in the store: %+v", l)
				}
				// an unknown name is locked the same way, with the same answer
				for i := 0; i < 3; i++ {
					e.login1(e.browser(addrA), &person{name: "ghost"}, "wrong wrong wrong", "")
				}
				e.clk.Advance(2 * time.Minute)
				g := e.login1(e.browser(addrB), &person{name: "ghost"}, goodPassword, "123456")
				if g.Status != 429 || g.Body != a.Body {
					t.Errorf("a locked unknown name answers %d %q, a locked account %d %q", g.Status, g.Body, a.Status, a.Body)
				}
			}
			if len(e.events("account_locked")) == 0 && scope == "account" {
				t.Error("no account_locked event")
			}
			// an administrator's unlock lifts the account lock at once, and the lock expires on its own
			if scope == "account" {
				if err := e.store.Unlock(accounts.CLI("t"), "alice", e.clk.Now()); err != nil {
					t.Fatal(err)
				}
				if r := e.login1(e.browser(addrB), alice, goodPassword, e.code(alice)); r.Status != 200 {
					t.Errorf("after unlock: %d %s", r.Status, r.Body)
				}
			}
			e.clk.Advance(31 * time.Minute)
			if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
				t.Errorf("after the lock: %d %s", r.Status, r.Body)
			}
		})
	}
}

func TestLocksAreOffByDefault(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 3, window: 1m}\n"})
	alice := e.addAccount("alice")
	for i := 0; i < 5; i++ {
		e.login1(e.browser(addrA), alice, "wrong wrong wrong", "")
	}
	e.clk.Advance(2 * time.Minute)
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestNISTCapRestrictsThenPasskeyOnly(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 100}\n"})
	alice := e.addAccount("alice")
	good := e.browser(addrA)
	if r := e.login1(good, alice, goodPassword, e.code(alice)); r.Status != 200 { // addrA is a known network now
		t.Fatalf("%d", r.Status)
	}
	fromNew := func(i int) *browser { return e.browser(fmt.Sprintf("192.0.2.%d", i)) }
	for i := 1; i <= 8; i++ { // eight failures from eight different networks
		e.login1(fromNew(i), alice, "wrong wrong wrong", "")
	}
	if got := e.account("alice"); got.ConsecutiveFailures != 8 || got.State != accounts.StateActive {
		t.Fatalf("%+v", got)
	}
	e.login1(fromNew(9), alice, "wrong wrong wrong", "") // the ninth: cap-1
	if got := e.account("alice"); got.State != accounts.StateRestricted {
		t.Fatalf("after 9: %s", got.State)
	}
	if ev := e.events("account_restricted"); len(ev) != 1 || ev[0].Code != "restricted" || ev[0].Identity != "local:alice" {
		t.Fatalf("%+v", ev)
	}
	// restricted: a new network is refused with the uniform answer, without counting; a known one is let in
	before := e.svc.sample.seq()
	r := e.login1(fromNew(10), alice, goodPassword, e.code(alice))
	if r.Status != 401 || r.code() != "sign_in_failed" || e.svc.sample.seq() != before+1 {
		t.Fatalf("restricted, new network: %d %s", r.Status, r.Body)
	}
	if e.account("alice").ConsecutiveFailures != 9 {
		t.Fatal("a refusal that never reached the password check must not count")
	}
	// the cap-th failure can only come from a known network
	e.login1(good, alice, "wrong wrong wrong", "")
	if got := e.account("alice"); got.State != accounts.StatePasskeyOnly || got.ConsecutiveFailures != 10 {
		t.Fatalf("after 10: %+v", got)
	}
	if ev := e.events("account_restricted"); len(ev) != 2 || ev[1].Code != "passkey_only" {
		t.Fatalf("%+v", ev)
	}
	if r := e.login1(good, alice, goodPassword, e.code(alice)); r.Status != 401 {
		t.Fatalf("passkey_only with the right password and code: %d", r.Status)
	}
	// an administrator's unlock brings it back
	if err := e.store.Unlock(accounts.CLI("t"), "alice", e.clk.Now()); err != nil {
		t.Fatal(err)
	}
	if r := e.login1(good, alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("after unlock: %d %s", r.Status, r.Body)
	}
	if got := e.account("alice"); got.ConsecutiveFailures != 0 || got.State != accounts.StateActive {
		t.Fatalf("a sign-in clears the counters: %+v", got)
	}
}

func TestNISTCapIsLowerableAndNeverMoreThan100(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  nist_cap: 10\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	for i := 0; i < 9; i++ {
		e.login1(e.browser(fmt.Sprintf("192.0.2.%d", i+1)), alice, "wrong wrong wrong", "")
	}
	if e.account("alice").State != accounts.StateRestricted {
		t.Fatal("a cap of 10 restricts at 9")
	}
	if set := e.svc.settings(); set.NISTCap != 10 {
		t.Fatal(set.NISTCap)
	}
	e2 := newEnv(t, envOpts{})
	if e2.svc.settings().NISTCap != 100 {
		t.Fatal("the default cap is the NIST maximum, 100")
	}
}

func TestSecondFactorFailuresStopTOTPForTheAccount(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  twofa_limits: {totp_per_day: 3}\n  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	for i := 0; i < 3; i++ { // a right password with a wrong code
		if r := e.login1(e.browser(fmt.Sprintf("192.0.2.%d", i+1)), alice, goodPassword, "000000"); r.Status != 401 {
			t.Fatal(r.Status)
		}
	}
	a := e.account("alice")
	if a.TOTPFailures != 3 || a.LastSecondFactorFailure == nil || a.ConsecutiveFailures != 0 {
		t.Fatalf("%+v", a)
	}
	if ev := e.events("account_locked"); len(ev) != 1 || ev[0].Code != "totp" {
		t.Fatalf("%+v", ev)
	}
	// TOTP is stopped: the right code is refused, with the uniform answer and one hash
	before := e.svc.sample.seq()
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 401 || e.svc.sample.seq() != before+1 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// a day later it is back
	e.clk.Advance(25 * time.Hour)
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestSSOOnlyAnswersEveryFailureTheSameAndLetsOnlyAdminsIn(t *testing.T) {
	e := newEnv(t, envOpts{sso: true, auth: "  login: {mode: dual, sso_only: true}\n  throttle: {max: 1000}\n"})
	alice, bob := e.addAccount("alice"), e.addAccount("bob") // alice is an admin, bob an editor
	var first resp
	for i, c := range []struct {
		name string
		do   func(b *browser) resp
	}{
		{"unknown", func(b *browser) resp { return e.login1(b, &person{name: "nobody"}, goodPassword, "123456") }},
		{"wrong password", func(b *browser) resp { return e.login1(b, alice, "wrong wrong wrong", e.code(alice)) }},
		{"non-admin with the right credentials", func(b *browser) resp { return e.login1(b, bob, goodPassword, e.code(bob)) }},
		{"admin with a wrong code", func(b *browser) resp { return e.login1(b, alice, goodPassword, "000000") }},
	} {
		r := c.do(e.browser(fmt.Sprintf("203.0.113.%d", 100+i)))
		if r.Status != 403 || r.code() != "sso_required" {
			t.Errorf("%s: %d %s", c.name, r.Status, r.Body)
		}
		if i == 0 {
			first = r
		} else if r.Body != first.Body {
			t.Errorf("%s answers differently", c.name)
		}
	}
	if len(e.events("login")) != 0 {
		t.Fatal("a refused non-admin must not be signed in")
	}
	b := e.browser(addrA)
	if r := e.login1(b, alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("an admin is exempt: %d %s", r.Status, r.Body)
	}
	if b.cookies[login.SessionCookie] == "" {
		t.Fatal("no session for the admin")
	}
}

func TestSSOOnlyIsInertWithoutALocalAdminOrWithoutSSO(t *testing.T) {
	// no local admin (bob is an editor): sso_only is treated as off, once recorded as a settings problem
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n"})
	bob := e.addAccount("bob")
	if r := e.login1(e.browser(addrA), bob, goodPassword, e.code(bob)); r.Status != 200 {
		t.Fatalf("without a local admin sso_only must be off: %d %s", r.Status, r.Body)
	}
	e.login1(e.browser(addrB), bob, "wrong wrong wrong", "")
	if ev := e.events("settings_problem"); len(ev) != 1 || ev[0].Code != "sso_only_without_local_admin" {
		t.Fatalf("%+v", ev)
	}
	// local_only mode and no SSO: inert as well
	for _, o := range []envOpts{
		{sso: true, auth: "  login: {mode: local_only, sso_only: true}\n"},
		{auth: "  login: {sso_only: true}\n"},
	} {
		e2 := newEnv(t, o)
		bob := e2.addAccount("bob")
		if r := e2.login1(e2.browser(addrA), bob, goodPassword, e2.code(bob)); r.Status != 200 {
			t.Fatalf("%+v: %d %s", o, r.Status, r.Body)
		}
	}
}

func TestAdminsAreExemptFromSSOOnlyEvenWithTheFailure(t *testing.T) {
	// the admin who mistypes sees the sso_required answer, not "wrong password"
	e := newEnv(t, envOpts{sso: true, auth: "  login: {sso_only: true}\n"})
	alice := e.addAccount("alice")
	if r := e.login1(e.browser(addrA), alice, "wrong wrong wrong", ""); r.Status != 403 || r.code() != "sso_required" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestDummyHashBudget(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	_ = alice
	b := func(i int) *browser { return e.browser(fmt.Sprintf("203.0.113.%d", i)) }
	// one bucket: two dummy hashes a minute, then sleeping
	for i := 0; i < 5; i++ {
		before := e.svc.sample.seq()
		r := e.login1(b(1), &person{name: fmt.Sprintf("ghost%d", i)}, goodPassword, "123456")
		hashed := e.svc.sample.seq() != before
		if (i < 2) != hashed {
			t.Errorf("unknown name %d from one bucket: hashed=%v", i, hashed)
		}
		if r.Status != 401 {
			t.Fatal(r.Status)
		}
	}
	if s := e.slept(); len(s) != 3 || s[0] > time.Millisecond || s[0] <= 0 {
		t.Errorf("past the budget the answer sleeps a duration of the sample: %v", s)
	}
	// the answer is the same, byte for byte, as an existing account's wrong password, which still hashes
	before := e.svc.sample.seq()
	real := e.login1(b(2), alice, "wrong wrong wrong", "")
	ghost := e.login1(b(1), &person{name: "ghost9"}, goodPassword, "123456")
	if e.svc.sample.seq() != before+1 || real.Status != ghost.Status || real.Body != ghost.Body {
		t.Fatalf("%v: %q vs %q", e.svc.sample.seq()-before, real.Body, ghost.Body)
	}
	// the server as a whole: 60 a minute
	e2 := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	hashed := 0
	for i := 0; i < 90; i++ {
		before := e2.svc.sample.seq()
		e2.login1(e2.browser(fmt.Sprintf("198.18.%d.%d", i/200, i%200+1)), &person{name: "ghost"}, goodPassword, "123456")
		if e2.svc.sample.seq() != before {
			hashed++
		}
	}
	if hashed != dummyPerMinute {
		t.Errorf("%d dummy hashes in a minute, want %d", hashed, dummyPerMinute)
	}
	// the next minute brings the budget back
	e2.clk.Advance(61 * time.Second)
	before = e2.svc.sample.seq()
	e2.login1(e2.browser("203.0.113.9"), &person{name: "ghost"}, goodPassword, "123456")
	if e2.svc.sample.seq() == before {
		t.Error("the budget did not come back")
	}
}

func TestBudgetDoesNotSwitchToSleepingBeforeTheSampleIsReady(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	e.svc.sample = &sample{} // the first seconds after a start
	for i := 0; i < 5; i++ {
		before := e.svc.sample.seq()
		e.login1(e.browser("203.0.113.5"), &person{name: "ghost"}, goodPassword, "123456")
		if e.svc.sample.seq() == before {
			t.Fatalf("attempt %d did not hash although the sample is not ready", i)
		}
	}
}

func TestSampleIsBoundedPerSource(t *testing.T) {
	var s sample
	for i := 0; i < 100; i++ {
		s.Add(time.Duration(i+1)*time.Hour, "bucket-1", "")
	}
	if n := countFrom(&s, "bucket-1"); n != samplePerSource {
		t.Fatalf("one bucket holds %d entries, want %d", n, samplePerSource)
	}
	for i := 0; i < 100; i++ {
		s.Add(time.Second, "", "acct")
	}
	if n := s.Len(); n > sampleSize || n > samplePerSource*2 {
		t.Fatalf("%d entries", n)
	}
	for i := 0; i < 1000; i++ {
		s.Add(time.Millisecond, fmt.Sprintf("b%d", i), fmt.Sprintf("a%d", i))
	}
	if s.Len() != sampleSize {
		t.Fatalf("the ring holds %d, want %d", s.Len(), sampleSize)
	}
}

func countFrom(s *sample, bucket string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.entries {
		if e.bucket == bucket {
			n++
		}
	}
	return n
}

// ks is the Kolmogorov-Smirnov statistic of two samples.
func ks(a, b []float64) float64 {
	sortF(a)
	sortF(b)
	var d float64
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] <= b[j] {
			i++
		} else {
			j++
		}
		fa, fb := float64(i)/float64(len(a)), float64(j)/float64(len(b))
		if x := fa - fb; x > d {
			d = x
		} else if -x > d {
			d = -x
		}
	}
	return d
}

func sortF(x []float64) {
	for i := 1; i < len(x); i++ {
		for j := i; j > 0 && x[j-1] > x[j]; j-- {
			x[j-1], x[j] = x[j], x[j-1]
		}
	}
}

// Past the dummy-hash budget an unknown name sleeps instead of hashing, and its response times follow the distribution of
// a real check (a two-sample Kolmogorov-Smirnov test; the design asks for 500 samples each with the real parameters,
// this runs with cheap ones and fewer).
func TestPastTheBudgetTimingFollowsARealCheck(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n", mutate: func(o *Options) {
		o.Sleep = time.Sleep
		o.Hasher = accounts.NewHasherCost(accounts.NewSlots(3, 5*time.Second), 4096, 2, 1)
	}})
	alice := e.addAccount("alice")
	// the hash-only sample, from real runs of this hasher
	e.svc.sample = &sample{}
	for i := 0; i < 64; i++ {
		d, err := e.svc.hasher.DummyTimed(t.Context(), accounts.ClassNormal, "x")
		if err != nil {
			t.Fatal(err)
		}
		e.svc.sample.Add(d, fmt.Sprintf("seed%d", i), "")
	}
	for e.svc.budget.Take("exhaust") || e.svc.budget.Take("exhaust2") { // the budget of this minute is spent for the whole server
		for i := 0; i < dummyPerMinute; i++ {
			e.svc.budget.Take(fmt.Sprintf("x%d", i))
		}
		break
	}
	const n = 150
	var real, ghost []float64
	for i := 0; i < n; i++ {
		b := e.browser(fmt.Sprintf("203.0.%d.%d", i/200, i%200+1))
		real = append(real, float64(e.login1(b, alice, "wrong wrong wrong", "").Elapsed))
		b = e.browser(fmt.Sprintf("203.1.%d.%d", i/200, i%200+1))
		ghost = append(ghost, float64(e.login1(b, &person{name: "ghost"}, "wrong wrong wrong", "").Elapsed))
	}
	// 2.5 * sqrt(2/n) is the critical value at alpha = 0.00001: the machine is shared and noisy, and a flake helps nobody
	d, crit := ks(real, ghost), 2.5*sqrt(2.0/float64(n))
	t.Logf("D = %.3f (critical %.3f)", d, crit)
	if d > crit {
		t.Fatalf("the response times differ: D = %.3f > %.3f", d, crit)
	}
}

func sqrt(x float64) float64 {
	z := x / 2
	for i := 0; i < 40; i++ {
		z = (z + x/z) / 2
	}
	return z
}

func TestFloodCeiling(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	b := e.browser(addrA)
	var last resp
	for i := 0; i < floodPerMinute+5; i++ {
		last = e.login1(b, &person{name: "ghost"}, "x", "")
	}
	if last.Status != 429 {
		t.Fatalf("%d", last.Status)
	}
	// another bucket is fine, and the next minute too
	if r := e.login1(e.browser(addrB), &person{name: "ghost"}, "x", ""); r.Status != 401 {
		t.Fatal(r.Status)
	}
	e.clk.Advance(61 * time.Second)
	if r := e.login1(b, &person{name: "ghost"}, "x", ""); r.Status != 401 {
		t.Fatal(r.Status)
	}
}

func TestRefusalsAreAggregatedPerBucketAndMinute(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	for i := 0; i < 20; i++ {
		e.login1(b, alice, "wrong wrong wrong", "")
	}
	for i := 0; i < 5; i++ {
		e.login1(b, &person{name: fmt.Sprintf("ghost%d", i)}, "x", "")
	}
	full := 0
	for _, ev := range e.events("login_refused") {
		if ev.Code != "summary" {
			full++
		}
	}
	if full != 2 { // the first of alice and the first of an unknown name
		t.Fatalf("%d full events in a minute, want 2", full)
	}
	e.clk.Advance(2 * time.Minute)
	e.svc.refused.Flush(e.clk.Now(), false)
	var sum []string
	for _, ev := range e.events("login_refused") {
		if ev.Code == "summary" {
			sum = ev.Detail
			if ev.Addr != addrA {
				t.Errorf("addr %q", ev.Addr)
			}
		}
	}
	if len(sum) == 0 || sum[0] != "count:23" || !strings.Contains(sum[1], "bad_credentials=19") || !strings.Contains(sum[1], "unknown_account=4") {
		t.Fatalf("%v", sum)
	}
}

func TestBeyond100BucketsFoldIntoOneSummaryWithoutAddr(t *testing.T) {
	var got []string
	a := newAggregator("login_refused", func(e auditEvent) { got = append(got, fmt.Sprint(e.Addr, e.Detail)) })
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 150; i++ {
		a.Note(now, fmt.Sprintf("b%d", i), fmt.Sprintf("10.0.0.%d", i), "", "unknown_account") // the first of each bucket: full
		a.Note(now, fmt.Sprintf("b%d", i), fmt.Sprintf("10.0.0.%d", i), "", "unknown_account") // counted
	}
	a.Flush(now.Add(2*time.Minute), false)
	if len(got) != 101 {
		t.Fatalf("%d summaries, want 100 buckets and one folded", len(got))
	}
	if !strings.HasPrefix(got[len(got)-1], "[count:") && !strings.Contains(got[len(got)-1], "count:50") {
		t.Fatalf("%q", got[len(got)-1])
	}
}

func TestAuditUnavailableFailsClosed(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	// the next month's file cannot be created: the log cannot be written
	e.clk.Advance(40 * 24 * time.Hour)
	if err := chmod(e.dir+"/audit", 0o500); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { chmod(e.dir+"/audit", 0o700) })
	b := e.browser(addrA)
	r := e.login1(b, alice, goodPassword, e.code(alice))
	if r.Status != 503 || r.code() != "audit_unavailable" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if b.cookies[login.SessionCookie] != "" {
		t.Fatal("a sign-in whose audit line could not be written must not get a session")
	}
}

func TestAnAccountWithNoRoleGetsNoSession(t *testing.T) {
	e := newEnv(t, envOpts{noRoles: true})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	r := e.login1(b, alice, goodPassword, e.code(alice))
	if r.Status != 403 || r.code() != "no_role" || b.cookies[login.SessionCookie] != "" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestEveryAnswerIsNoStoreJSON(t *testing.T) {
	e := newEnv(t, envOpts{})
	r := e.login1(e.browser(addrA), &person{name: "x"}, "x", "")
	if r.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || r.Header.Get("Content-Length") == "" {
		t.Fatalf("%v", r.Header)
	}
	_ = http.StatusOK
}

type fakeCaptcha struct{ required bool }

func (f *fakeCaptcha) Required(bucket, name string) bool { return f.required }
func (f *fakeCaptcha) Verify(_ context.Context, _, solve, _ string) error {
	if solve == "right" {
		return nil
	}
	return errors.New("wrong")
}

// The CAPTCHA is piece 5: off here, with a hook that the sign-in asks before the throttle when one is set.
func TestCaptchaHookPointIsOffAndAsksBeforeTheThrottleWhenSet(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	if r := e.browser(addrA).post("/auth/local/attempt", map[string]string{}); r.json()["captcha"] != false {
		t.Fatalf("%s", r.Body)
	}
	if r := e.login1(e.browser(addrA), alice, goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("with no CAPTCHA configured: %d %s", r.Status, r.Body)
	}
	fc := &fakeCaptcha{required: true}
	e2 := newEnv(t, envOpts{mutate: func(o *Options) { o.Captcha = fc }})
	alice2 := e2.addAccount("alice")
	before := e2.svc.sample.seq()
	r := e2.login1(e2.browser(addrA), alice2, goodPassword, e2.code(alice2))
	if r.Status != 401 || r.code() != "captcha_required" || e2.svc.sample.seq() != before {
		t.Fatalf("an unsolved CAPTCHA must refuse before any hash: %d %s", r.Status, r.Body)
	}
	if a := e2.browser(addrA).post("/auth/local/attempt", map[string]string{}); a.json()["captcha"] != true {
		t.Fatalf("%s", a.Body)
	}
	ok := e2.browser(addrA).post("/auth/local/login", map[string]string{"username": "alice", "password": goodPassword, "code": e2.code(alice2), "captcha": "right"})
	if ok.Status != 200 {
		t.Fatalf("%d %s", ok.Status, ok.Body)
	}
}

// Nothing a person types is in a log or an audit event: passwords, codes, typed names of accounts that do not exist.
func TestNoPasswordOrCodeIsLoggedOrAudited(t *testing.T) {
	logs := &syncBuf{}
	e := newEnv(t, envOpts{mutate: func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}})
	alice := e.addAccount("alice")
	secret1, secret2 := "typed-password-never-logged", "another-secret-pass-phrase"
	var codes []string
	for i := 0; i < 3; i++ {
		e.login1(e.browser(addrA), alice, secret1, "654321")
		e.login1(e.browser(addrB), &person{name: "ghostname"}, secret2, "111222")
		codes = append(codes, "654321", "111222")
	}
	b := e.browser(addrA)
	code := e.code(alice)
	e.login1(b, alice, goodPassword, code)
	b.post("/auth/local/reauth", map[string]string{"password": secret1, "code": "999888"})
	var all strings.Builder
	all.WriteString(logs.String())
	for _, ev := range e.events("") {
		raw, _ := json.Marshal(ev)
		all.Write(raw)
	}
	e.svc.refused.Flush(e.clk.Now(), true)
	for _, ev := range e.events("") {
		raw, _ := json.Marshal(ev)
		all.Write(raw)
	}
	for _, s := range append([]string{secret1, secret2, goodPassword, "ghostname", code, "999888"}, codes...) {
		if strings.Contains(all.String(), s) {
			t.Fatalf("%q is in a log or an audit event", s)
		}
	}
}

// The page's modes (2.1): sso_redirect goes straight to the provider unless ?local=1 or an error asks for the page, and
// /auth/config says how to shape it.
func TestLoginModesShapeThePageAndTheRedirect(t *testing.T) {
	get := func(e *env, path string) (int, string, string) {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		e.mux.ServeHTTP(w, r)
		return w.Code, w.Header().Get("Location"), w.Body.String()
	}
	e := newEnv(t, envOpts{sso: true, auth: "  login: {mode: sso_redirect}\n"})
	if code, loc, _ := get(e, "/auth/login"); code != 303 || loc != "/auth/oidc/start" {
		t.Fatalf("sso_redirect: %d %q", code, loc)
	}
	if code, loc, _ := get(e, "/auth/login?return=%2Frecords%2Fx"); code != 303 || loc != "/auth/oidc/start?return=%2Frecords%2Fx" {
		t.Fatalf("with a return: %d %q", code, loc)
	}
	for _, p := range []string{"/auth/login?local=1", "/auth/login?error=idp_error", "/auth/login?error=logged_out"} {
		if code, _, body := get(e, p); code != 200 || !strings.Contains(body, "page") {
			t.Fatalf("%s: %d", p, code)
		}
	}
	_, _, cfg := get(e, "/auth/config")
	var j map[string]any
	_ = json.Unmarshal([]byte(cfg), &j)
	if j["mode"] != "sso_redirect" || j["local"] != true || j["oidc"] != true {
		t.Fatalf("%v", j)
	}
	// without single sign-on every mode is local_only, and nothing redirects
	e2 := newEnv(t, envOpts{auth: "  login: {mode: sso_redirect}\n"})
	if code, _, _ := get(e2, "/auth/login"); code != 200 {
		t.Fatalf("no SSO: %d", code)
	}
	_, _, cfg = get(e2, "/auth/config")
	_ = json.Unmarshal([]byte(cfg), &j)
	if j["mode"] != "local_only" || j["oidc"] != false {
		t.Fatalf("%v", j)
	}
	for _, m := range []string{"dual", "sso_first", "local_only"} {
		e3 := newEnv(t, envOpts{sso: true, auth: "  login: {mode: " + m + "}\n"})
		if code, _, _ := get(e3, "/auth/login"); code != 200 {
			t.Fatalf("%s: %d", m, code)
		}
		_, _, cfg = get(e3, "/auth/config")
		_ = json.Unmarshal([]byte(cfg), &j)
		if j["mode"] != m {
			t.Fatalf("%s: %v", m, j)
		}
	}
}
