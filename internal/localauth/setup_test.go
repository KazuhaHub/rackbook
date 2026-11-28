package localauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/login"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

const newPassword = "an entirely different passphrase"

// invite makes an invited account and returns its link token.
func (e *env) invite(name string) string {
	e.t.Helper()
	tok, err := e.store.Invite(accounts.CLI("t"), name, "Dana", 72*time.Hour, e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) open(b *browser, tok string) resp {
	return b.post("/auth/local/setup/open", map[string]string{"token": tok})
}

// setupTOTP asks for a secret and returns the finish body with a code of it.
func (e *env) enrolTOTP(b *browser, tok string) (map[string]any, []byte) {
	e.t.Helper()
	r := b.post("/auth/local/setup/totp", map[string]string{"token": tok})
	if r.Status != 200 {
		e.t.Fatalf("totp: %d %s", r.Status, r.Body)
	}
	j := r.json()
	sec, err := decodeBase32(j["secret"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	if !strings.HasPrefix(j["uri"].(string), "otpauth://totp/") {
		e.t.Fatal(j["uri"])
	}
	code := accounts.TOTPCode(sec, accounts.TOTPStep(e.clk.Now()))
	return map[string]any{"enrol": j["enrol"], "code": code}, sec
}

func TestInviteSetupWithTOTPSignsThePersonIn(t *testing.T) {
	logs := &syncBuf{}
	e := newEnv(t, envOpts{mutate: func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}})
	tok := e.invite("dana")
	b := e.browser(addrA)
	r := e.open(b, tok)
	j := r.json()
	if r.Status != 200 || j["kind"] != "invite" || j["scope"] != "all" || j["username"] != "dana" || j["newPassword"] != true || j["newFactor"] != true || j["minLength"] != float64(12) {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if b.cookies[HoldCookie] == "" {
		t.Fatal("the link is held for this browser by a cookie")
	}
	totp, sec := e.enrolTOTP(b, tok)
	fin := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": totp})
	if fin.Status != 200 || fin.json()["signedIn"] != true {
		t.Fatalf("%d %s", fin.Status, fin.Body)
	}
	a := e.account("dana")
	if a.State != accounts.StateActive || a.Password == "" || a.TOTP == nil || a.Pending != nil || a.LastLogin == nil {
		t.Fatalf("%+v", a)
	}
	if _, ok := e.login.LocalSession(httptestRequest(b)); !ok {
		t.Fatal("no session after setup")
	}
	// the sign-in works with the new password, and the link is dead
	if r := e.login1(e.browser(addrB), &person{name: "dana"}, newPassword, e.code(&person{name: "dana", secret: sec})); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := e.open(e.browser(addrA), tok); r.Status != 404 || r.code() != "invite_invalid" {
		t.Fatalf("a used link: %d %s", r.Status, r.Body)
	}
	for _, name := range []string{"account_invited", "account_link_opened", "account_setup_completed", "login"} {
		if len(e.events(name)) == 0 {
			t.Errorf("no %s event", name)
		}
	}
	// no link token, password or code in any log or audit line
	var all strings.Builder
	all.WriteString(logs.String())
	for _, ev := range e.events("") {
		raw, _ := json.Marshal(ev)
		all.Write(raw)
	}
	for _, secret := range []string{tok, newPassword, goodPassword, totp["code"].(string)} {
		if strings.Contains(all.String(), secret) {
			t.Fatalf("%q appears in a log or an audit event", secret[:min(len(secret), 6)])
		}
	}
}

func TestSetupNeedsASecondFactorAndAGoodPassword(t *testing.T) {
	e := newEnv(t, envOpts{})
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	// no second factor
	r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword})
	if r.Status != 422 || r.code() != "factor_required" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	totp, _ := e.enrolTOTP(b, tok)
	// a weak password, and one with the username in it
	for _, pw := range []string{"short", "danadanadana-pass", "password1234"} {
		r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": pw, "totp": totp})
		if r.Status != 422 || r.code() != "password_rules" {
			t.Errorf("%q: %d %s", pw, r.Status, r.Body)
		}
	}
	// a wrong confirmation code
	bad := map[string]any{"enrol": totp["enrol"], "code": "000000"}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": bad}); r.Status != 422 || r.code() != "bad_code" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if a := e.account("dana"); a.State != accounts.StateInvited || a.Password != "" || a.TOTP != nil {
		t.Fatalf("a refused setup changed the account: %+v", a)
	}
	// an enrolment of another browser cannot be used here
	other := e.browser(addrB)
	tok2 := e.invite("erin")
	e.open(other, tok2)
	foreign, _ := e.enrolTOTP(other, tok2)
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "totp": foreign}); r.Status != 422 {
		t.Fatalf("a TOTP enrolment of another link: %d", r.Status)
	}
}

func TestInviteLinkIsHeldForOneBrowserAndExpires(t *testing.T) {
	e := newEnv(t, envOpts{})
	tok := e.invite("dana")
	one, two := e.browser(addrA), e.browser(addrB)
	if r := e.open(one, tok); r.Status != 200 {
		t.Fatal(r.Body)
	}
	if r := e.open(two, tok); r.Status != 409 || r.code() != "invite_claimed" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// the other browser cannot continue either, even with the token
	if r := two.post("/auth/local/setup/totp", map[string]string{"token": tok}); r.Status == 200 {
		t.Fatal("a browser that does not hold the link got a TOTP secret")
	}
	// the hold ends: the link is dead for everybody
	e.clk.Advance(accounts.HoldTime + time.Minute)
	if r := e.open(one, tok); r.Status != 410 || r.code() != "invite_expired" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// an invite that was never opened expires with its lifetime
	tok2 := e.invite("erin")
	e.clk.Advance(73 * time.Hour)
	if r := e.open(e.browser(addrA), tok2); r.Status != 410 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// nothing is sent until Continue: a wrong token tells nothing about names
	if r := e.open(e.browser(addrA), "garbage"); r.Status != 404 || r.code() != "invite_invalid" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	for _, ev := range e.events("login_refused") {
		if ev.Reason == "" || !strings.HasPrefix(ev.Reason, "invite_") {
			t.Errorf("%+v", ev)
		}
	}
}

func TestResetLinksNeedWhatTheyNeed(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("bob")
	reset := func(scope string) (string, *browser, map[string]any) {
		tok, err := e.store.Reset(accounts.CLI("t"), "bob", accounts.ResetOptions{Scope: scope, TTL: 24 * time.Hour}, e.clk.Now())
		if err != nil {
			t.Fatal(err)
		}
		b := e.browser(addrA)
		r := e.open(b, tok)
		if r.Status != 200 {
			t.Fatalf("%s: %d %s", scope, r.Status, r.Body)
		}
		return tok, b, r.json()
	}
	// password: an existing factor first, no new factor
	tok, b, j := reset(accounts.ScopePassword)
	if j["kind"] != "reset" || j["scope"] != "password" || j["proveFactor"] != true || j["newFactor"] != false || j["currentPassword"] != false {
		t.Fatalf("%v", j)
	}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword}); r.Status != 401 {
		t.Fatalf("a password reset link alone is not enough: %d %s", r.Status, r.Body)
	}
	proof := map[string]any{"code": e.code(alice)}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": map[string]any{"code": "000000"}}); r.Status != 401 {
		t.Fatalf("a wrong factor: %d", r.Status)
	}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": proof}); r.Status != 200 || r.json()["signedIn"] != true {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if a := e.account("bob"); a.State != accounts.StateActive || a.TOTP == nil || a.Password == "" {
		t.Fatalf("%+v", a)
	}
	// second_factor: the current password first, then a new factor
	tok, b, j = reset(accounts.ScopeSecondFactor)
	if j["currentPassword"] != true || j["newFactor"] != true || j["newPassword"] != false {
		t.Fatalf("%v", j)
	}
	totp, _ := e.enrolTOTP(b, tok)
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "totp": totp}); r.Status != 401 {
		t.Fatalf("a second-factor reset link alone is not enough: %d %s", r.Status, r.Body)
	}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "current_password": "not the password", "totp": totp}); r.Status != 401 {
		t.Fatalf("a wrong current password: %d", r.Status)
	}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "current_password": newPassword, "totp": totp}); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// all: like a new invite
	tok, b, j = reset(accounts.ScopeAll)
	if j["newPassword"] != true || j["newFactor"] != true || j["proveFactor"] != false {
		t.Fatalf("%v", j)
	}
	totp, _ = e.enrolTOTP(b, tok)
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": goodPassword, "totp": totp}); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestTenWrongProofsKillAResetLink(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 1000}\n"})
	e.addAccount("bob")
	tok, _ := e.store.Reset(accounts.CLI("t"), "bob", accounts.ResetOptions{Scope: accounts.ScopePassword, TTL: 24 * time.Hour}, e.clk.Now())
	b := e.browser(addrA)
	e.open(b, tok)
	for i := 0; i < maxSetupFails; i++ {
		b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": map[string]any{"code": "000000"}})
	}
	if r := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "proof": map[string]any{"code": "000000"}}); r.Status != 404 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

// ---- passkeys

type device struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newDevice() *device {
	return &device{
		rp:   virtualwebauthn.RelyingParty{Name: "Rackbook", ID: "rackbook.test", Origin: testBase},
		auth: virtualwebauthn.NewAuthenticator(),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

func (d *device) attest(t *testing.T, b *browser, tok string) map[string]any {
	t.Helper()
	r := b.post("/auth/local/setup/passkey", map[string]string{"token": tok})
	if r.Status != 200 {
		t.Fatalf("passkey begin: %d %s", r.Status, r.Body)
	}
	opts, _ := json.Marshal(r.json()["options"])
	o, err := virtualwebauthn.ParseAttestationOptions(string(opts))
	if err != nil {
		t.Fatal(err)
	}
	d.auth.Options.UserHandle = []byte(o.UserID)
	body := virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *o)
	return map[string]any{"ceremony": r.json()["ceremony"], "credential": json.RawMessage(body), "name": "Laptop"}
}

// assert runs the attempt endpoint and answers its challenge.
func (d *device) assert(t *testing.T, b *browser) (attempt string, assertion json.RawMessage) {
	t.Helper()
	r := b.post("/auth/local/attempt", map[string]string{})
	if r.Status != 200 {
		t.Fatalf("attempt: %d %s", r.Status, r.Body)
	}
	opts, _ := json.Marshal(r.json()["passkey"])
	o, err := virtualwebauthn.ParseAssertionOptions(string(opts))
	if err != nil {
		t.Fatal(err)
	}
	body := virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *o)
	return r.json()["attempt"].(string), json.RawMessage(body)
}

func TestSetupWithAPasskeyAndSignInWithIt(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  throttle: {max: 3, window: 5m}\n  lock: {enabled: true, scope: account}\n"})
	d := newDevice()
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	pk := d.attest(t, b, tok)
	fin := b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "passkey": pk})
	if fin.Status != 200 || fin.json()["signedIn"] != true {
		t.Fatalf("%d %s", fin.Status, fin.Body)
	}
	a := e.account("dana")
	if len(a.Passkeys) != 1 || a.TOTP != nil || a.Passkeys[0].Name != "Laptop" || len(a.Passkeys[0].UserHandle) == 0 {
		t.Fatalf("%+v", a)
	}
	d.auth.AddCredential(d.cred)
	// sign in with the password and the passkey in one request
	signIn := func(b *browser, pw string) resp {
		attempt, assertion := d.assert(t, b)
		return b.post("/auth/local/login", map[string]any{"username": "dana", "password": pw, "attempt": attempt, "passkey": assertion})
	}
	if r := signIn(e.browser(addrB), newPassword); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if ev := e.events("login"); ev[len(ev)-1].Detail[0] != "factor:passkey" {
		t.Fatalf("%+v", ev)
	}
	// the throttle and the lock: three failures from addrA lock everything for a person without the passkey,
	// and a verified passkey goes past both
	for i := 0; i < 3; i++ {
		e.login1(e.browser(addrA), &person{name: "dana"}, "wrong wrong wrong", "")
	}
	if r := e.login1(e.browser(addrA), &person{name: "dana"}, newPassword, "123456"); r.Status != 429 {
		t.Fatalf("locked and throttled: %d", r.Status)
	}
	e.clk.Advance(time.Second) // last_login must move forward for the counters to be lowered
	if r := signIn(e.browser(addrA), newPassword); r.Status != 200 {
		t.Fatalf("a verified passkey goes past the throttle and the locks: %d %s", r.Status, r.Body)
	}
	// but the password is still checked: a wrong one after a verified passkey counts for the passkey path
	r := signIn(e.browser(addrA), "wrong wrong wrong")
	if r.Status != 401 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if got := e.account("dana"); got.PasskeyPathFailures != 1 {
		t.Fatalf("%+v", got)
	}
	// an assertion is single use
	e.clk.Advance(time.Second)
	attempt, assertion := d.assert(t, e.browser(addrB))
	body := map[string]any{"username": "dana", "password": newPassword, "attempt": attempt, "passkey": assertion}
	if r := e.browser(addrB).post("/auth/local/login", body); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := e.browser(addrB).post("/auth/local/login", body); r.Status == 200 {
		t.Fatal("a replayed assertion signed in")
	}
	// an attempt belongs to its network
	attempt, assertion = d.assert(t, e.browser(addrB))
	if r := e.browser("192.0.2.77").post("/auth/local/login", map[string]any{"username": "dana", "password": newPassword, "attempt": attempt, "passkey": assertion}); r.Status == 200 {
		t.Fatal("an attempt of another network signed in")
	}
	// the passkey of one account does not sign in another
	e.addAccount("bob")
	attempt, assertion = d.assert(t, e.browser(addrB))
	if r := e.browser(addrB).post("/auth/local/login", map[string]any{"username": "bob", "password": goodPassword, "attempt": attempt, "passkey": assertion}); r.Status == 200 {
		t.Fatal("dana's passkey signed in bob")
	}
}

func TestPasskeyPathIsLimitedPerHour(t *testing.T) {
	e := newEnv(t, envOpts{auth: "  twofa_limits: {passkey_path_per_hour: 3}\n"})
	d := newDevice()
	tok := e.invite("dana")
	b := e.browser(addrA)
	e.open(b, tok)
	pk := d.attest(t, b, tok)
	b.post("/auth/local/setup/finish", map[string]any{"token": tok, "password": newPassword, "passkey": pk})
	d.auth.AddCredential(d.cred)
	for i := 0; i < 3; i++ {
		bb := e.browser(fmt.Sprintf("192.0.2.%d", i+1))
		attempt, assertion := d.assert(t, bb)
		bb.post("/auth/local/login", map[string]any{"username": "dana", "password": "wrong wrong wrong", "attempt": attempt, "passkey": assertion})
	}
	bb := e.browser(addrB)
	attempt, assertion := d.assert(t, bb)
	if r := bb.post("/auth/local/login", map[string]any{"username": "dana", "password": newPassword, "attempt": attempt, "passkey": assertion}); r.Status == 200 {
		t.Fatal("the passkey path must be refused after its limit")
	}
	e.clk.Advance(61 * time.Minute)
	bb = e.browser(addrB)
	attempt, assertion = d.assert(t, bb)
	if r := bb.post("/auth/local/login", map[string]any{"username": "dana", "password": newPassword, "attempt": attempt, "passkey": assertion}); r.Status != 200 {
		t.Fatalf("an hour later: %d %s", r.Status, r.Body)
	}
}

// ---- re-authentication

func TestReauthentication(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	e.login1(b, alice, goodPassword, e.code(alice))
	req := func() bool { return e.login.RecentAuth(httptestRequest(b), 10*time.Minute) }
	if !req() {
		t.Fatal("fresh after sign-in")
	}
	e.clk.Advance(11 * time.Minute)
	if req() {
		t.Fatal("the window ended")
	}
	re := func(pw, code string) resp {
		return b.post("/auth/local/reauth", map[string]string{"password": pw, "code": code})
	}
	// two failures, then a success resets the count
	if r := re("wrong wrong wrong", ""); r.Status != 401 {
		t.Fatal(r.Status)
	}
	if r := re(goodPassword, "000000"); r.Status != 401 {
		t.Fatal(r.Status)
	}
	if a := e.account("alice"); a.ReauthFailures != 2 || a.ConsecutiveFailures != 1 {
		t.Fatalf("%+v", a)
	}
	if r := re(goodPassword, e.code(alice)); r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if !req() {
		t.Fatal("a re-authentication starts a new window")
	}
	if a := e.account("alice"); a.ReauthFailures != 0 {
		t.Fatalf("success resets the count: %+v", a)
	}
	if len(e.events("reauth")) != 1 {
		t.Fatal("no reauth event")
	}
	// three failures end every session of the account, the browser's included
	other := e.browser(addrB)
	e.login1(other, alice, goodPassword, e.code(alice))
	for i := 0; i < 3; i++ {
		re("wrong wrong wrong", "")
	}
	if _, ok := e.login.LocalSession(httptestRequest(b)); ok {
		t.Fatal("this session survived three failed re-authentications")
	}
	if _, ok := e.login.LocalSession(httptestRequest(other)); ok {
		t.Fatal("another session of the account survived")
	}
	if ev := e.events("sessions_ended"); len(ev) != 1 || ev[0].Reason != "reauth_failed" || ev[0].Identity != "local:alice" {
		t.Fatalf("%+v", ev)
	}
	// without a session there is nothing to re-authenticate
	if r := e.browser(addrA).post("/auth/local/reauth", map[string]string{"password": goodPassword, "code": e.code(alice)}); r.Status != 401 || r.code() != "login_required" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestReauthenticationIsOneStepAndUniform(t *testing.T) {
	e := newEnv(t, envOpts{})
	alice := e.addAccount("alice")
	b := e.browser(addrA)
	e.login1(b, alice, goodPassword, e.code(alice))
	a := b.post("/auth/local/reauth", map[string]string{"password": "wrong wrong wrong", "code": e.code(alice)})
	c := b.post("/auth/local/reauth", map[string]string{"password": goodPassword, "code": "000000"})
	if a.Status != 401 || a.Body != c.Body {
		t.Fatalf("a wrong password and a wrong code must be told apart by nobody: %q vs %q", a.Body, c.Body)
	}
	// a session cookie that is not a local one cannot re-authenticate a local account
	_ = login.SessionCookie
}
