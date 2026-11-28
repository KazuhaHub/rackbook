package localauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kazuhahub/rackbook/internal/accounts"
	"github.com/kazuhahub/rackbook/internal/audit"
	"github.com/kazuhahub/rackbook/internal/auth"
	"github.com/kazuhahub/rackbook/internal/config"
	"github.com/kazuhahub/rackbook/internal/login"
	"github.com/kazuhahub/rackbook/internal/roles"
	"github.com/kazuhahub/rackbook/internal/statekey"
)

const (
	testBase     = "https://rackbook.test"
	goodPassword = "correct horse battery staple"
)

var sessionKey = []byte("0123456789abcdef0123456789abcdef-test-key")

type clock struct{ t atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Unix(c.t.Load(), 0).UTC() }
func (c *clock) Advance(d time.Duration) { c.t.Add(int64(d.Seconds())) }

// rolesYAML gives alice the admin role, bob the editor role and every other local account the viewer role.
const rolesYAML = `  roles:
    admin: ["local:alice", "root@example.com"]
    editor: ["local:bob"]
    viewer: ["local:*"]
`

type env struct {
	t      *testing.T
	dir    string
	key    *statekey.Key
	clk    *clock
	log    *audit.Log
	store  *accounts.Store
	login  *login.Service
	authn  *auth.Authenticator
	svc    *Service
	mux    *http.ServeMux
	cfg    atomic.Pointer[config.Config]
	mu     sync.Mutex
	sleeps []time.Duration
	rev    *fakeRevoker
}

type envOpts struct {
	auth    string // YAML under auth:, after the roles
	sso     bool
	mutate  func(*Options)
	noRoles bool
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	k, err := statekey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: t.TempDir(), key: k, clk: &clock{}}
	e.clk.t.Store(time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC).Unix())
	e.setAuth(o)
	pin := accounts.NewPin(e.dir, k)
	e.log, err = audit.Open(e.dir+"/audit", audit.Options{Now: e.clk.Now, Pin: pin, Addr: audit.AddrFull})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.log.Close)
	e.store, err = accounts.Open(accounts.Options{StateDir: e.dir, Key: k, Log: e.log, Pin: pin, Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	lo := login.Options{Login: e.cfg.Load().Auth.Login, Config: e.cfg.Load, BaseURL: testBase, Key: sessionKey, Audit: e.log, Local: e.store, Now: e.clk.Now}
	if o.sso {
		lo.Login.OIDC = config.OIDC{Issuer: "https://idp.example", ClientID: "c"}
		lo.ClientSecret = "x"
	}
	e.login, err = login.New(lo)
	if err != nil {
		t.Fatal(err)
	}
	e.authn, err = auth.New(context.Background(), auth.Config{Mode: auth.ModeOIDC, Sessions: e.login, Config: e.cfg.Load, Local: e.store})
	if err != nil {
		t.Fatal(err)
	}
	e.login.Bind(e.authn)
	so := Options{
		StateDir: e.dir, Store: e.store, Key: k, Audit: e.log, Login: e.login, Config: e.cfg.Load, BaseURL: testBase, SSO: o.sso, Now: e.clk.Now,
		Hasher: accounts.NewHasherCost(accounts.NewSlots(3, 5*time.Second), 64, 1, 1), SkipCalibration: true,
		Sleep: func(d time.Duration) { e.mu.Lock(); e.sleeps = append(e.sleeps, d); e.mu.Unlock() },
		IsAdmin: func(u string) bool {
			return e.authn.Evaluate(&auth.Identity{ID: "local:" + u, Method: auth.MethodLocal}).EffectiveRole() == roles.Admin
		},
	}
	if o.mutate != nil {
		o.mutate(&so)
	}
	e.svc, err = New(so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.svc.Close)
	e.rev = &fakeRevoker{}
	e.svc.SetRevoker(e.rev)
	// a ready sample, so that the budget behaves as it does after the first seconds of a start
	for i := 0; i < sampleReady; i++ {
		e.svc.sample.Add(time.Millisecond, "", "")
	}
	e.mux = http.NewServeMux()
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>page</html>")) })
	e.login.Mount(e.mux, static)
	e.svc.Mount(e.mux, static)
	return e
}

func (e *env) setAuth(o envOpts) {
	y := "collections:\n  a: {file: a.yml, schema: s.json}\nauth:\n"
	if !o.noRoles {
		y += rolesYAML
	}
	if o.sso {
		y += "  mode: oidc\n  oidc: {issuer: 'https://idp.example', client_id: c}\n"
	}
	y += o.auth
	c, err := config.Parse([]byte(y), "/r/rackbook.yml")
	if err != nil {
		e.t.Fatal(err)
	}
	e.cfg.Store(c)
}

func (e *env) slept() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Duration(nil), e.sleeps...)
}

func (e *env) resetSleeps() { e.mu.Lock(); e.sleeps = nil; e.mu.Unlock() }

// ---- a browser

type browser struct {
	e       *env
	cookies map[string]string
	addr    string
}

func (e *env) browser(addr string) *browser {
	return &browser{e: e, cookies: map[string]string{}, addr: addr}
}

type timedRecorder struct {
	*httptest.ResponseRecorder
	flushedAt time.Time
}

func (t *timedRecorder) Flush() {
	if t.flushedAt.IsZero() {
		t.flushedAt = time.Now()
	}
	t.ResponseRecorder.Flush()
}

type resp struct {
	Elapsed time.Duration
	Status  int
	Body    string
	Header  http.Header
}

func (b *browser) post(path string, body any) resp {
	b.e.t.Helper()
	var raw []byte
	switch v := body.(type) {
	case string:
		raw = []byte(v)
	default:
		raw, _ = json.Marshal(v)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = b.addr + ":4000"
	for n, v := range b.cookies {
		r.AddCookie(&http.Cookie{Name: n, Value: v})
	}
	w := &timedRecorder{ResponseRecorder: httptest.NewRecorder()}
	start := time.Now()
	b.e.mux.ServeHTTP(w, r)
	answered := time.Since(start)
	if !w.flushedAt.IsZero() {
		answered = w.flushedAt.Sub(start) // what the client waits for: the answer is sent before the counters are written
	}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return resp{Status: w.Code, Body: w.Body.String(), Header: w.Header(), Elapsed: answered}
}

func (r resp) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(r.Body), &m)
	return m
}

func (r resp) code() string { s, _ := r.json()["error"].(string); return s }

// ---- accounts

type person struct {
	name   string
	secret []byte
}

// code is a TOTP code the account has not used: the clock moves to a new step first.
func (e *env) code(p *person) string {
	e.clk.Advance(31 * time.Second)
	return accounts.TOTPCode(p.secret, accounts.TOTPStep(e.clk.Now()))
}

// addAccount makes an active account through the invite flow's own writes.
func (e *env) addAccount(name string) *person {
	e.t.Helper()
	tok, err := e.store.Invite(accounts.CLI("test"), name, strings.ToUpper(name[:1])+name[1:], 72*time.Hour, e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	_, hh, _ := accounts.NewHold()
	if _, _, err := e.store.OpenLink(tok, hh, "198.51.100.1", e.clk.Now()); err != nil {
		e.t.Fatal(err)
	}
	sec, _ := accounts.NewTOTPSecret()
	f, err := accounts.NewTOTPFactor(sec, accounts.TOTPCode(sec, accounts.TOTPStep(e.clk.Now())), e.clk.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	pw, err := e.svc.hasher.Hash(context.Background(), accounts.ClassNormal, goodPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.store.CompleteSetup(accounts.Setup{Token: tok, Holder: hh, Password: pw, TOTP: f, Factor: "totp"}, e.clk.Now()); err != nil {
		e.t.Fatal(err)
	}
	return &person{name: name, secret: sec}
}

func (e *env) events(name string) []audit.Event {
	e.t.Helper()
	var out []audit.Event
	if err := e.log.EachEvent("", func(ev audit.Event, _ string) bool {
		if name == "" || ev.Event == name {
			out = append(out, ev)
		}
		return true
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) account(name string) *accounts.Account { return e.store.Lookup(name) }

func (e *env) login1(b *browser, p *person, password, code string) resp {
	e.t.Helper()
	return b.post("/auth/local/login", map[string]string{"username": p.name, "password": password, "code": code})
}

// the typical fixed addresses of the tests
var (
	addrA = "203.0.113.10"
	addrB = "198.51.100.20"
)

var _ = netip.Prefix{}

type auditEvent = audit.Event

func chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

// httptestRequest is a request that carries the browser's cookies.
func httptestRequest(b *browser) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for n, v := range b.cookies {
		r.AddCookie(&http.Cookie{Name: n, Value: v})
	}
	return r
}

func decodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(s, " ", "")))
}

// fakeRevoker owns tokens and grants by account and records what was revoked.
type fakeRevoker struct {
	mu      sync.Mutex
	tokens  map[string][]string // account -> token names
	grants  map[string][]string
	revoked []string
}

func (f *fakeRevoker) own(user string, tokens, grants []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens, f.grants = map[string][]string{}, map[string][]string{}
	}
	f.tokens[user] = append(f.tokens[user], tokens...)
	f.grants[user] = append(f.grants[user], grants...)
}

func (f *fakeRevoker) Owned(user string) ([]string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tokens[user]...), append([]string(nil), f.grants[user]...), nil
}

func (f *fakeRevoker) RevokeToken(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, "token:"+name)
	for u, ts := range f.tokens {
		f.tokens[u] = without(ts, name)
	}
	return nil
}

func (f *fakeRevoker) RevokeGrant(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, "grant:"+id)
	for u, gs := range f.grants {
		f.grants[u] = without(gs, id)
	}
	return nil
}

func (f *fakeRevoker) did() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func without(in []string, drop string) []string {
	var out []string
	for _, v := range in {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}
